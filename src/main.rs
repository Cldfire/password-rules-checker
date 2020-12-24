use anyhow::{anyhow, Context};
use password_rules_parser::error::PasswordRulesError;
use password_rules_parser::{parse_password_rules, CharacterClass, PasswordRules};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
struct Opt {
    /// The path to the password rules JSON file in the apple repo
    file_name: PathBuf,
    /// Path to password rules JSON file to diff against
    #[structopt(long)]
    diff_against: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
struct Quirk {
    #[serde(rename = "password-rules")]
    password_rules: String,
}

fn load_rules_map(p: impl AsRef<Path>) -> Result<HashMap<String, Quirk>, anyhow::Error> {
    let path = p.as_ref();
    let json_string = fs::read_to_string(path)
        .with_context(|| format!("Failed to read file at {}", path.to_string_lossy()))?;

    Ok(serde_json::from_str(&json_string).with_context(|| {
        format!(
            "Failed to parse JSON loaded from {}",
            path.to_string_lossy()
        )
    })?)
}

fn print_password_rules_error(site: &str, parsed_from: &str, e: PasswordRulesError) {
    println!("{}:\n", site);
    println!("{}\n", e.to_string_pretty(parsed_from).unwrap());
}

fn remove_unecessary_allows(rules: &PasswordRules) -> Vec<CharacterClass> {
    rules
        .allowed
        .iter()
        .filter(|allowed_class| {
            // Keep only rules that aren't present in the required classes
            !rules
                .required
                .iter()
                .flatten()
                .any(|required_class| *allowed_class == required_class)
        })
        .cloned()
        .collect()
}

fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::from_args();

    let quirks_parsed = load_rules_map(opt.file_name)?;
    let quirks_to_diff_parsed = if let Some(p) = opt.diff_against.as_ref() {
        Some(load_rules_map(p)?)
    } else {
        None
    };

    let mut failed_to_parse = 0;
    for (site, quirk) in quirks_parsed.iter() {
        match parse_password_rules(&quirk.password_rules, true) {
            Ok(quirk_parsed) => {
                let possibly_shortened_allows = remove_unecessary_allows(&quirk_parsed);

                if quirk_parsed.allowed != possibly_shortened_allows {
                    // TODO: pretty print the suggestion
                    println!(
                        "{}: the `allowed` property for this rule can be shortened to: {:?}",
                        site, possibly_shortened_allows
                    );
                }
            }
            Err(e) => {
                print_password_rules_error(site, &quirk.password_rules, e);
                failed_to_parse += 1;
            }
        }
    }

    if failed_to_parse == 0 {
        println!("All password rules parsed successfully!");
    } else {
        return Ok(());
    }

    if let Some(quirks_to_diff_parsed) = quirks_to_diff_parsed {
        println!(
            "Diffing against the rules loaded from {}",
            opt.diff_against.unwrap().to_string_lossy()
        );

        if quirks_to_diff_parsed.len() != quirks_parsed.len() {
            return Err(anyhow!(
                "The number of quirks is different between the two files being compared; \
                they must have the same number of rules"
            ));
        }

        for (site, quirk) in quirks_parsed.iter() {
            let other_quirk = quirks_to_diff_parsed.get(site).ok_or_else(|| {
                anyhow!(
                    "The quirks being diffed against didn't contain an entry for {}",
                    site
                )
            })?;

            // We already verified that all of these rules parse correctly above
            let mut quirk_parsed = parse_password_rules(&quirk.password_rules, true).unwrap();
            let mut other_quirk_parsed = match parse_password_rules(
                &other_quirk.password_rules,
                true,
            ) {
                Ok(parsed) => parsed,
                Err(e) => {
                    print_password_rules_error(site, &other_quirk.password_rules, e);
                    return Err(anyhow!("One of the password rules in the quirks being diffed against failed to parse"));
                }
            };

            quirk_parsed.allowed = remove_unecessary_allows(&quirk_parsed);
            other_quirk_parsed.allowed = remove_unecessary_allows(&other_quirk_parsed);

            println!("Checking {}", site);

            assert_eq!(quirk_parsed.min_length, other_quirk_parsed.min_length);
            assert_eq!(quirk_parsed.max_length, other_quirk_parsed.max_length);
            assert_eq!(
                quirk_parsed.max_consecutive,
                other_quirk_parsed.max_consecutive
            );
            assert_eq!(quirk_parsed.allowed, other_quirk_parsed.allowed);

            for required_class in quirk_parsed.required.iter() {
                assert!(other_quirk_parsed.required.contains(required_class));
            }

            for required_class in other_quirk_parsed.required.iter() {
                assert!(quirk_parsed.required.contains(required_class));
            }
        }

        println!("All rules were semantically equivalent!");
    }

    Ok(())
}
