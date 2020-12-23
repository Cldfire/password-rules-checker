use password_rules_parser::parse_password_rules;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
struct Opt {
    /// The path to the password rules JSON file in the apple repo
    file_name: PathBuf,
}

#[derive(Debug, Deserialize)]
struct Quirk {
    #[serde(rename = "password-rules")]
    password_rules: String,
}

fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::from_args();

    let json_string = fs::read_to_string(opt.file_name)?;
    let quirks_parsed = serde_json::from_str::<HashMap<String, Quirk>>(&json_string)?;
    let mut failed_to_parse = 0;

    for (site, quirk) in quirks_parsed {
        match parse_password_rules(&quirk.password_rules, true) {
            Ok(_) => {}
            Err(e) => {
                println!("{}:\n", site);
                println!("{}\n", e.to_string_pretty(&quirk.password_rules)?);
                failed_to_parse += 1;
            }
        }
    }

    if failed_to_parse == 0 {
        println!("All password rules parsed successfully!");
    }

    Ok(())
}
