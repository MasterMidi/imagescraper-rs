use inquire::{
    formatter::MultiOptionFormatter, list_option::ListOption, validator::Validation, MultiSelect,
};
use log::{error, info, trace};
use reqwest::Url;
use std::{collections::HashMap, fmt::Display};

use error_chain::error_chain;
use imagescraper::{load_config, query, Website};

error_chain! {
    foreign_links {
        Io(std::io::Error);
        Reqwest(reqwest::Error);
        Inquire(inquire::InquireError);
    }
}

fn main() {
    env_logger::init(); // Initialize logger

    loop {
        // Wait for user input
        println!("Enter a URL: ");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        trace!("Input: {input}");

        // Parse input as URL
        let url = match Url::parse(&input) {
            Ok(x) => x,
            Err(e) => {
                error!("Invalid URL: {e}");
                continue;
            }
        };

        // Load configuration for website
        let cfg = match load_config(&url, "./config.toml") {
            Ok(x) => x,
            Err(ref e) => {
                e.iter()
                    .enumerate()
                    .for_each(|(index, error)| eprintln!("└> {index} - {error}"));
                error!("Failed to load configuration: {e}");
                continue;
            }
        };

        let output = query(&url).unwrap();

        // Generate imageinfo from HTML-document
        let img = match Website::from(output, cfg.clone()) {
            Ok(x) => x,
            Err(ref e) => {
                e.iter()
                    .enumerate()
                    .for_each(|(index, error)| eprintln!("└> {index} - {error}"));
                continue;
            }
        };

        // Prompt user to select tags
        let tags = img
            .tags
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    if v.len() <= cfg.tags[k].minimum.unwrap_or(1) {
                        v.clone()
                    } else {
                        match prompt_list(v.clone(), k, cfg.tags[k].minimum, true) {
                            Ok(x) => x,
                            Err(ref e) => {
                                e.iter()
                                    .enumerate()
                                    .for_each(|(index, error)| eprintln!("└> {index} - {error}"));
                                Vec::new()
                            }
                        }
                    },
                )
            })
            .collect::<HashMap<_, _>>();

        let w = Website::new(img.cfg, img.url, tags);

        // Download image
        match w.download() {
            Ok(_) => info!("Image downloaded successfully!"),
            Err(ref e) => {
                e.iter()
                    .enumerate()
                    .for_each(|(index, error)| eprintln!("└> {index} - {error}"));
            }
        };
    }
}

fn prompt_list<T>(
    mut options: Vec<T>,
    input_kind: &str,
    min: Option<usize>,
    select_all: bool,
) -> Result<Vec<T>>
where
    T: Display + Ord,
{
    options.sort();

    let validator = move |a: &[ListOption<&T>]| {
        if a.len() < min.unwrap_or(0) {
            return Ok(Validation::Invalid("No options selected".into()));
        }

        Ok(Validation::Valid)
    };

    let formatter: MultiOptionFormatter<'_, T> = &|a| format!("{} {input_kind}", a.len());

    let default: Vec<usize> = if select_all {
        (0..options.len()).collect()
    } else {
        Vec::new()
    };

    MultiSelect::new(format!("Select {input_kind} to include:").as_str(), options)
        .with_validator(validator)
        .with_formatter(formatter)
        .with_default(&default)
        .prompt()
        .chain_err(|| "Failed to prompt user")
}
