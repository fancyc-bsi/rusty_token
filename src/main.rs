use clap::{App, Arg};
use std::error::Error;
use colored::*;

mod error;
mod types;
mod constants;
mod jwt_exploiter;
use jwt_exploiter::JWTExploiter;
mod jwt_core;
use jwt_core::jwt_analyzer::JWTAnalyzer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let matches = App::new("JWT Vulnerability Analyzer")
        .version("1.0")
        .author("Connor Fancy")
        .about("Analyzes JWT tokens for common vulnerabilities")
        .arg(
            Arg::with_name("token")
                .help("The JWT token to analyze")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::with_name("format")
                .help("The output format of the report (text, json, html)")
                .short("f")
                .long("format")
                .takes_value(true)
                .default_value("text"),
        )
        .get_matches();

    let token = matches.value_of("token").unwrap();
    let format = matches.value_of("format").unwrap();
    let analyzer = JWTAnalyzer::new();

    println!("Analyzing JWT token...\n");

    match analyzer.analyze_token(token).await {
        Ok((vulnerabilities, header, payload, exploits)) => {
            if vulnerabilities.is_empty() {
                println!("No common vulnerabilities found.");
            } else {
                println!("{}", analyzer.generate_report(&vulnerabilities, &header, &payload, &exploits, format));
            }
        }
        Err(e) => println!("Error analyzing token: {}", e),
    }

    // Attempt to crack signature using common dictionary
    match analyzer.crack_signature_parallel(token).await {
        Ok(Some(secret)) => println!("\n{} Found matching secret: {}", "[!]".green(), secret.green()),
        Ok(None) => println!("\n{} Could not crack signature with common secrets", "[-]".yellow()),
        Err(e) => println!("\n{} Error during signature cracking: {}", "[!]".red(), e.to_string().red()),
    }

    Ok(())
}


