use clap::{App, Arg};
use std::error::Error;
mod error;
mod helpers;
mod types;
mod constants;
mod jwt_exploiter;
use jwt_exploiter::JWTExploiter;
mod jwt_core;
use jwt_core::jwt_analyzer::JWTAnalyzer;
use types::output::Output;
use helpers::print_output::print_output;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let matches = App::new("Rusty Token - JWT Vulnerability Analyzer")
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
        Ok(Some(secret)) => {
            print_output(format, Output {
                status: "found".to_string(),
                secret: Some(secret.clone()),
                detail: "A matching secret was found for the given JWT signature.".to_string(),
                usage: Some(format!("This secret can be used to verify the JWT signature, ensuring that the token is valid and has not been tampered with.")),
            });
        }
        Ok(None) => {
            print_output(format, Output {
                status: "not_found".to_string(),
                secret: None,
                detail: "No matching secrets were found using common secrets.".to_string(),
                usage: None,
            });
        }
        Err(e) => {
            print_output(format, Output {
                status: "error".to_string(),
                secret: Some(e.to_string()),
                detail: "An error occurred during the signature cracking process.".to_string(),
                usage: None,
            });
        }
    }
        
    Ok(())
}


