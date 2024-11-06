use crate::types::output::Output;
use colored::*;

pub fn print_output(format: &str, output: Output) {
    match format {
        "json" => {
            let json_output = serde_json::to_string(&output).unwrap();
            println!("{}", json_output);
        }
        _ => {
            match output.status.as_str() {
                "found" => {
                    if let Some(secret) = output.secret {
                        println!("\n{} Found matching secret: {}", "[!]".green(), secret.green());
                        if let Some(usage) = output.usage {
                            println!("Usage: {}", usage);
                        }
                    }
                }
                "not_found" => {
                    println!("\n{} Could not crack signature with common secrets", "[-]".yellow());
                }
                "error" => {
                    if let Some(message) = output.secret {
                        println!("\n{} Error during signature cracking: {}", "[!]".red(), message.red());
                    }
                }
                _ => {}
            }
        }
    }
}