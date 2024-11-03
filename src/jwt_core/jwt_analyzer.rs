use constants::{COMMON_HEADERS, COMMON_PAYLOADS, JWKS_COMMON, JWT_COMMON};
use crate::{error::JWTAnalyzerError, jwt_exploiter::JWTExploiter, types::{ExploitResult, Vulnerability}};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use rayon::prelude::*;
use serde_json::Value;
use types::{AttackExample, Claims, Severity};
use std::sync::Arc;
use chrono::Utc;
use colored::*;
use serde_json::json;
use std::fmt;

use crate::{constants, types};

// Implement Display for Vulnerability
impl fmt::Display for Vulnerability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let base = format!(
            "[{}] {}\nImpact: {}\nMitigation: {}",
            self.severity, self.description, self.impact, self.mitigation
        );
        
        if let Some(attack) = &self.attack_example {
            write!(
                f,
                "{}\nAttack Example:\n{}\nPayload: {}\nExploitation Steps:\n{}",
                base,
                attack.description,
                attack.payload,
                attack.exploitation_steps.join("\n")
            )
        } else {
            write!(f, "{}", base)
        }
    }
}


// Implement Display for Severity
impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
            // Severity::Info => write!(f, "INFO"),
        }
    }
}

pub struct JWTAnalyzer {
    common_headers: Vec<String>,
    common_payloads: Vec<String>,
    jwks_common: Vec<String>,
    jwt_common: Vec<String>,
}

impl JWTAnalyzer {
    pub fn new() -> Self {
        JWTAnalyzer {
            common_headers: COMMON_HEADERS.lines().map(String::from).collect(),
            common_payloads: COMMON_PAYLOADS.lines().map(String::from).collect(),
            jwks_common: JWKS_COMMON.lines().map(String::from).collect(),
            jwt_common: JWT_COMMON.lines().map(String::from).collect(),
        }
    }

    pub async fn analyze_token(&self, token: &str) -> Result<(Vec<Vulnerability>, Value, Value, Vec<ExploitResult>), JWTAnalyzerError> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(JWTAnalyzerError::InvalidFormat);
        }

        let header = self.decode_header(parts[0])?;
        let payload = self.decode_payload(parts[1])?;
        let mut all_vulnerabilities = Vec::new();

        // Run checks sequentially to avoid potential race conditions
        all_vulnerabilities.extend(self.check_algorithm_vulnerabilities(&header).await?);
        all_vulnerabilities.extend(self.check_expiration_claims(&payload).await?);
        all_vulnerabilities.extend(self.check_key_confusion(&header).await?);
        all_vulnerabilities.extend(self.check_signature_stripping(token).await?);
        all_vulnerabilities.extend(self.check_kid_injection(&header).await?);
        all_vulnerabilities.extend(self.check_jwk_vulnerability(&header).await?);

        let exploiter = Arc::new(JWTExploiter::new(
            token,
            header.clone(),
            payload.clone(),
            all_vulnerabilities.clone()
        ));

        let exploits = exploiter.generate_exploits().await.unwrap_or_default();
        
        Ok((all_vulnerabilities, header, payload, exploits))
    }
    

    fn decode_timestamp(timestamp: usize) -> String {
        let naive = chrono::NaiveDateTime::from_timestamp(timestamp as i64, 0);
        let utc: chrono::DateTime<Utc> = chrono::DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc);
        utc.format("%Y-%m-%d %H:%M:%S (UTC)").to_string()
    }
    

    fn decode_header(&self, header_b64: &str) -> Result<Value, JWTAnalyzerError> {
        let header_bytes = base64::decode_config(header_b64, base64::URL_SAFE_NO_PAD)
            .map_err(|_| JWTAnalyzerError::InvalidFormat)?;
        
        let header_str = String::from_utf8(header_bytes)
            .map_err(|_| JWTAnalyzerError::InvalidFormat)?;
        
        serde_json::from_str(&header_str)
            .map_err(|_| JWTAnalyzerError::InvalidFormat)
    }

    fn decode_payload(&self, payload_b64: &str) -> Result<Value, JWTAnalyzerError> {
        let payload_bytes = base64::decode_config(payload_b64, base64::URL_SAFE_NO_PAD)
            .map_err(|_| JWTAnalyzerError::InvalidFormat)?;
        
        let payload_str = String::from_utf8(payload_bytes)
            .map_err(|_| JWTAnalyzerError::InvalidFormat)?;
        
        serde_json::from_str(&payload_str)
            .map_err(|_| JWTAnalyzerError::InvalidFormat)
    }

    async fn check_algorithm_vulnerabilities(&self, header: &Value) -> Result<Vec<Vulnerability>, JWTAnalyzerError> {
        let mut vulnerabilities = Vec::new();
        
        if let Some(alg) = header.get("alg") {
            match alg.as_str() {
                Some("none") => {
                    vulnerabilities.push(Vulnerability {
                        severity: Severity::Critical,
                        description: "Algorithm 'none' detected".to_string(),
                        impact: "Allows bypass of signature verification".to_string(),
                        mitigation: "Reject tokens with 'none' algorithm and always require valid signatures".to_string(),
                        attack_example: Some(AttackExample {
                            description: "Signature bypass using 'none' algorithm".to_string(),
                            payload: r#"{
    "typ": "JWT",
    "alg": "none"
}
// Payload can be any arbitrary data
{
    "user": "admin",
    "role": "superuser"
}
// No signature required"#.to_string(),
                            exploitation_steps: vec![
                                "1. Take an existing JWT token".to_string(),
                                "2. Decode the payload and modify claims as desired".to_string(),
                                "3. Create new header with 'alg': 'none'".to_string(),
                                "4. Base64url encode header and payload".to_string(),
                                "5. Create token as 'header.payload.' (note the trailing dot)".to_string(),
                                "6. Some implementations may also accept 'header.payload' (no trailing dot)".to_string()
                            ],
                        }),
                    });
                }
                Some(alg @ ("HS256" | "HS384" | "HS512")) => {
                    if self.test_weak_hmac_keys(header).await {
                        vulnerabilities.push(Vulnerability {
                            severity: Severity::High,
                            description: format!("Weak HMAC key detected for {}", alg).to_string(),
                            impact: "Allows brute force attacks on signature".to_string(),
                            mitigation: "Use strong, random keys of appropriate length (at least 256 bits for HS256)".to_string(),
                            attack_example: Some(AttackExample {
                                description: "Brute force attack against weak HMAC key".to_string(),
                                payload: r#"{
    "typ": "JWT",
    "alg": "HS256"
}
// Example of common weak secrets:
// - "secret"
// - "key"
// - "1234567890"
// - "password"
// - Application name or domain"#.to_string(),
                                exploitation_steps: vec![
                                    "1. Collect list of common weak secrets".to_string(),
                                    "2. For each secret:".to_string(),
                                    "   a. Generate HMAC signature using the secret".to_string(),
                                    "   b. Compare with original signature".to_string(),
                                    "3. If match found, secret is discovered".to_string(),
                                    "4. Use secret to forge new tokens".to_string()
                                ],
                            }),
                        });
                    }
                }
                _ => {}
            }
        }
    
        Ok(vulnerabilities)
    }

    async fn test_weak_hmac_keys(&self, _header: &Value) -> bool {
        self.jwt_common.par_iter().any(|key| {
            key.len() < 32 || key.chars().all(|c| c.is_ascii_alphanumeric())
        })
    }

    async fn check_key_confusion(&self, header: &Value) -> Result<Vec<Vulnerability>, JWTAnalyzerError> {
        let mut vulnerabilities = Vec::new();
        
        if let Some(_alg) = header.get("alg") {
            if let Some(_kid) = header.get("kid") {
                vulnerabilities.push(Vulnerability {
                    severity: Severity::High,
                    description: "Potential key confusion vulnerability".to_string(),
                    impact: "Could allow signature verification bypass by switching between RSA and HMAC algorithms".to_string(),
                    mitigation: "Explicitly verify algorithm types and reject algorithm switching. Maintain separate key stores for different algorithms.".to_string(),
                    attack_example: Some(AttackExample {
                        description: "Algorithm confusion attack switching from RS256 to HS256".to_string(),
                        payload: r#"{
    "typ": "JWT",
    "alg": "HS256",    // Changed from RS256
    "kid": "public-key-1"
}"#.to_string(),
                        exploitation_steps: vec![
                            "1. Obtain a JWT signed with RS256 and the corresponding public key".to_string(),
                            "2. Modify the algorithm in the header from 'RS256' to 'HS256'".to_string(),
                            "3. Use the RSA public key as the HMAC secret key".to_string(),
                            "4. If the server doesn't validate algorithm types, it will use the public key as an HMAC secret".to_string(),
                            "5. Sign the token using HMAC-SHA256 with the public key as the secret".to_string(),
                            "6. The server will validate the signature using the same public key as an HMAC secret".to_string()
                        ],
                    }),
                });
            }
        }

        Ok(vulnerabilities)
    }

    async fn check_expiration_claims(&self, payload: &Value) -> Result<Vec<Vulnerability>, JWTAnalyzerError> {
        let mut vulnerabilities = Vec::new();
        
        if !payload.get("exp").is_some() {
            vulnerabilities.push(Vulnerability {
                severity: Severity::Medium,
                description: "Missing expiration claim".to_string(),
                impact: "Token never expires, leading to permanent access".to_string(),
                mitigation: "Add reasonable expiration time using 'exp' claim".to_string(),
                attack_example: Some(AttackExample {
                    description: "Persistent access using non-expiring token".to_string(),
                    payload: r#"{
    "typ": "JWT",
    "alg": "HS256"
}
{
    "sub": "user123",
    "role": "admin"
    // Note: No 'exp' claim
}"#.to_string(),
                    exploitation_steps: vec![
                        "1. Obtain a valid JWT without expiration".to_string(),
                        "2. Token remains valid indefinitely".to_string(),
                        "3. Can be used for access even after user privileges should have been revoked".to_string(),
                        "4. Token must be explicitly blacklisted to prevent access".to_string()
                    ],
                }),
            });
        }

        if let Some(exp) = payload.get("exp") {
            if let Some(exp_time) = exp.as_i64() {
                let current_time = chrono::Utc::now().timestamp();
                if exp_time - current_time > 31536000 { // One year
                    vulnerabilities.push(Vulnerability {
                        severity: Severity::Low,
                        description: "Extended token lifetime".to_string(),
                        impact: "Long-lived tokens increase the window of opportunity for attacks".to_string(),
                        mitigation: "Reduce token lifetime to minimum required time. Consider using refresh tokens.".to_string(),
                        attack_example: Some(AttackExample {
                            description: "Token exposure due to extended lifetime".to_string(),
                            payload: r#"{
    "typ": "JWT",
    "alg": "HS256"
}
{
    "sub": "user123",
    "exp": 1999999999  // Far future timestamp
}"#.to_string(),
                            exploitation_steps: vec![
                                "1. Identify token with extended lifetime".to_string(),
                                "2. Token can be collected through:".to_string(),
                                "   - Man-in-the-middle attacks".to_string(),
                                "   - XSS if stored in JavaScript accessible storage".to_string(),
                                "   - Compromised user device".to_string(),
                                "3. Token remains valid for extended period despite compromise".to_string()
                            ],
                        }),
                    });
                }
            }
        }

        Ok(vulnerabilities)
    }

    async fn check_kid_injection(&self, header: &Value) -> Result<Vec<Vulnerability>, JWTAnalyzerError> {
        let mut vulnerabilities = Vec::new();
        
        if let Some(kid) = header.get("kid") {
            if let Some(kid_str) = kid.as_str() {
                let injection_patterns = [
                    "../../", "../", "....//", "\\", 
                    "'", "\"", ";", "|", "&", "||"
                ];

                if injection_patterns.iter().any(|pattern| kid_str.contains(pattern)) {
                    vulnerabilities.push(Vulnerability {
                        severity: Severity::High,
                        description: "Potential KID injection vulnerability".to_string(),
                        impact: "Could allow key selection manipulation through directory traversal or command injection".to_string(),
                        mitigation: "Implement strict KID validation using a whitelist and avoid file system operations based on KID value".to_string(),
                        attack_example: Some(AttackExample {
                            description: "Directory traversal attack to force the server to use a different key file".to_string(),
                            payload: r#"{
    "typ": "JWT",
    "alg": "HS256",
    "kid": "../../../../../../dev/null"
}"#.to_string(),
                            exploitation_steps: vec![
                                "1. Identify a JWT that uses the 'kid' header parameter".to_string(),
                                "2. Modify the header to include a directory traversal sequence".to_string(),
                                "3. If the server uses the 'kid' parameter to locate key files, it may read from the wrong location".to_string(),
                                "4. This could result in using a predictable or null key for verification".to_string(),
                                "5. Sign the token with the known key to create a valid signature".to_string()
                            ],
                        }),
                    });
                }
            }
        }

        Ok(vulnerabilities)
    }

    async fn check_signature_stripping(&self, token: &str) -> Result<Vec<Vulnerability>, JWTAnalyzerError> {
        let mut vulnerabilities = Vec::new();
        
        let variants = vec![
            format!("{}..", token),
            format!("{}.", token),
            token.replace(token.split('.').last().unwrap_or(""), ""),
        ];

        for variant in variants {
            if self.verify_token_accepted(&variant).await {
                vulnerabilities.push(Vulnerability {
                    severity: Severity::Critical,
                    description: "Signature stripping vulnerability".to_string(),
                    impact: "Allows complete bypass of signature verification".to_string(),
                    mitigation: "Always verify signature presence and validity. Never accept unsigned tokens.".to_string(),
                    attack_example: Some(AttackExample {
                        description: "Signature removal attack".to_string(),
                        payload: r#"// Original token:
header.payload.signature

// Attack variants:
header.payload..
header.payload.
header.payload"#.to_string(),
                        exploitation_steps: vec![
                            "1. Start with a valid JWT token".to_string(),
                            "2. Try multiple signature stripping variants:".to_string(),
                            "   a. Remove signature but keep dots".to_string(),
                            "   b. Remove signature and one dot".to_string(),
                            "   c. Remove signature and both dots".to_string(),
                            "3. Modify payload claims as desired".to_string(),
                            "4. If server accepts any variant, signature verification is bypassed".to_string()
                        ],
                    }),
                });
                break;
            }
        }

        Ok(vulnerabilities)
    }

    async fn check_jwk_vulnerability(&self, header: &Value) -> Result<Vec<Vulnerability>, JWTAnalyzerError> {
        let mut vulnerabilities = Vec::new();
        
        if header.get("jwk").is_some() {
            vulnerabilities.push(Vulnerability {
                severity: Severity::High,
                description: "JWK embedded in header".to_string(),
                impact: "Allows attackers to specify their own verification keys".to_string(),
                mitigation: "Disable JWK header support. Use pre-configured keys or JWKS endpoints.".to_string(),
                attack_example: Some(AttackExample {
                    description: "JWK header injection attack".to_string(),
                    payload: r#"{
    "typ": "JWT",
    "alg": "RS256",
    "jwk": {
        "kty": "RSA",
        "kid": "attacker-key-1",
        "use": "sig",
        "n": "<<attacker's public key modulus>>",
        "e": "AQAB"
    }
}"#.to_string(),
                    exploitation_steps: vec![
                        "1. Generate new RSA key pair".to_string(),
                        "2. Create JWK from public key".to_string(),
                        "3. Insert JWK into token header".to_string(),
                        "4. Sign payload with corresponding private key".to_string(),
                        "5. Server uses embedded JWK for verification".to_string(),
                        "6. Attacker can forge valid signatures using their key pair".to_string()
                    ],
                }),
            });
        }

        Ok(vulnerabilities)
    }

    async fn verify_token_accepted(&self, _token: &str) -> bool {
        false
    }
    

    
    pub async fn crack_signature_parallel(&self, token: &str) -> Result<Option<String>, JWTAnalyzerError> {
        // Split the token to get the header part
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(JWTAnalyzerError::InvalidFormat);
        }
    
        // Decode the header to extract the algorithm
        let header = self.decode_header(parts[0])?;
        let algorithm = match header.get("alg").and_then(Value::as_str) {
            Some(alg) => alg,
            None => return Err(JWTAnalyzerError::InvalidFormat),
        };
    
        let found_secret = self.jwt_common.par_iter().find_map_any(|secret| {
            // Determine the algorithm for validation
            let algorithm_enum = match algorithm {
                "HS256" => Algorithm::HS256,
                "HS384" => Algorithm::HS384,
                "HS512" => Algorithm::HS512,
                "RS256" => Algorithm::RS256,
                "RS384" => Algorithm::RS384,
                "RS512" => Algorithm::RS512,
                
                _ => {
                    eprintln!("{}", format!("Unsupported algorithm: {}", algorithm).red());
                    return None;
                }
            };
    
            // Configure validation
            let mut validation = Validation::new(algorithm_enum);
            validation.validate_exp = false; // Disable expiration validation
            validation.validate_nbf = false; // Disable not before validation
            validation.validate_aud = false; // Disable audience validation
    
            // Try decoding with the current secret
            let decode_result = decode::<Claims>(
                &token,
                &DecodingKey::from_secret(secret.trim().as_bytes()),
                &validation,
            );
    
            match decode_result {
                Ok(token_data) => {
                    println!("{}", format!("[!] Successfully decoded with secret key '{}'.", secret).green());
                    if let Some(exp) = token_data.claims.exp {
                        eprintln!("{}", format!("[+] Note: 'exp' claim is present with value: {}", exp).yellow());
                    } else {
                        eprintln!("{}", "[-] Note: 'exp' claim is missing.".yellow());
                    }
                    Some(secret.to_string())
                }
                Err(_err) => {
                    None
                }
            }
        });
    
        Ok(found_secret)
    }

    fn generate_text_report(&self, vulnerabilities: &[Vulnerability], header: &Value, payload: &Value, exploits: &[ExploitResult]) -> String {
        let mut report = String::new();
        report.push_str(&"JWT Vulnerability Analysis Report\n".green().bold());
        report.push_str("==============================\n\n");

        // Decode and report the header values
        report.push_str(&"Decoded Token Values:\n".cyan().bold());
        report.push_str("=====================\n\n");
        report.push_str(&"Token header values:\n".yellow());

        for header_key in &self.common_headers {
            if let Some(value) = header.get(header_key) {
                report.push_str(&format!("[+] {} = \"{}\"\n", header_key, value.to_string().bright_blue()));
            }
        }

        report.push_str(&"\nToken payload values:\n".yellow());

        // Handle timestamp fields
        for (field, label) in [("iat", "IssuedAt"), ("exp", "Expires"), ("nbf", "NotBefore")] {
            if let Some(value) = payload.get(field) {
                if let Some(timestamp) = value.as_u64() {
                    report.push_str(&format!("[+] {} = {}    ==> TIMESTAMP = {}\n", 
                        field, 
                        timestamp.to_string().bright_blue(), 
                        Self::decode_timestamp(timestamp as usize).bright_blue()));
                }
            }
        }

        for payload_key in &self.common_payloads {
            if let Some(value) = payload.get(payload_key) {
                report.push_str(&format!("[+] {} = \"{}\"\n", payload_key, value.to_string().bright_blue()));
            }
        }

        // Add timestamp legend
        report.push_str("\n----------------------\n");
        report.push_str(&"JWT common timestamps:\n".yellow());
        report.push_str("iat = IssuedAt\n");
        report.push_str("exp = Expires\n");
        report.push_str("nbf = NotBefore\n");
        report.push_str("----------------------\n\n");

        // Add vulnerabilities section
        let mut severity_groups = vec![
            ("Critical", Vec::new()),
            ("High", Vec::new()),
            ("Medium", Vec::new()),
            ("Low", Vec::new()),
        ];

        for vuln in vulnerabilities {
            match vuln.severity {
                Severity::Critical => severity_groups[0].1.push(vuln),
                Severity::High => severity_groups[1].1.push(vuln),
                Severity::Medium => severity_groups[2].1.push(vuln),
                Severity::Low => severity_groups[3].1.push(vuln),
            }
        }

        // Format and add each severity section
        for (severity_name, vulns) in &severity_groups {
            if !vulns.is_empty() {
                report.push_str(&format!("{} Vulnerabilities\n", severity_name).bold());
                report.push_str(&"=".repeat(severity_name.len() + 15));
                report.push_str("\n\n");

                for (i, vuln) in vulns.iter().enumerate() {
                    report.push_str(&format!(
                        "{}. {}\n   Impact: {}\n   Mitigation: {}\n",
                        i + 1,
                        vuln.description.yellow(),
                        vuln.impact.red(),
                        vuln.mitigation.green()
                    ));

                    if let Some(attack) = &vuln.attack_example {
                        report.push_str("\n   Attack Example:\n");
                        report.push_str(&format!("   Description: {}\n", attack.description.blue()));
                        report.push_str(&format!("   Payload:\n{}\n", attack.payload.bright_blue()));
                        report.push_str("   Exploitation Steps:\n");
                        for step in &attack.exploitation_steps {
                            report.push_str(&format!("   - {}\n", step.cyan()));
                        }
                    }
                    report.push_str("\n");
                }
            }
        }

        // Add exploits section
        if !exploits.is_empty() {
            report.push_str("\nGenerated Exploit Tokens\n");
            report.push_str("======================\n\n");
            
            for (i, exploit) in exploits.iter().enumerate() {
                report.push_str(&format!("{}. Technique: {}\n", i + 1, exploit.technique.green()));
                report.push_str(&format!("   Description: {}\n", exploit.description.yellow()));
                report.push_str(&format!("   Forged Token: {}\n\n", exploit.forged_token.bright_blue()));
            }
        }

        // Add summary section
        report.push_str(&"\nSummary\n=======\n".bold());
        for (severity_name, vulns) in severity_groups {
            report.push_str(&format!("{}: {}\n", severity_name, vulns.len()));
        }

        report
    }

    fn generate_json_report(&self, vulnerabilities: &[Vulnerability], header: &Value, payload: &Value, exploits: &[ExploitResult]) -> String {
        json!({
            "header": header,
            "payload": payload,
            "vulnerabilities": vulnerabilities.iter().map(|v| json!({
                "description": v.description,
                "impact": v.impact,
                "mitigation": v.mitigation,
                "attack_example": v.attack_example.as_ref().map(|attack| json!({
                    "description": attack.description,
                    "payload": attack.payload,
                    "exploitation_steps": attack.exploitation_steps,
                })),
            })).collect::<Vec<_>>(),
            "exploits": exploits.iter().map(|e| json!({
                "technique": e.technique,
                "description": e.description,
                "forged_token": e.forged_token,
            })).collect::<Vec<_>>(),
        }).to_string()
    }

    fn generate_html_report(&self, vulnerabilities: &[Vulnerability], header: &Value, payload: &Value, exploits: &[ExploitResult]) -> String {
        let mut report = String::from("<html><body><h1>JWT Vulnerability Analysis Report</h1><hr>");
        
        // Header and payload section
        report.push_str("<h2>Decoded Token Values</h2>");
        report.push_str("<h3>Token Header Values</h3><ul>");
        for header_key in &self.common_headers {
            if let Some(value) = header.get(header_key) {
                report.push_str(&format!("<li><strong>{}</strong>: {}</li>", header_key, value));
            }
        }
        
        report.push_str("</ul><h3>Token Payload Values</h3><ul>");
        for payload_key in &self.common_payloads {
            if let Some(value) = payload.get(payload_key) {
                report.push_str(&format!("<li><strong>{}</strong>: {}</li>", payload_key, value));
            }
        }
        
        // Vulnerabilities section
        report.push_str("</ul><hr><h2>Vulnerabilities</h2>");
        for vuln in vulnerabilities {
            report.push_str("<div class='vulnerability'>");
            report.push_str(&format!("<h3>Description: {}</h3>", vuln.description));
            report.push_str(&format!("<p><strong>Impact:</strong> {}</p>", vuln.impact));
            report.push_str(&format!("<p><strong>Mitigation:</strong> {}</p>", vuln.mitigation));
            report.push_str("</div>");
        }
        
        // Exploits section
        if !exploits.is_empty() {
            report.push_str("<hr><h2>Generated Exploit Tokens</h2>");
            for exploit in exploits {
                report.push_str("<div class='exploit'>");
                report.push_str(&format!("<h3>Technique: {}</h3>", exploit.technique));
                report.push_str(&format!("<p><strong>Description:</strong> {}</p>", exploit.description));
                report.push_str(&format!("<p><strong>Forged Token:</strong> {}</p>", exploit.forged_token));
                report.push_str("</div>");
            }
        }
        
        report.push_str("</body></html>");
        report
    }

    pub fn generate_report(&self, vulnerabilities: &[Vulnerability], header: &Value, payload: &Value, exploits: &[ExploitResult], format: &str) -> String {
        match format {
            "json" => self.generate_json_report(vulnerabilities, header, payload, exploits),
            "html" => self.generate_html_report(vulnerabilities, header, payload, exploits),
            _ => self.generate_text_report(vulnerabilities, header, payload, exploits),
        }
    }
    
}