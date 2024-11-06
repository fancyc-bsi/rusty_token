---
layout: default
title: Home
index: 1
---

# Rusty Token Intro

This application performs comprehensive security analysis on JSON Web Tokens (JWTs) to identify potential vulnerabilities and security risks.

Windows, MacOS and linux are all supported platforms.

## Security Checks

The analyzer performs the following vulnerability checks:

1. **Algorithm Vulnerabilities**
   - Validates the security of the signing algorithm
   - Checks for known vulnerable algorithm types

2. **Expiration and Timing**
   - Validates token expiration claims
   - Checks for expired tokens
   - Ensures proper timestamp handling

3. **Key Management**
   - Detects key confusion vulnerabilities
   - Validates JWK (JSON Web Key) implementations
   - Checks for KID (Key ID) injection vulnerabilities

4. **Signature Security**
   - Tests for signature stripping vulnerabilities
   - Validates signature integrity
   - Checks for blank password vulnerabilities

5. **Payload Analysis**
   - Validates required claims
   - Checks for missing mandatory fields
   - Monitors payload size for potential DOS vectors
   - Validates algorithm case sensitivity

Exploits are then generated for you to use, in an attempt to verify the discovered vulnerabilites. 

## Reporting formats

JSON, HTML and text formats can be used - with json being JQ friendly.

Text is the default format but can be modified with the '--format' flag.