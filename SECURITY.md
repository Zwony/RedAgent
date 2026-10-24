# Security Policy

## Supported Versions

We take the security of RedAgent and its ecosystem seriously. The following table indicates which versions currently receive security updates and patches:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1.0 | :x:                |

---

## Reporting a Vulnerability

If you discover a potential security vulnerability within RedAgent (such as an unhandled deserialization flaw, sensitive credential exposure, or logic bypass in authorization checks), please report it responsibly following our coordinated disclosure policy.

### How to Report

**Please do NOT report security vulnerabilities through public GitHub issues or discussions.**

Instead, please report security issues through one of the following private channels:

1. **GitHub Private Vulnerability Reporting:**  
   Navigate to the repository's **Security** tab, click on **Advisories**, and select **Report a vulnerability**. This allows secure, private collaboration with the maintainers.
2. **Security Team Contact:**  
   Send an encrypted email to `security@redagent-project.org` with the subject line `[SECURITY] Potential Vulnerability in RedAgent`.

### What to Include in Your Report

To help us investigate and triage the issue quickly, please include:
- A clear description of the vulnerability and its potential security impact.
- Step-by-step reproduction instructions or a minimal Proof of Concept (PoC).
- Affected version(s) and environment details (OS, Python version, dependencies).
- Any proposed remediation or mitigation steps if available.

---

## Response and Disclosure Timelines

- **Initial Acknowledgment:** Within 48 hours of report submission.
- **Triage and Assessment:** Within 5 business days, confirming vulnerability scope and severity.
- **Fix and Release:** We aim to release a patch within 30 days of confirmed triage, coordinated with the reporter.
- **Public Disclosure:** Public release notes and security advisories (CVE) will be published simultaneously with the patch.

---

## Responsible Red Teaming & Bug Bounty Notice

RedAgent is an adversarial testing tool designed to identify vulnerabilities in third-party LLM systems. When conducting research or testing using RedAgent:
- Always obtain written authorization before testing any target system you do not own.
- Adhere strictly to the target organization's Vulnerability Disclosure Policy (VDP) or Bug Bounty guidelines.
- Never exfiltrate real customer data or cause system denial of service.
