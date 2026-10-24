---
name: New Attack / Benchmark Vector
about: Propose a new adversarial attack vector or OWASP test pattern for the RedAgent knowledge store
title: "[VECTOR] "
labels: ["security", "benchmark-seed"]
assignees: ""
---

### Attack Vector Overview
- **Category:** (e.g., OWASP LLM01 Prompt Injection, LLM06 Sensitive Information Disclosure, LLM08 Excessive Agency)
- **Technique Name:** (e.g., Delimiter Hijacking, Token Smuggling, Multi-turn Role Play)
- **Target Component:** (Prompt Parser / Function Calling Engine / RAG Pipeline)

### Proposed Seed Template
```text
[Provide the probe prompt or template pattern here]
```

### Expected Vulnerable vs. Secure Behavior
- **Vulnerable Behavior:** Target agent complies with instruction, invokes unauthorized tool, or reveals secret data.
- **Secure Behavior:** Target agent enforces boundary filter and declines or sanitizes input.

### Recommended Remediation Guidance
What specific guardrail, regex filter, or system prompt hardening constraint mitigates this issue?

### References & Prior Art
Links to academic papers, CVE advisories, or OWASP LLM Top 10 documentation.
