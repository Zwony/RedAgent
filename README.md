<div align="center">

<img src="assets/redagent_banner.jpg" alt="RedAgent Banner" width="100%" />

# RedAgent
### Autonomous AI Agent Red Teaming & Security Auditing Platform
**Stateful Multi-Agent Vulnerability Assessment Engine for Enterprise LLM Systems**

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python: 3.11+](https://img.shields.io/badge/Python-3.11%2B-3776AB.svg?logo=python&logoColor=white)](pyproject.toml)
[![Framework: LangGraph](https://img.shields.io/badge/Orchestration-LangGraph-FF4B4B.svg)](https://github.com/langchain-ai/langgraph)
[![Tests: Passing](https://img.shields.io/badge/Tests-6%2F6%20Passed-brightgreen.svg)](tests/)
[![Security: OWASP LLM Top 10](https://img.shields.io/badge/Standard-OWASP_LLM_Top_10-red.svg)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)

[Features](#key-features) • [Architecture](#system-architecture) • [Quickstart](#quickstart--installation) • [CLI Usage](#cli-usage) • [SDK Usage](#python-sdk--cicd-integration) • [Legal Notice](#legal-disclaimer--authorized-use-policy)

</div>

---

> [!WARNING]
> ### LEGAL DISCLAIMER & AUTHORIZED USE POLICY
> **RedAgent is strictly designed for authorized security auditing, internal red teaming, academic research, and defensive hardening.**
> 
> Testing AI agents, API endpoints, or systems without prior **explicit, written authorization** from the system owner is illegal and violates computer crime laws (e.g., Computer Fraud and Abuse Act - CFAA, EU NIS2, UK Computer Misuse Act). The authors and contributors of RedAgent assume **no liability** and are not responsible for any misuse, damage, or legal consequences resulting from this tool. By using RedAgent, you agree to comply with all applicable local and international cybersecurity laws.

---

## Why RedAgent?

Traditional Dynamic Application Security Testing (DAST) and API scanners are fundamentally incapable of discovering non-deterministic LLM vulnerabilities:
- They do not understand conversational state, prompt boundaries, or instruction delimiters.
- They conclude execution after a single HTTP 200 or standard polite refusal ("I am sorry, but...").
- They cannot evaluate autonomous function calling (`Excessive Agency`) or vector memory leakage (`RAG Data Exfiltration`).

**RedAgent solves this by deploying a team of adversarial AI agents.** Powered by a **Dynamic Test Iteration Engine with Backtracking**, our specialist agents analyze target refusals, systematically mutate boundary conditions (delimiters, role claims, parameter tampering), and continue exploring alternative attack vectors until every path on the exploration tree is exhausted.

---

## Key Features

- **OWASP LLM Top 10 Coverage:** Automated test generation mapped to Prompt Injection (LLM01), Sensitive Information Disclosure (LLM06), and Excessive Agency / Insecure Tool Abuse (LLM07/LLM08).
- **Persistent Refinement with Backtracking:** Agents do not surrender on a single defense. When a prompt is blocked by a guardrail, the engine backtracks and mutates formatting, delimiters, and semantic framing.
- **ChromaDB Vector Knowledge Store:** Persistently indexes adversarial seeds, boundary test templates, and OWASP evaluation rubrics (with zero-dependency in-memory fallback).
- **Pluggable Target Connectors:** Test local mock agents, staging bots, or live enterprise agents over REST API endpoints (`RestTargetConnector`).
- **Actionable Remediation Roadmap:** Automatically generates concrete developer fixes, including regex guardrail patterns, system prompt hardening snippets, and RBAC constraints.
- **Dual Mode (CLI + SDK):** Run as a standalone terminal security scanner or embed into Python CI/CD pipelines.

---

## System Architecture

RedAgent operates as a stateful Directed Acyclic Graph (DAG) built on **LangGraph**, **Pydantic v2**, and **LiteLLM**:

```mermaid
graph TD
    A[Target AI Agent Profile] --> B[Orchestrator Agent]
    B --> C{Adversarial Specialists}
    C -->|OWASP LLM01| D[Prompt Injection Specialist]
    C -->|OWASP LLM07/LLM08| E[Tool Abuse & Authorization Agent]
    C -->|OWASP LLM06| F[Data Exfiltration Agent]
    
    subgraph Persistent Refinement Loop
        D <-->|Multi-turn Mutation & Backtracking| IE[Dynamic Test Iteration Engine]
        E <-->|Adaptive Strategy Shift| IE
        F <-->|Vector Seed Retrieval| IE
        IE <--> VS[(Security Vector Store: ChromaDB)]
        IE <--> TC[Target Connectors: Mock / REST]
    end

    D --> G[Evaluator & Reporting Agent]
    E --> G
    F --> G
    G --> H[Final Audit Report & Remediation Roadmap]
```

### Specialized Multi-Agent Roles

| Agent Role | Domain Specialty | OWASP Focus | Core Objective |
| :--- | :--- | :--- | :--- |
| **Orchestrator Agent** | Threat Modeler & Planner | System-wide | Profiles target tools, RAG connections, and generates structured test matrices. |
| **Prompt Injection Specialist** | Boundary & Delimiter Attacks | LLM01 | Tests instruction delimiters, goal hijacking, and system override resistance. |
| **Tool Abuse Agent** | RBAC & Excessive Agency | LLM07, LLM08 | Tests unconstrained function calling, parameter tampering, and privilege escalation. |
| **Data Exfiltration Agent** | Confidentiality & Memory | LLM06 | Evaluates system prompt leaks, canary tokens, and RAG metadata disclosure. |
| **Evaluator & Reporter** | Semantic Analysis & Risk | Comprehensive | Computes risk scores (0-10) and formulates concrete developer remediation rules. |

---

## Quickstart & Installation

### 1. Installation
Clone the repository and install in editable mode:

```bash
git clone https://github.com/Zwony/RedAgent.git
cd RedAgent

# Create and activate virtual environment
python -m venv venv
# Windows:
.\venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# Install dependencies and CLI tool
pip install -e .
```

### 2. Configure Environment (Optional)
To use cloud LLMs (OpenAI, Anthropic, Gemini) for the attack and evaluation agents, copy `.env.example`:

```bash
cp .env.example .env
```
And specify your API keys:
```env
OPENAI_API_KEY=your_key_here
DEFAULT_ATTACKER_MODEL=gpt-4o
```

---

## CLI Usage

### 1. Scaffold a New Target Agent Profile
Generate a starter configuration file with customizable tools and RAG settings:
```bash
redagent init --output target.json --name "CustomerServiceAgent"
```

### 2. Run Security Audit on an AI Agent Profile
Execute the stateful multi-agent DAG against your target and export an executive Markdown report:
```bash
redagent scan --target target.json --output audit_report.md
```
Or export as structured JSON:
```bash
redagent scan --target target.json --output report.json
```

### 3. Run the Interactive Sandbox Demo
Experience the multi-agent refinement loop against a simulated banking assistant:
```bash
redagent demo
```

---

## Sample Audit Output

When an audit finishes, RedAgent renders a comprehensive executive summary and remediation table:

```text
         Security Audit Posture Summary          
+-----------------------------------------------+
| Metric            | Value                     |
|-------------------+---------------------------|
| Target Name       | Acme Customer Service Bot |
| Overall Rating    | CRITICAL_RISK             |
| Max Risk Score    | 9.1 / 10.0                |
| Total Test Cases  | 6                         |
| Findings Detected | 3                         |
+-----------------------------------------------+

                  Vulnerability Findings & Evaluator Analysis                  
+-----------------------------------------------------------------------------+
| Finding ID   | Category       | Severity | Status          | Remediation    |
|--------------+----------------+----------+-----------------+----------------|
| fnd_fa89278c | LLM01: Prompt  | HIGH     | confirmed_vuln  | Sanitize input |
|              | Injection      |          |                 | delimiters     |
| fnd_df05d8d0 | LLM08:         | CRITICAL | confirmed_vuln  | Enforce RBAC   |
|              | Excessive      |          |                 | & schema check |
|              | Agency         |          |                 | on query tool  |
| fnd_e8a2e77f | LLM08:         | CRITICAL | confirmed_vuln  | Require user   |
|              | Excessive      |          |                 | confirmation   |
|              | Agency         |          |                 | for wire trf   |
| fnd_3d6dc2bd | LLM01: Prompt  | INFO     | robust_defense  | Boundary kept  |
| fnd_223a6591 | LLM06: Data    | INFO     | robust_defense  | Prompt kept    |
| fnd_951b5078 | LLM06: Data    | INFO     | robust_defense  | KB protected   |
+-----------------------------------------------------------------------------+

=> Hardening & Guardrail Remediation Roadmap:
  #1 [LLM08: Excessive Agency]: Enforce server-side RBAC and schema constraints on tool 'lookup_customer_order'.
  #2 [LLM08: Excessive Agency]: Require explicit user confirmation token for sensitive function calls ('cancel_and_refund_order').
  #3 [LLM01: Prompt Injection]: Sanitize input delimiters such as triple backticks or custom markup tags.
```

---

## Python SDK & CI/CD Integration

Embed automated AI red teaming directly into test suites or CI/CD pipelines:

```python
import asyncio
from redagent import RedTeamGraphEngine, TargetInfo, TargetToolDefinition

async def test_ai_agent_security():
    # 1. Define Target System
    target = TargetInfo(
        target_id="support_bot_staging",
        name="Customer Service Assistant",
        endpoint_type="rest_api",
        endpoint_url="https://staging.acme.internal/agent",
        accessible_tools=[
            TargetToolDefinition(
                name="query_orders",
                description="Queries customer orders by ID",
                is_sensitive=True,
            )
        ],
        has_rag=True,
        rag_sources=["internal_kb"],
    )

    # 2. Run RedAgent Engine
    engine = RedTeamGraphEngine()
    final_state = await engine.run(target=target)

    # 3. Assert Security Baseline in CI/CD
    report = final_state.audit_report
    assert report.overall_rating.value in ("SECURE", "LOW_RISK"), (
        f"Security audit failed with posture: {report.overall_rating.value} (Risk: {report.overall_risk_score}/10)"
    )

if __name__ == "__main__":
    asyncio.run(test_ai_agent_security())
```

---

## Running Regression Tests

Ensure platform integrity across all modules:
```bash
pytest -v tests/
```

## Community & Contributing

We welcome contributions from security researchers, AI engineers, and open-source developers.

- **Contributing Guide:** Review [CONTRIBUTING.md](CONTRIBUTING.md) for local environment setup, coding standards, and agent creation guides.
- **Security Policy:** To report vulnerabilities in RedAgent itself, consult [SECURITY.md](SECURITY.md).
- **Code of Conduct:** We adhere to the Contributor Covenant. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
- **Release History:** See [CHANGELOG.md](CHANGELOG.md) for version notes and release highlights.

---

## License
This project is licensed under the **Apache License 2.0** - see the [LICENSE](LICENSE) file for details.
