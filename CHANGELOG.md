# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] - 2026-10-24

### Added
- **Core Architecture:** Stateful multi-agent Red Teaming Directed Acyclic Graph (DAG) built on LangGraph and Pydantic v2.
- **Specialized Agents:**
  - `OrchestratorAgent`: Automated threat modeling and dynamic test matrix planning.
  - `PromptInjectionSpecialistAgent`: Delimiter attacks, instruction override, and goal hijacking simulation (OWASP LLM01).
  - `ToolAbuseAgent`: Function calling authorization boundaries, parameter tampering, and privilege escalation testing (OWASP LLM07/LLM08).
  - `DataExfiltrationAgent`: System prompt disclosure, canary extraction, and RAG metadata enumeration (OWASP LLM06).
  - `EvaluatorAgent`: Semantic analysis of target responses, risk scoring (0-10), and actionable remediation roadmap generation.
- **Dynamic Test Iteration Engine:** Adaptive multi-turn mutation with backtracking exploration tree ensuring agents never surrender on initial refusal.
- **Target Connectors:**
  - `BaseTargetConnector`: Standardized asynchronous adapter interface.
  - `RestTargetConnector`: Live HTTP/JSON agent endpoint communication.
  - `MockTargetConnector`: Sandboxed enterprise banking assistant with layered guardrail simulation.
- **Vector Knowledge Store:** Persistent ChromaDB integration with automatic in-memory fallback for indexing OWASP benchmark vectors.
- **Command Line Interface (CLI):** `redagent` CLI supporting `scan`, `demo`, and `version` subcommands with mandatory authorization verification flags (`--authorized`).
- **Developer Experience (DX):** Full Python SDK support for direct programmatic invocation in CI/CD pipelines.
- **Test Suite:** Comprehensive unit and integration test coverage across all components with 100% pass rate.
