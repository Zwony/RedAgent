# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.2.0] - 2026-10-31

### Added
- **Interactive Web UI Dashboard (`redagent ui`):** Full-featured Streamlit visual command center providing live target profiling, real-time multi-agent activity streams, metric summary cards, and one-click report downloads.
- **In-Memory Callable Connector (`CallableTargetConnector`):** Direct test adapter for evaluating local Python functions, coroutines, and LangChain Runnable chains with zero server setup.
- **Standalone Executive HTML Reports (`--format html`):** Air-gapped, single-file HTML security audit reports featuring responsive dark cybersecurity styling, vulnerability cards, and remediation roadmaps.
- **Automatic Release Updater (`redagent update`):** PyPI and GitHub release discovery with 24-hour TTL caching, non-blocking CI/CD checks, and an interactive upgrade confirmation prompt in terminal sessions.
- **Optional Dependencies in Packaging:** Added `redagent[ui]` optional dependencies group in `pyproject.toml` for lightweight core installation.

### Changed
- **Performance & Cold-Start Optimization:** Implemented lazy LiteLLM loading and cached vector store seed checks, eliminating startup delays and network timeouts in offline environments.
- **Documentation Standards:** Refactored docstrings across all modules to strictly comply with the Google Python Style Guide.

### Fixed
- Resolved IDE missing-module warnings for optional dependencies using dynamic specification lookups.

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
- **Vector Knowledge Store:** Persistent ChromaDB integration with automatic in-memory fallback, seeded with expanded benchmark vectors (SSRF redirection, SQL parameter injection, obfuscated base64 extraction, and goal hijacking).
- **Command Line Interface (CLI):** `redagent` CLI with retro ASCII art banner supporting `init` (profile scaffolding), `scan` (with `--output report.md` or `report.json`), `demo`, and `version` subcommands.
- **Executive Reporting:** Dual-format audit report generation supporting structured JSON and CISO-ready Markdown format with CVSS metrics and remediation tables.
- **Developer Experience (DX):** Full Python SDK support for direct programmatic invocation in CI/CD pipelines.
- **Test Suite:** Comprehensive unit and integration test coverage across all components with 100% pass rate.
