# Contributing to RedAgent

Thank you for your interest in contributing to RedAgent. As an open-source cybersecurity project, we welcome contributions from security researchers, AI engineers, and software developers.

Please review this document before submitting issues or pull requests.

---

## Code of Conduct

All contributors and maintainers are expected to adhere to our [Code of Conduct](CODE_OF_CONDUCT.md). We maintain a professional, collaborative, and inclusive environment.

---

## Development Setup

### Prerequisites
- Python 3.11 or higher
- Git

### Initializing Environment
1. Fork the repository on GitHub and clone your fork locally:
   ```bash
   git clone https://github.com/your-username/RedAgent.git
   cd RedAgent
   ```

2. Create and activate a dedicated virtual environment:
   ```bash
   python -m venv venv
   # On Windows:
   .\venv\Scripts\activate
   # On Linux/macOS:
   source venv/bin/activate
   ```

3. Install the project in editable mode with development dependencies:
   ```bash
   pip install -e ".[dev]"
   ```

---

## How to Contribute

### 1. Adding a New Red Team Specialist Agent
RedAgent is designed to be fully modular. To introduce a new adversarial agent:

1. Create a new module under `redagent/agents/<agent_name>.py`.
2. Inherit from `BaseAgent`:
   ```python
   from typing import Any, Dict
   from redagent.agents.base import BaseAgent
   from redagent.schemas.state import RedTeamGraphState

   class CustomSpecialistAgent(BaseAgent):
       def __init__(self, model_name: str = "gpt-4o"):
           super().__init__(
               agent_id="agent_custom_specialist",
               name="CustomSpecialistAgent",
               role="Custom Domain Red Teaming",
               system_prompt="...",
               model_name=model_name,
           )

       async def run(self, state: RedTeamGraphState) -> Dict[str, Any]:
           # Execute tests and return state updates
           return {}
   ```
3. Register your agent in `redagent/agents/__init__.py`.
4. Add the corresponding node and edges in `redagent/core/graph.py`.
5. Add unit tests in `tests/test_redagent.py`.

### 2. Adding Benchmark Vector Seeds
To expand our vector knowledge base with new OWASP test cases:
1. Open `redagent/knowledge/seed_data.py`.
2. Append your structured seed dictionary to `DEFAULT_SEEDS`:
   ```python
   {
       "id": "seed_category_XX",
       "category": OWASPCategory.LLMXX_...,
       "technique": AttackTechnique....,
       "content": "...",
       "metadata": {"framing": "...", "complexity": 2},
   }
   ```

---

## Coding Standards

To maintain an enterprise-grade codebase:
- **Type Annotations:** All function signatures and data schemas must be fully typed using Python type hints (`typing` / `pydantic`).
- **Code Style:** Strictly follow PEP 8. Format code using `black` and `isort`.
- **Documentation:** Use clear, technical docstrings. Do NOT use emojis in code, logs, or documentation.
- **Testing:** Every new feature, connector, or agent must include corresponding unit tests under `tests/`.

---

## Running Quality Checks

Before opening a pull request, run all verification checks locally:

```bash
# Run unit and integration tests
pytest -v tests/

# Type checking
mypy redagent/

# Code formatting checks
black --check redagent/ tests/
isort --check-only redagent/ tests/
```

---

## Submitting Pull Requests

1. Create a feature branch:
   ```bash
   git checkout -b feat/your-feature-name
   ```
2. Commit your changes with clear, semantic commit messages (e.g., `feat: add indirect prompt injection mutation strategy`).
3. Push to your fork:
   ```bash
   git push origin feat/your-feature-name
   ```
4. Open a Pull Request against the `main` branch of `RedAgent`. Complete the PR template with a clear explanation of changes and test evidence.
