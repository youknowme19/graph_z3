# Contributing to NeuroZ3

Thank you for your interest in contributing to NeuroZ3. We welcome contributions from security researchers, formal methods specialists, and machine learning engineers.

---

## 1. Code of Conduct and Standards

Contributors are expected to adhere to professional communication standards. All contributions must uphold rigorous engineering quality, comprehensive test coverage, and documentation integrity.

---

## 2. Development Setup

### 2.1 Prerequisites
- Python 3.10+
- C/C++ compiler toolchain (`clang` or `gcc`)
- Node.js 18+ (for frontend contributions)

### 2.2 Local Environment Setup
```bash
# Clone the repository
git clone https://github.com/sandy191020/graph_z3.git
cd graph_z3

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install development dependencies
pip install -r requirements.txt
pip install pytest flake8 black
```

---

## 3. Pull Request Workflow

1. **Fork the Repository**: Create your branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```
2. **Implement Changes**: Maintain modular separation between:
   - `src/core/`: Binary loading, IR lifting, and SARIF export.
   - `src/symbolic/`: Symbolic execution hooks and Z3 constraint solving.
   - `src/ml/`: GNN architectures, feature extractors, and dataset loaders.
   - `src/ml/federated/`: Flower federated learning clients, servers, and strategies.
3. **Write Unit Tests**: Add test cases under `tests/` covering new logic.
4. **Run Verification Suites**:
   ```bash
   pytest tests/
   python -m unittest discover tests/
   ```
5. **Submit Pull Request**: Provide a detailed description including rationale, benchmark verification, and test outputs.

---

## 4. Coding Conventions

- **Python Style**: Adhere to PEP 8. Format code using `black`.
- **Type Annotations**: Use Python typing annotations (`typing.Dict`, `typing.List`, `typing.Optional`, `typing.Tuple`) across public interfaces.
- **Tone & Style**: Do not use emojis in commit messages, documentation, or code comments. Maintain concise, enterprise-grade technical phrasing.
- **Commit Messages**: Follow Conventional Commits format:
  - `feat(...)`: New feature implementation
  - `fix(...)`: Bug fix or patch
  - `docs(...)`: Documentation updates
  - `test(...)`: Unit test additions
  - `refactor(...)`: Code refactoring without behavior modification

---

## 5. Reporting Issues

When filing issues, provide:
- Operating system and architecture (e.g., Ubuntu 22.04 x86-64, macOS ARM64).
- Target binary architecture and file format.
- Exact command line invocation and stack trace output.
