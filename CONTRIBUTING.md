# Contributing to Slack Security Audit Tool

We welcome contributions to the Slack Security Audit Tool! This document provides guidelines for contributing to the project.

## How to Contribute

### Reporting Issues

1. Check if the issue already exists in the [Issues](https://github.com/ethanolivertroy/slack-audit/issues) section
2. If not, create a new issue with:
   - Clear description of the problem
   - Steps to reproduce
   - Expected behavior
   - Actual behavior
   - Environment details (OS, Python version, etc.)

### Submitting Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests if applicable
5. Ensure all tests pass
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to your branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

### Development Setup

```bash
# Clone your fork
git clone https://github.com/ethanolivertroy/slack-audit.git
cd slack-audit

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install development dependencies
pip install pytest pytest-asyncio black flake8 mypy
```

### Code Style

- Follow PEP 8
- Use type hints where appropriate
- Add docstrings to all functions and classes
- Keep line length under 100 characters
- Run `black` for formatting: `black .`
- Run `flake8` for linting: `flake8 .`

### Testing

- Add unit tests for new functionality
- Ensure all tests pass before submitting PR
- Run tests with: `pytest tests/`
- Test coverage should not decrease

### Adding New Features

#### New Compliance Framework

1. Create new file in `slack_security_audit/frameworks/`
2. Extend `ComplianceFramework` base class
3. Implement required methods
4. Add to framework registry in `core.py`
5. Add documentation

#### New Control

1. Add control definition to framework's `_load_controls()`
2. Implement assessment method `_assess_<control_id>()`
3. Map CIA impacts appropriately
4. Add tests

#### New Data Collector

1. Create new file in `slack_security_audit/collectors/`
2. Extend `DataCollector` base class
3. Implement `collect()` method
4. Add to collector list in `core.py`
5. Handle errors gracefully

### Commit Messages

- Use clear, descriptive commit messages
- Start with a verb (Add, Fix, Update, etc.)
- Keep first line under 50 characters
- Add detailed description if needed

Example:
```
Add support for HIPAA compliance framework

- Implement HIPAA control mappings
- Add healthcare-specific checks
- Update documentation
```

### Documentation

- Update README.md for significant changes
- Add docstrings to new code
- Update DEVELOPMENT.md if architecture changes
- Include examples where helpful

## Code of Conduct

### Our Standards

- Be respectful and inclusive
- Welcome newcomers and help them get started
- Accept constructive criticism
- Focus on what's best for the community

### Unacceptable Behavior

- Harassment or discrimination
- Trolling or insulting comments
- Public or private harassment
- Publishing private information

## Questions?

Feel free to open an issue for any questions about contributing.