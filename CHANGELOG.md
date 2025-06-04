# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2025-01-06

### Added
- Complete rewrite with modular plugin architecture
- CIA Triad impact analysis for all findings and controls
- Risk-based scoring engine with multiple factors
- Support for multiple compliance frameworks:
  - NIST 800-53 Rev 5 (150+ controls)
  - FedRAMP (Low/Moderate/High baselines)
  - CIS Slack Benchmark
  - ISO 27001 (placeholder)
- Enhanced Slack API client with async support
- Parallel data collection for improved performance
- Multiple report formats (JSON, HTML, Markdown, CSV)
- Configuration file support (YAML/JSON)
- Customizable CIA weights for risk scoring
- Comprehensive evidence collection
- Rate limiting and error handling

### Changed
- Migrated from synchronous to asynchronous architecture
- Improved control coverage from 27 to 150+ controls
- Enhanced risk scoring with CIA impact consideration
- Better error handling and logging

### Removed
- Bash implementation (Python-only now)
- Legacy single-file architecture

## [1.0.0] - 2025-01-05

### Added
- Initial release
- Python and Bash implementations
- 27 NIST 800-53 controls
- Basic compliance checking
- JSON and Markdown reports
- Raw configuration exports