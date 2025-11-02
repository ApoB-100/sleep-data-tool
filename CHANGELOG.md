# Changelog

All notable changes to the Fitbit Sleep Data Tool will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned Features
- Automated tests (unit and integration)
- Date range selection for batch fetching
- Data visualization (charts and graphs)
- Export to multiple formats (JSON, Excel)
- PyInstaller packaging for standalone executables
- Dark mode optimization
- Statistics and insights dashboard

## [1.0.0] - 2025-11-02

### Added
- Initial release of Fitbit Sleep Data Tool
- Modern GUI built with ttkbootstrap
- OAuth2 authentication with PKCE (Proof Key for Code Exchange)
- Multi-account support
- Encrypted token storage using OS keychain:
  - Windows Credential Manager support
  - macOS Keychain support
  - Linux Secret Service support
  - Fallback to encrypted file storage
- Sleep data fetching from Fitbit API v1.2
- CSV export functionality
- Thread-safe operations with progress indicators
- Automatic token refresh mechanism
- Rate limit handling with exponential backoff
- Cross-platform support (Windows, macOS, Linux)
- Multiple theme support
- Comprehensive error handling and user feedback
- Detailed logging with configurable levels

### Security Features
- No client secret required (Personal OAuth app)
- AES encryption for stored tokens (Fernet)
- SHA-256 hashing for account identifiers
- Secure keychain integration where available
- Token expiration checking with safety buffer

### Sleep Metrics Tracked
- REM sleep duration
- Light sleep duration
- Deep sleep duration
- Sleep Onset Latency (SOL)
- Minutes awake during sleep
- Wake After Sleep Onset (WASO)
- Time In Bed (TIB)
- Sleep type classification
- Data source information

### Documentation
- Comprehensive README with step-by-step installation guide
- Detailed usage instructions for non-technical users
- Troubleshooting section
- Security best practices
- Technical architecture documentation
- AGPL-3.0 license
- Contributing guidelines
- Environment configuration template

### Known Limitations
- Single date fetching only (batch fetching planned for future)
- No data visualization (planned for future)
- Manual date entry required (date picker planned)

## Version History Format

### [Version Number] - YYYY-MM-DD

#### Added
- New features

#### Changed
- Changes in existing functionality

#### Deprecated
- Soon-to-be removed features

#### Removed
- Removed features

#### Fixed
- Bug fixes

#### Security
- Vulnerability fixes

---

## Links

- [Current Release](https://github.com/apob-100/sleep-data-tool/releases/latest)
- [All Releases](https://github.com/apob-100/sleep-data-tool/releases)
- [Issue Tracker](https://github.com/apob-100/sleep-data-tool/issues)
