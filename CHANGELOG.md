# Changelog

## [0.3.0] - 2026-11-24

### Added
- Normalized forensic event model
- UTC timestamp normalization
- Timestamp confidence and warnings
- Deterministic event identifiers
- SQLite event storage and indexes
- Event filtering and pagination
- Possible duplicate detection
- Incremental collection tracking
- Atomic SQLite collection transactions
- Additional automated and integration tests

### Known Limitations
- Full forensic snapshot integrity is not yet guaranteed
- Incremental collection reads source files for hashing



## [0.1.0] - 2026-11-18

### Added

- Initial project architecture
- LinuxTrace CLI
- Version command
- Doctor command
- System information discovery
- Log source discovery
- Rotated log discovery
- Compressed log discovery
- Permission status reporting
- Initial symlink boundary validation
- Eleven automated tests
- Development documentation

## [0.2.0] - 2026-11-18

### Added

- Streaming log reader
- Gzip log reading
- Raw and parsed event models
- Authentication Collector
- SSH authentication parser
- PAM session and authentication parser
- Sudo authorization parser
- Systemd Journal Collector
- Journal parser integration
- Journal metadata enrichment
- Authentication parser dispatcher
- Record-level SHA-256 hashing
- Unclassified authentication event preservation
- 101 additional automated tests

### Security

- Evidence root boundary checks
- Regular file validation
- Log read size limits
- Journal output size limits
- Shell-free subprocess execution

### Fixed

- Missing working_directory field in ParsedEvent

### Testing

- 112 automated tests passed
