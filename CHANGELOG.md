# Changelog

All notable changes to **Zano-CFLeak** will be documented in this file.

The format is based on **Keep a Changelog**  
and this project adheres to **Semantic Versioning**.

---

## [2.1.0]

### Added

#### IPv6 Support
- Full IPv6 (AAAA record) resolution alongside IPv4
- Detection of Cloudflare IPv6 IP ranges (7 ranges)
- Results display both IPv4 and IPv6 addresses with individual Cloudflare status indicators

#### Multiple IPs Detection
- DNS resolution now returns **all IPs** for a domain
- Each IP is checked individually against Cloudflare ranges
- Output format example:  
  `v4: [ip1, ip2, ip3]`
- CSV export uses semicolon (`;`) separators for multiple IPs

#### Progress Bar
- Real-time progress bar during subdomain scanning using `tqdm`
- Displays elapsed time and estimated remaining time
- Live statistics:
  - Found origin IPs
  - Cloudflare-protected targets
- Automatically disabled in quiet mode (`-q`)

#### Dynamic Cloudflare IP Ranges
- Dynamic fetching of Cloudflare IP ranges from official endpoints:
  - https://www.cloudflare.com/ips-v4
  - https://www.cloudflare.com/ips-v6
- Automatic fallback to hardcoded ranges if API is unreachable
- Status logs indicate whether ranges were loaded from API or fallback

#### Multiple Output Formats
- JSON output (`-f json`)
- YAML output (`-f yaml`) using a custom serializer (no external dependency)
- CSV output (`-f csv`)
- Enhanced human-readable output with structured report sections

#### Multiple Wordlists Support
- Load multiple wordlists using repeated `-w` flags
- Wordlists are automatically merged and deduplicated
- Each wordlist load is logged individually

#### Verbosity Controls
- Verbose mode (`-v`, `--verbose`) shows all results including unresolved domains
- Quiet mode (`-q`, `--quiet`) outputs only confirmed origin IPs
- Structured logging system with verbosity levels

#### Root Domain Check
- Automatic resolution of the root domain before subdomain enumeration

#### Scan Summary
End-of-scan summary includes:
- Total domains checked
- Count of non-Cloudflare (origin) IPs
- Count of Cloudflare-protected domains
- Count of unresolved domains
- Error count (if any)

#### Wordlist Improvements
- Support for comments in wordlists (`#`)
- Empty lines are automatically ignored

#### Data Classes & Type Hints
- `ResolveResult` dataclass with list-based IP fields
- `ipv4` and `ipv6` stored as `list[str]`
- Cloudflare IP tracking via:
  - `ipv4_cloudflare`
  - `ipv6_cloudflare`
- Helper properties:
  - `ipv4_non_cf`
  - `ipv6_non_cf`
- `ScanReport` dataclass for full report serialization
- `CloudflareIPRanges` class for IP range management
- `ReportWriter` for multi-format output
- `CloudRip` main scanner class with encapsulated state
- `Colors` class for terminal color constants
- `OutputFormat` enum for output format types
- Comprehensive type hints across the codebase

---

### Changed

#### Architecture
- Refactored from procedural to object-oriented architecture
- Scanner state and configuration encapsulated in `CloudRip`
- Clear separation between scanning, detection, and reporting logic

#### Cloudflare IP Detection
- Moved `ipaddress` import to module level
- Separated IPv4 and IPv6 parsing with proper error handling
- Cloudflare IP ranges are lazily loaded on first use

#### Error Handling
- Added handling for `dns.resolver.LifetimeTimeout`
- Added `EOFError` handling for user interrupts
- Explicit UTF-8 encoding for all file operations

#### Signal Handling
- Signal handling moved from global scope to instance method
- Cleaner shutdown using `cancel_futures=True`

#### Rate Limiting
- Reduced inter-request delay from `0.1s` to `0.05s`

#### Output Formatting
- Results now display both IPv4 and IPv6 addresses
- Cloudflare IPs marked with `[CF]`
- Colored `[CLOUDFLARE]` indicator for protected domains
- Improved categorized report sections:
  - Found
  - Cloudflare
  - Not Found
  - Errors

#### Documentation
- Added module-level docstring describing Zano-CFLeak purpose
- Added docstrings to all classes and methods

---

### Removed
- Removed `os` module usage (replaced with `pathlib.Path`)
- Removed global `stop_requested` variable
- Removed standalone color constants (centralized in `Colors`)

---

### Technical Improvements

#### Code Quality
- Added executable shebang: `#!/usr/bin/env python3`
- Migrated file handling to `pathlib.Path`
- Optimized wordlist deduplication using `set`
- Explicit UTF-8 encoding for all I/O operations

#### Dependencies
- `requests` for Cloudflare IP API calls
- `tqdm` for progress visualization
- Built-in modules: `csv`, `json`, `datetime`, `dataclasses`, `enum`

#### CLI Improvements
- Added `RawDescriptionHelpFormatter`
- Included real usage examples in CLI help
- Improved argument descriptions and clarity

---

## [2.0.0]

### Added
- Major wordlist expansion (100 → 600+ subdomains)
- API, cloud infrastructure, and IoT endpoint coverage
- Authentication, payment, analytics, and CI/CD targets
- Improved geographic coverage
- Better discovery for databases and backend services

---

## [1.5.0]

### Added
- Rate limiting to prevent DNS blocking

### Changed
- Improved thread handling and stability

### Fixed
- Prevented crashes on DNS resolution failures
- Improved colored terminal output

---

## [1.0.0]

### Added
- Initial release of Zano-CFLeak
- Multi-threaded subdomain enumeration
- Cloudflare IP filtering
- Custom wordlist support
- Result export to file
- Initial reconnaissance wordlist (~100 entries)
