# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Pending
- Validation against a live Trellix IVX appliance ([checklist](docs/live-test-checklist.md)).

## [0.5.0] - 2026-10-15

Feature complete. 1.0.0 will follow the live appliance test.

### Added
- `ivx lookup FILE|MD5...`: query existing alerts on the appliance by MD5
  (`GET /wsapis/<ver>/alerts?md5=`) without uploading; `known-malicious`,
  `known-suspicious` or `no-alerts`, with `--fail-on-malicious`.
- Sandbox behaviour from extended results (`explanation > osChanges`): signatures
  (`malicious-alert`), processes (`process`, `process_informational`) and file activity
  (`file_informational`), parsed from XML and JSON and shown in the JSON and HTML reports.
- The mock server returns OS changes for `info_level=extended` and answers MD5 alert lookups.
- Installation straight from GitHub or from a release wheel.

### Changed
- README roadmap replaced by a scope section. MITRE ATT&CK mapping, network IOCs and
  appliance health are documented as out of scope because the public API documentation does
  not define them.

### Known limitations
- Still **not tested on a live IVX appliance**.

## [0.4.0] - 2026-10-15

### Added
- Local submission history (SQLite in the user data directory, owner-only on POSIX).
- `ivx submit --skip-known [--max-age DAYS]`: files already analysed on the same appliance
  are not resubmitted; the stored result (with alerts and IOCs) is reused and marked
  `(cached)`. `--no-history` disables reading and writing the history.
- `ivx history [--sha256 HASH] [-f json]` lists past analyses.
- Release workflow: pushing a `v*` tag that matches the package version tests, builds and
  publishes a GitHub Release with the wheel and source archive.
- "Live test report" issue form and SECURITY.md.

### Known limitations
- Still **not tested on a live IVX appliance**.

## [0.3.0] - 2026-10-15

### Added
- `--save-raw DIR` on `submit` and `results`: keep each raw results response as
  `DIR/<id>.xml` or `DIR/<id>.json`.
- `ivx parse FILE...`: parse saved raw responses offline (no appliance, no credentials) into
  any report or IOC format.
- `ivx sanitize FILE...`: mask private IPs, MAC and e-mail addresses, appliance/sensor/host
  names and user-supplied terms with consistent placeholders before sharing; public
  indicators are kept by default.
- CI now also runs on Windows (Python 3.9 and 3.13).

### Fixed
- Windows: CSV reports written with `-o` had broken `\r\r\n` line endings.
- Windows: the CLI no longer crashes when the console code page cannot display a character
  (e.g. in malware names or the table's truncation marker).

### Known limitations
- Still **not tested on a live IVX appliance**.

## [0.2.0] - 2026-10-15

### Added
- `ivx doctor`: step-by-step connectivity diagnostics (DNS, TCP, TLS certificate and expiry,
  API login, API access) that stops at the first failing layer and prints a hint.
- IOC export from malicious results: `-f iocs` (flat CSV) and `-f stix` (STIX 2.1 bundle with
  indicators, malware objects and relationships; deterministic object IDs).
- The SHA-256 of each submitted file is now kept with its result and exported as an IOC.
- `ivx-mock --cert/--key` serves HTTPS, to rehearse certificate handling.
- README section explaining that the toolkit runs on a separate machine, not on the appliance,
  and the prerequisites on the IVX side.

### Fixed
- `IVX_CA_BUNDLE` and `--insecure` were silently ignored when `REQUESTS_CA_BUNDLE` or
  `CURL_CA_BUNDLE` was set in the environment (common on corporate machines). The TLS setting
  is now passed explicitly on every request.

### Known limitations
- Still **not tested on a live IVX appliance**.

## [0.1.0] - 2026-10-15

### Added
- IVX REST API client: login with automatic re-authentication, file and URL submission,
  status polling, results retrieval.
- Tolerant results parser for XML and JSON responses with a normalised verdict.
- `ivx` CLI: `check`, `submit` (files, folders, URLs, `--wait`), `status`, `results`.
- Table, JSON, CSV and standalone HTML reports.
- `ivx-mock` local mock server and a pytest suite that runs against it.
- GitHub Actions CI (ruff + pytest on Python 3.9–3.13).

### Known limitations
- **Not tested on a live IVX appliance.** Verified only against the mock server.
