# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Pending
- Validation against a live Trellix IVX appliance ([checklist](docs/live-test-checklist.md)).

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
