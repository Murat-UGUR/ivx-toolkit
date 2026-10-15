# Security policy

## Reporting a vulnerability

Please do **not** open a public issue for security problems in ivx-toolkit itself (for
example, credentials leaking into logs or reports, or unsafe handling of responses).
Use GitHub's private reporting instead: **Security > Report a vulnerability** on this
repository.

Vulnerabilities in Trellix products should be reported to Trellix, not here.

## Handling data

- Credentials are read from environment variables or prompted; they are never accepted on
  the command line and never written to disk by the toolkit.
- Raw API responses (`--save-raw`) and the local history database can contain details of
  your environment. Keep them out of version control (`raw/` is in `.gitignore`) and run
  `ivx sanitize` before sharing anything.
- Only submit samples you are authorised to analyse.
