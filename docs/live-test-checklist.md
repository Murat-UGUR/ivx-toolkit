# Live test checklist

ivx-toolkit has only been verified against the bundled mock server. Use this checklist the
first time you run it against a real IVX appliance, and record the outcome in the CHANGELOG.

Use a **lab** appliance and harmless test files (e.g. the EICAR test string) only.

## Environment

- [ ] IVX version / build: ______
- [ ] API version used (`IVX_API_VERSION`): ______
- [ ] TLS: trusted certificate via `IVX_CA_BUNDLE`, or `--insecure` (lab only)
- [ ] Dedicated API user with the minimum role for submissions

## Steps

1. **Authentication**
   - [ ] `ivx -vv check` succeeds
   - [ ] Which login path worked? `/wsapis/common/<ver>/auth/login` or legacy `/wsapis/<ver>/auth/login`
2. **File submission**
   - [ ] `ivx submit eicar.com --profile <profile>` returns an ID
   - [ ] Profile names accepted by your appliance: ______
3. **Status**
   - [ ] `ivx status <id>` shows `In Progress`, then `Done`
   - [ ] Any other status values seen (failed, queued, …)? ______
4. **Results**
   - [ ] `ivx results <id> --raw` — save the raw output (remove any internal hostnames/IPs)
   - [ ] Is the response XML or JSON? ______
   - [ ] `ivx results <id>` shows the expected verdict, severity and malware name
   - [ ] Repeat with `--info-level normal` and `--info-level extended`
5. **URL submission**
   - [ ] `ivx submit --url http://<safe-test-url> --wait`
   - [ ] Does the appliance accept `urls` as a JSON array? ______
6. **Batch + report**
   - [ ] `ivx submit ./folder --wait -f html -o report.html` produces a correct report
7. **Session expiry**
   - [ ] A run longer than 15 minutes re-authenticates automatically
8. **Logout**
   - [ ] No errors at the end of a run (logout is best-effort)

## Reporting differences

If anything differs from the mock, open an issue with the command, the error and a
**sanitised** raw response, so the parser can be adjusted. Never commit real customer data,
hostnames, IPs, credentials or malware samples to this repository.
