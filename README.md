# ivx-toolkit

Command-line toolkit for the **Trellix IVX** (Intelligent Virtual Execution) sandbox REST API.
Submit files, folders and URLs, wait for the analysis, and export the verdicts as a table,
JSON, CSV or a standalone HTML report, plus IOCs as CSV or a STIX 2.1 bundle.

> [!WARNING]
> **Status: untested on a live IVX appliance.**
> This project was written against the public Trellix IVX API documentation and is verified
> only against the bundled mock server. Endpoint paths, response formats (XML vs JSON) and
> field names may differ between appliance versions. Validate it in a lab before relying on it
> in production. Live-test results and fixes will be tracked in the
> [CHANGELOG](CHANGELOG.md) — see [docs/live-test-checklist.md](docs/live-test-checklist.md).

## Where it runs

ivx-toolkit does **not** run on the IVX appliance. IVX is a hardened system and nothing is
installed on it. The toolkit runs on a separate machine (your workstation, a jump host or a
SOC server) and talks to the appliance only through its web services API over HTTPS, just
like a browser talks to the web UI:

```
[workstation / jump host: ivx-toolkit]  --HTTPS (443)-->  [IVX appliance: wsapis API]
```

Prerequisites on the IVX side:

- **Network:** the machine running the toolkit can reach the IVX management interface on
  port 443 (or the port you set in `IVX_PORT`).
- **Web services API enabled** on the appliance.
- **An account allowed to use the API.** A normal web UI account may not be enough; use a
  dedicated account with the minimum role needed for submissions.
- **Certificate:** if the appliance uses a self-signed or internal-CA certificate, point
  `IVX_CA_BUNDLE` at it. `--insecure` skips verification and is for lab use only.

Run `ivx doctor` first: it checks each of these layers in order and tells you which one fails.

## Features

- Session login with automatic re-authentication when the token expires (IVX sessions time out
  after ~15 minutes of inactivity)
- Submit single files, whole folders (optionally recursive) and URLs in one command
- Poll until done, then fetch and normalise results (XML **or** JSON responses)
- Verdict per submission: `malicious`, `suspicious`, `no-detection`, `pending`, `error`
- Reports: console table, JSON, CSV, self-contained HTML (light/dark)
- IOC export from malicious results: flat CSV or a STIX 2.1 bundle with stable object IDs
- `ivx doctor`: step-by-step connectivity diagnostics (DNS, TCP, TLS, login, API access)
- Save raw API responses (`--save-raw`), re-parse them offline (`ivx parse`) and mask internal
  details before sharing them (`ivx sanitize`)
- Local submission history: `--skip-known` reuses recent verdicts instead of resubmitting
  the same file, and `ivx history` lists past analyses
- Works on Linux and Windows (both tested in CI)
- `--fail-on-malicious` exit code for scripts and pipelines
- Credentials only from environment variables or an interactive prompt — never on the
  command line
- A local **mock IVX server** (`ivx-mock`) for demos and tests without an appliance

## Installation

```bash
git clone https://github.com/Murat-UGUR/ivx-toolkit.git
cd ivx-toolkit
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .
```

Requires Python 3.9+ and `requests`.

## Configuration

| Variable | Description | Default |
|---|---|---|
| `IVX_HOST` | Appliance address (or use `--host`) | — |
| `IVX_USER` | API user | — |
| `IVX_PASSWORD` | Password (prompted if unset) | — |
| `IVX_API_VERSION` | `v2.0.0` or `v1.2.0` | `v2.0.0` |
| `IVX_PORT` | HTTPS port | `443` |
| `IVX_VERIFY_TLS` | `true` / `false` | `true` |
| `IVX_CA_BUNDLE` | Path to a CA bundle for the appliance certificate | — |
| `IVX_CLIENT_TOKEN` | Optional `X-FeClient-Token` provided by Trellix | — |

See [`.env.example`](.env.example). Use a dedicated API account with the minimum role
required for submissions.

## Usage

```bash
# 1. Diagnose connectivity, then check that authentication works
ivx doctor
ivx check

# 2. Submit a file and wait for the verdict
ivx submit sample.exe --profile win10x64 --wait

# 3. Submit a folder and URLs, write an HTML report
ivx submit ./samples -r --url http://example.com/a.pdf --wait -f html -o report.html

# 4. Fire-and-forget, then check later
ivx submit sample.docx            # prints: <submission_id>  <file>
ivx status 7709
ivx results 7709 -f json --info-level extended
ivx results 7709 --raw            # raw API response, useful for debugging
```

Example table output (from the mock server):

```
SUBMISSION_ID  TARGET                    VERDICT       MAX_SEVERITY  ALERTS  MALWARE
-------------  ------------------------  ------------  ------------  ------  -------------------
7700           samples/eicar_test.txt    malicious     MAJR          1       Mock.Generic.Trojan
7701           samples/report.docx       no-detection  -             0       -
7702           http://example.com/clean  no-detection  -             0       -
```

### Connectivity diagnostics

`ivx doctor` stops at the first failing layer and prints a hint:

```
[PASS] DNS         ivx.lab.local -> 10.0.10.25
[PASS] TCP         ivx.lab.local:443 is reachable
[FAIL] TLS         certificate not trusted: self-signed certificate
                   -> Export the appliance (or issuing CA) certificate and set IVX_CA_BUNDLE to it. For a lab test only, --insecure skips verification.
[SKIP] API login   skipped after previous failure
[SKIP] API access  skipped after previous failure
```

The last step requests the status of a submission ID that cannot exist; a `404` answer proves
that the session token is accepted by the submissions API without submitting anything.

### IOC export

```bash
ivx submit ./samples --wait -f iocs -o iocs.csv     # type,value,verdict,malware,submission_id
ivx submit ./samples --wait -f stix -o iocs.json    # STIX 2.1 bundle
ivx results 7709 -f stix -o iocs.json
```

Only results with a **malicious** verdict produce IOCs, so uncertain alerts never end up in a
block list by accident. Exported indicators:

- SHA-256 of each submitted file (computed locally before upload)
- MD5 / SHA-256 of malware objects reported by IVX
- submitted URLs

The STIX bundle contains `indicator`, `malware` and `indicates` relationship objects. Object IDs
are derived from the indicator value, so exporting the same sample again does not create
duplicates in a threat intelligence platform. `ivx results <id>` does not know what was
submitted, so it can only export the hashes IVX reports.

### Skip files that were already analysed

Every finished file analysis is recorded in a small local database. With `--skip-known`, a
file whose SHA-256 was already analysed **on the same appliance** within `--max-age` days
(default 30) is not uploaded again; its stored result is reused and marked `(cached)`:

```bash
ivx submit ./share-scan -r --wait --skip-known
ivx submit ./share-scan -r --wait --skip-known --max-age 7
ivx history                       # recent analyses
ivx history --sha256 <hash>       # everything known about one file
```

The full raw response is stored with each entry, so cached results keep their alerts and
IOCs. Errors and unfinished analyses are never cached. Only the file's base name is stored,
never its path or contents. Location: `$IVX_HISTORY`, otherwise
`%LOCALAPPDATA%\ivx-toolkit\history.db` on Windows and
`~/.local/share/ivx-toolkit/history.db` elsewhere (owner-only permissions on Linux/macOS).
Use `--no-history` to neither read nor write it.

### Raw responses: save, re-parse offline, sanitise

During a live test, keep the raw API responses so they can be analysed later without the
appliance:

```bash
ivx submit ./samples --wait --save-raw raw/        # writes raw/<id>.xml or raw/<id>.json
ivx results 7709 --info-level extended --save-raw raw/
ivx parse raw/*.xml -f html -o report.html          # offline: no appliance, no credentials
```

Before sharing a raw response (in an issue, with a colleague or a vendor), mask what
identifies your environment:

```bash
ivx sanitize raw/7709.xml --mask corp.example --host-from-env
# -> raw/7709.sanitized.xml  (masked: email=1, host=5, ip=3, mac=1)
```

Masked by default, with consistent placeholders such as `ip-redacted-1`:

- private, loopback, link-local and other non-public IPv4/IPv6 addresses
- MAC addresses and e-mail addresses
- appliance, sensor and host names found in attributes / JSON keys, everywhere they appear
- anything passed with `--mask` (a domain also covers its subdomains)

Public IP addresses, domains of the sample, hashes and malware names are **kept**, because
they are the indicators the analysis is about (`--all-ips` masks public IPs too).
Masking is best-effort: always review the output before sharing it.

### Other options

Useful submit options: `--urgent`, `--live` (live analysis instead of sandbox), `--force`
(re-analyse duplicates), `--analysis-timeout`, `--max-wait`, `--interval`,
`--fail-on-malicious`, `--insecure` (lab only). Run `ivx submit -h` for all of them.

> **Note:** `--note` text may be shared with the Trellix DTI cloud. Do not put customer or
> internal information in it.

## Try it without an appliance

```bash
ivx-mock --port 8443 &
export IVX_SCHEME=http IVX_HOST=127.0.0.1 IVX_PORT=8443 IVX_USER=admin IVX_PASSWORD=admin
echo test > eicar_demo.txt
ivx submit eicar_demo.txt --wait --interval 1
```

The mock marks any file or URL containing `malware` or `eicar` in its name or content as
malicious. It imitates the documented request/response shapes only; it is not an emulator.
To rehearse certificate handling, start it with `--cert cert.pem --key key.pem` to serve HTTPS.

## API endpoints used

| Purpose | Request |
|---|---|
| Login | `POST /wsapis/common/<ver>/auth/login` (Basic auth → `X-FeApi-Token` header). Falls back to the legacy `/wsapis/<ver>/auth/login`. |
| Submit file | `POST /wsapis/<ver>/submissions/file` (multipart: `options` JSON first, then `filename`) |
| Submit URL | `POST /wsapis/<ver>/submissions/url` |
| Status | `GET /wsapis/<ver>/submissions/status/<id>` |
| Results | `GET /wsapis/<ver>/submissions/results/<id>?info_level=…` |

Reference: [Trellix IVX API documentation](https://docs-dr.trellix.com/network-and-platform/docs/ivx-api-endpoints).

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check . && ruff format --check .
```

### Releases

Bump `version` in `pyproject.toml` and `src/ivx_toolkit/__init__.py`, update the
CHANGELOG, then create a matching tag (`v0.4.0`) from GitHub's *Releases > Draft a new
release* page or with `git tag v0.4.0 && git push origin v0.4.0`. The release workflow checks
that the tag matches the package version, runs the tests, builds the wheel and source
archive, and publishes them on a GitHub Release.

### Reporting live test results

Use the **Live test report** issue form. It asks for the IVX version, the `ivx doctor`
output and an optional sanitised raw response. See also [SECURITY.md](SECURITY.md).

## Roadmap

- [ ] Validate against a live IVX appliance (see checklist)
- [x] IOC export (STIX 2.1 / CSV)
- [x] Connectivity diagnostics (`ivx doctor`)
- [x] Raw response capture, offline parsing and sanitising
- [x] Windows support
- [x] Local history and `--skip-known`
- [ ] Network IOCs (domains, IPs) from extended results, once the live response format is known
- [ ] MITRE ATT&CK technique extraction
- [ ] Server-side hash lookup, if the appliance API offers one (local history covers it today)
- [ ] Appliance health checks (queue, license, guest images)

## Türkçe özet

Trellix IVX sandbox REST API'si için komut satırı aracı: dosya, klasör ve URL gönderir, analiz
bitene kadar bekler, sonucu tablo, JSON, CSV ya da HTML rapor olarak verir; zararlı sonuçlardan
IOC'leri CSV ya da STIX 2.1 olarak dışa aktarır.
Araç IVX cihazının **üzerinde çalışmaz**; ayrı bir makineden HTTPS üzerinden API'ye bağlanır.
Bağlantıyı adım adım sınamak için önce `ivx doctor` çalıştırın. Ham API yanıtlarını
`--save-raw` ile kaydedip `ivx parse` ile cihaz olmadan yeniden işleyebilir, paylaşmadan önce
`ivx sanitize` ile iç IP, MAC, e-posta ve host adlarını maskeleyebilirsiniz.
`--skip-known` ile aynı cihazda yakın zamanda analiz edilmiş dosyalar yeniden gönderilmez;
sonuç yerel geçmişten alınır (`ivx history`).
**Henüz canlı bir IVX cihazında test edilmedi**; yalnızca dahili mock sunucuya karşı doğrulandı.
Üretimde kullanmadan önce lab ortamında deneyin.

## Disclaimer

Independent project, not affiliated with or endorsed by Trellix. "Trellix" and "IVX" are
trademarks of their respective owner. Only submit samples you are authorised to analyse.

## License

[MIT](LICENSE) © 2026 Murat UĞUR
