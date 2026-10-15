# ivx-toolkit

Command-line toolkit for the **Trellix IVX** (Intelligent Virtual Execution) sandbox REST API.
Submit files, folders and URLs, wait for the analysis, and export the verdicts as a table,
JSON, CSV or a standalone HTML report.

> [!WARNING]
> **Status: untested on a live IVX appliance.**
> This project was written against the public Trellix IVX API documentation and is verified
> only against the bundled mock server. Endpoint paths, response formats (XML vs JSON) and
> field names may differ between appliance versions. Validate it in a lab before relying on it
> in production. Live-test results and fixes will be tracked in the
> [CHANGELOG](CHANGELOG.md) — see [docs/live-test-checklist.md](docs/live-test-checklist.md).

## Features

- Session login with automatic re-authentication when the token expires (IVX sessions time out
  after ~15 minutes of inactivity)
- Submit single files, whole folders (optionally recursive) and URLs in one command
- Poll until done, then fetch and normalise results (XML **or** JSON responses)
- Verdict per submission: `malicious`, `suspicious`, `no-detection`, `pending`, `error`
- Reports: console table, JSON, CSV, self-contained HTML (light/dark)
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
# 1. Check that authentication works
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

## Roadmap

- [ ] Validate against a live IVX appliance (see checklist)
- [ ] Hash pre-check to skip already analysed samples
- [ ] IOC export (STIX 2.1 / CSV) from extended results
- [ ] MITRE ATT&CK technique extraction
- [ ] Appliance health checks (queue, license, guest images)

## Türkçe özet

Trellix IVX sandbox REST API'si için komut satırı aracı: dosya, klasör ve URL gönderir, analiz
bitene kadar bekler, sonucu tablo, JSON, CSV ya da HTML rapor olarak verir.
**Henüz canlı bir IVX cihazında test edilmedi**; yalnızca dahili mock sunucuya karşı doğrulandı.
Üretimde kullanmadan önce lab ortamında deneyin.

## Disclaimer

Independent project, not affiliated with or endorsed by Trellix. "Trellix" and "IVX" are
trademarks of their respective owner. Only submit samples you are authorised to analyse.

## License

[MIT](LICENSE) © 2026 Murat UĞUR
