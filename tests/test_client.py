import pytest

from ivx_toolkit import IVXClient, IVXError, SubmissionOptions, parse_results


def test_login_and_logout(settings):
    with IVXClient(settings) as client:
        assert client.login()
        assert client.token
    assert client.token is None


def test_bad_credentials(settings):
    settings.password = "wrong"
    with pytest.raises(IVXError) as err:
        IVXClient(settings).login()
    assert err.value.status_code == 401


def test_submit_file_wait_and_results(settings, tmp_path):
    sample = tmp_path / "malware_sample.bin"
    sample.write_bytes(b"not really malware")
    with IVXClient(settings) as client:
        sid = client.submit_file(sample, SubmissionOptions(profiles=["win10x64"]))
        assert client.status(sid) == "In Progress"
        assert client.wait(sid, interval=0) == "Done"
        ctype, body = client.results_raw(sid)
    result = parse_results(sid, ctype, body, target=str(sample))
    assert result.verdict == "malicious"
    assert result.malware_names == ["Mock.Generic.Trojan"]
    assert result.max_severity == "MAJR"


def test_clean_file(settings, tmp_path):
    sample = tmp_path / "invoice.pdf"
    sample.write_bytes(b"%PDF-1.4")
    with IVXClient(settings) as client:
        sid = client.submit_file(sample, SubmissionOptions())
        client.wait(sid, interval=0)
        ctype, body = client.results_raw(sid)
    assert parse_results(sid, ctype, body).verdict == "no-detection"


def test_submit_urls(settings):
    with IVXClient(settings) as client:
        sid = client.submit_urls(["http://example.com/malware.exe"], SubmissionOptions())
        client.wait(sid, interval=0)
        ctype, body = client.results_raw(sid)
    assert parse_results(sid, ctype, body).verdict == "malicious"


def test_reauth_after_token_expiry(settings, tmp_path):
    sample = tmp_path / "a.txt"
    sample.write_text("x")
    client = IVXClient(settings)
    client.login()
    client.token = "expired-token"  # simulate the 15-minute session timeout
    sid = client.submit_file(sample, SubmissionOptions())
    assert sid
    assert client.token != "expired-token"
    client.logout()


def test_unknown_submission(settings):
    with IVXClient(settings) as client, pytest.raises(IVXError) as err:
        client.status("999999")
    assert err.value.status_code == 404


def test_missing_file(settings, tmp_path):
    with IVXClient(settings) as client, pytest.raises(IVXError):
        client.submit_file(tmp_path / "nope.exe", SubmissionOptions())
