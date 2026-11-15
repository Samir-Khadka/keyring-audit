"""Tests for v1.0 container image scanning (Phase 6 coverage).
A fake `docker save` tar is built in a temp dir: manifest.json plus
one directory per layer, each holding a layer tar (one gzipped).
No Docker daemon, no network."""
import gzip
import io
import json
import tarfile
from pathlib import Path

import pytest

from keyring_audit import images as images_mod
from keyring_audit.__main__ import cli
from keyring_audit.ranking import rank

# Fragmented on purpose: the full literal trips GitHub push protection.
GITHUB_PAT = "ghp_" + "1234567890abcdefghij1234567890abcdef"


def _layer_tar(files: dict[str, str], gzip_it: bool = False) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for name, content in files.items():
            data = content.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
    raw = buf.getvalue()
    return gzip.compress(raw) if gzip_it else raw


def _make_image(tmp_path: Path, layers: list[bytes]) -> Path:
    """A docker-save-shaped tar: manifest.json + <dir>/layer.tar."""
    image_path = tmp_path / "app.tar"
    buf = io.BytesIO()
    layer_names = []
    with tarfile.open(fileobj=buf, mode="w") as t:
        for i, layer in enumerate(layers):
            name = f"layer{i:02d}/layer.tar"
            layer_names.append(name)
            info = tarfile.TarInfo(name)
            info.size = len(layer)
            t.addfile(info, io.BytesIO(layer))
        manifest = json.dumps([{"Config": "config.json",
                                "RepoTags": ["app:latest"],
                                "Layers": layer_names}]).encode()
        info = tarfile.TarInfo("manifest.json")
        info.size = len(manifest)
        t.addfile(info, io.BytesIO(manifest))
    image_path.write_bytes(buf.getvalue())
    return image_path


def _fixture(tmp_path: Path) -> Path:
    layer0 = _layer_tar({"app/config.py": f'TOKEN = "{GITHUB_PAT}"\n',
                         "app/main.py": "# clean\n"})
    # The same secret again in layer 1 — the dedup must keep layer 0.
    layer1 = _layer_tar({"app/config.py": f'TOKEN = "{GITHUB_PAT}"\n',
                         "app/other.py": "# clean\n"}, gzip_it=True)
    return _make_image(tmp_path, [layer0, layer1])


def test_scan_image_finds_the_secret_in_layer_zero(tmp_path):
    result = images_mod.scan_image(_fixture(tmp_path))
    assert len(result["findings"]) == 1  # deduped across layers
    f = result["findings"][0]
    assert f["detector"] == "github-pat-classic"
    assert f["source"] == "layer 0: app/config.py"
    assert f["line"] == 1
    assert f["redacted"].startswith("ghp_")
    assert f["exposure_source"] == "image"
    assert result["warnings"] == []


def test_scan_image_scores_image_exposure(tmp_path):
    result = images_mod.scan_image(_fixture(tmp_path))
    f = result["findings"][0]
    f["validity"] = {"live": "unknown", "reason": "offline",
                     "permissions": [], "method": "none"}
    f["owner"] = {"name": None, "source": "none"}
    ranked = rank(f)
    assert ranked["risk"]["components"]["exposure"]["score"] == 15
    assert "container image layer" in \
        ranked["risk"]["components"]["exposure"]["why"]


def test_scan_image_plain_tar_is_one_layer(tmp_path):
    plain = tmp_path / "plain.tar"
    plain.write_bytes(_layer_tar(
        {"config.py": f'TOKEN = "{GITHUB_PAT}"\n'}))
    result = images_mod.scan_image(plain)
    assert len(result["findings"]) == 1
    assert result["findings"][0]["source"] == "layer 0: config.py"


def test_scan_image_clean_image_has_no_findings(tmp_path):
    clean = _make_image(tmp_path, [_layer_tar({"app.py": "# nothing\n"})])
    result = images_mod.scan_image(clean)
    assert result["findings"] == []
    assert result["warnings"] == []


def test_scan_image_not_a_tar(tmp_path):
    bad = tmp_path / "bad.tar"
    bad.write_text("not a tar at all\n")
    with pytest.raises(ValueError, match="not a readable tar"):
        images_mod.scan_image(bad)


def test_scan_image_missing_file(tmp_path):
    with pytest.raises(ValueError, match="is not a file"):
        images_mod.scan_image(tmp_path / "nope.tar")


def test_cli_scan_image_no_verify(tmp_path, capsys):
    image = _fixture(tmp_path)
    rc = cli(["scan-image", str(image), "--no-verify"])
    assert rc == 0  # the PAT is unverified, so no live finding at 60+
    out = capsys.readouterr().out
    assert "layer 0: app/config.py" in out
    assert "1 credential(s) found" in out
    assert GITHUB_PAT not in out  # the secret never appears in output


def test_cli_scan_image_json(tmp_path, capsys):
    image = _fixture(tmp_path)
    rc = cli(["scan-image", str(image), "--no-verify", "--format", "json"])
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    assert len(doc["findings"]) == 1
    assert doc["findings"][0]["source"] == "layer 0: app/config.py"
    assert GITHUB_PAT not in json.dumps(doc)
