"""Container image scanning (Keyring Audit v1.0, Phase 6 coverage).

A credential baked into a container image ships with the image — anyone
who pulls it gets the secret. `scan_image` reads a `docker save` tar
(manifest.json + one directory per layer) and scans every file in every
layer with the same detectors as a repo scan. The finding's source is
"layer <n>: <file path>", so the fix is obvious: the secret was baked
in at that layer, and the Dockerfile line that added it is the one to
change (move the secret to a build secret or a runtime env var).

The same safety contract as the repo scan: a finding keeps a salted
hash + the first/last 4 characters, and the full value only in memory
for the duration of the validity check. The report never shows it.

No Docker daemon is needed — the image is read from the tar file
alone, with stdlib tarfile. A plain tar of files (no manifest.json)
is scanned as a single layer, so the command also works on any
archive. A layer that cannot be read is a warning, not a failure —
the scan reports what it could see.
"""
from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

from .scanner import MAX_FILE_SIZE, _scan_text_lines

WHITEOUT_PREFIX = ".wh."


def _is_binary(data: bytes) -> bool:
    return b"\x00" in data[:8192]


def _scan_layer_file(data: bytes, source: str) -> list[dict]:
    """Scan one file's bytes from a layer. Binary files are skipped."""
    if _is_binary(data):
        return []
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return []
    lines = [(i + 1, line) for i, line in enumerate(text.splitlines())]
    findings = _scan_text_lines(lines, source)
    for f in findings:
        # A credential in an image layer ships with the image — the
        # ranking scores it as image exposure, not a working tree.
        f["exposure_source"] = "image"
    return findings


def _layer_members(layer_tar: tarfile.TarFile) -> list[tuple[str, bytes | None]]:
    """(name, content) for every regular file in a layer tar, in
    order. Whiteout files (which delete a file) hold no content.
    Content is None for a file that was skipped (too large)."""
    out: list[tuple[str, bytes | None]] = []
    for member in layer_tar:
        if not member.isfile():
            continue
        if member.name.split("/")[-1].startswith(WHITEOUT_PREFIX):
            continue
        if member.size > MAX_FILE_SIZE:
            out.append((member.name, None))
            continue
        f = layer_tar.extractfile(member)
        if f is None:
            out.append((member.name, None))
            continue
        out.append((member.name, f.read()))
    return out


def scan_image(path: Path) -> dict:
    """Scan a container image archive. Returns the same raw-scan shape
    as scanner.scan(): {"path", "findings", "warnings"}."""
    path = Path(path)
    if not path.is_file():
        raise ValueError(f"{path} is not a file")
    findings: list[dict] = []
    warnings: list[str] = []
    try:
        outer = tarfile.open(path, "r:*")
    except (tarfile.TarError, OSError) as e:
        raise ValueError(f"{path} is not a readable tar archive: {e}") from None
    with outer:
        try:
            manifest_member = outer.getmember("manifest.json")
        except KeyError:
            manifest_member = None
        if manifest_member is not None:
            try:
                manifest = json.loads(
                    outer.extractfile(manifest_member).read())
                layers = manifest[0].get("Layers", [])
            except (json.JSONDecodeError, IndexError, KeyError,
                    AttributeError) as e:
                raise ValueError(
                    f"{path}: manifest.json is unreadable: {e}") from None
            layer_sources: list[tuple[int, str]] = [
                (i, name) for i, name in enumerate(layers)]
        else:
            # No manifest — the archive itself is one layer.
            layer_sources = [(0, None)]
        for layer_no, layer_name in layer_sources:
            if layer_name is None:
                # The outer tar is the layer.
                members = _layer_members(outer)
                for name, data in members:
                    if data is None:
                        warnings.append(
                            f"layer {layer_no}: skipped {name} "
                            "(too large or unreadable)")
                        continue
                    findings.extend(
                        _scan_layer_file(data, f"layer {layer_no}: {name}"))
                continue
            try:
                layer_member = outer.getmember(layer_name)
            except KeyError:
                warnings.append(f"layer {layer_no}: {layer_name} missing "
                                "from the archive")
                continue
            layer_f = outer.extractfile(layer_member)
            if layer_f is None:
                warnings.append(f"layer {layer_no}: {layer_name} unreadable")
                continue
            try:
                layer_tar = tarfile.open(fileobj=layer_f, mode="r|*")
            except (tarfile.TarError, OSError):
                warnings.append(f"layer {layer_no}: {layer_name} is not "
                                "a readable tar")
                continue
            with layer_tar:
                for name, data in _layer_members(layer_tar):
                    if data is None:
                        warnings.append(
                            f"layer {layer_no}: skipped {name} "
                            "(too large or unreadable)")
                        continue
                    findings.extend(
                        _scan_layer_file(data, f"layer {layer_no}: {name}"))
    # Dedup: the same secret in several layers is one credential, first
    # baked in at its earliest layer — that is the layer to fix.
    seen: dict[str, dict] = {}
    for f in findings:
        fp = f["fingerprint"]
        if fp not in seen:
            seen[fp] = f
    return {"path": str(path), "findings": list(seen.values()),
            "warnings": warnings}
