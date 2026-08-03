"""Fetch plugin releases from wordpress.org into a local cache.

This is the only module that touches the network, and it only ever talks to
wordpress.org — never to a site under test. Everything downstream runs offline
against the cache, which matters for two reasons: your hunting hypotheses stay
on your own disk, and a re-run produces the same answer as the first run.

Two deliberate choices:

  * Release ZIPs, not SVN checkouts. What ships to users is decided by the
    `Stable Tag:` line in trunk/readme.txt, not by trunk, and SVN lets an author
    modify an existing tag after release. Diffing ZIP against ZIP compares what
    users actually received.
  * `?nostats=1` on every download, which is what the official directory
    slurper does, so browsing a plugin's history does not inflate its author's
    download counters.
"""

from __future__ import annotations

import hashlib
import json
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path

API = "https://api.wordpress.org/plugins/info/1.2/"
DOWNLOAD = "https://downloads.wordpress.org/plugin/{slug}.{version}.zip?nostats=1"
USER_AGENT = "wp-authz-audit (+https://github.com/kubakozub/wp-authz-audit)"
TIMEOUT = 30


class FetchError(RuntimeError):
    pass


def _get(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            return response.read()
    except Exception as error:  # noqa: BLE001 - surfaced to the CLI as a message
        raise FetchError(f"{url}: {error}") from error


@dataclass
class PluginInfo:
    slug: str
    name: str
    version: str
    active_installs: int
    last_updated: str
    versions: dict[str, str]

    @property
    def released(self) -> list[str]:
        """Released versions, newest first, excluding trunk."""
        return sorted(
            (v for v in self.versions if v.lower() != "trunk"),
            key=version_key,
            reverse=True,
        )

    def previous(self, version: str) -> str | None:
        released = self.released
        if version not in released:
            return None
        index = released.index(version)
        return released[index + 1] if index + 1 < len(released) else None


def version_key(version: str) -> tuple:
    """Sortable key tolerant of 1.2, 1.2.3, 1.2.3.4 and suffixes like 1.2-beta."""
    parts = []
    for chunk in version.replace("-", ".").split("."):
        digits = "".join(c for c in chunk if c.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts + [0] * (5 - len(parts)))[:5]


def info(slug: str, cache: Path) -> PluginInfo:
    cache.mkdir(parents=True, exist_ok=True)
    path = cache / f"{slug}.info.json"

    if path.exists():
        payload = json.loads(path.read_text(encoding="utf-8"))
    else:
        query = urllib.parse.urlencode(
            {
                "action": "plugin_information",
                "request[slug]": slug,
                "request[fields][versions]": "1",
                "request[fields][sections]": "0",
            }
        )
        raw = _get(f"{API}?{query}")
        payload = json.loads(raw.decode("utf-8"))
        if payload.get("error"):
            raise FetchError(f"{slug}: {payload['error']}")
        path.write_text(json.dumps(payload), encoding="utf-8")

    return PluginInfo(
        slug=payload.get("slug", slug),
        name=payload.get("name", slug),
        version=payload.get("version", ""),
        active_installs=payload.get("active_installs", 0) or 0,
        last_updated=payload.get("last_updated", ""),
        versions=payload.get("versions", {}) or {},
    )


def release(slug: str, version: str, cache: Path) -> Path:
    """Extract one release into the cache and return its directory."""
    target = cache / slug / version
    if (target / ".complete").exists():
        return target

    archive = cache / slug / f"{slug}.{version}.zip"
    archive.parent.mkdir(parents=True, exist_ok=True)

    if not archive.exists():
        data = _get(DOWNLOAD.format(slug=slug, version=version))
        archive.write_bytes(data)
        (archive.with_suffix(".zip.sha256")).write_text(
            hashlib.sha256(data).hexdigest(), encoding="utf-8"
        )

    target.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as bundle:
        for member in bundle.infolist():
            name = member.filename
            # Refuse absolute paths and traversal; a plugin ZIP is untrusted input.
            if name.startswith("/") or ".." in Path(name).parts:
                continue
            bundle.extract(member, target)

    (target / ".complete").write_text("", encoding="utf-8")
    return target


def plugin_root(extracted: Path) -> Path:
    """A release ZIP contains one top-level directory; return it."""
    entries = [p for p in extracted.iterdir() if p.is_dir() and p.name != "__MACOSX"]
    return entries[0] if len(entries) == 1 else extracted


def recently_updated(count: int, cache: Path) -> list[str]:
    """Slugs of the most recently updated plugins — the discovery worklist."""
    query = urllib.parse.urlencode(
        {
            "action": "query_plugins",
            "request[browse]": "updated",
            "request[per_page]": str(min(count, 250)),
        }
    )
    payload = json.loads(_get(f"{API}?{query}").decode("utf-8"))
    return [entry["slug"] for entry in payload.get("plugins", [])][:count]
