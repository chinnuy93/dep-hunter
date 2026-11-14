from __future__ import annotations

import logging
from pathlib import Path

from dephunter.core.util import gzip_write, sha256_bytes

log = logging.getLogger(__name__)


class EvidenceStore:
    """Content-addressed, gzip-compressed evidence archive."""

    def __init__(self, evidence_dir: Path) -> None:
        self.evidence_dir = evidence_dir
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

    def store(self, content: bytes) -> tuple[str, str]:
        digest = sha256_bytes(content)
        path = self.evidence_dir / f"{digest}.gz"
        if not path.exists():
            try:
                gzip_write(path, content)
            except OSError as exc:
                log.warning("cannot persist evidence %s: %s", digest, exc)
                return digest, ""
        return digest, str(path)
