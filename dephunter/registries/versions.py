from __future__ import annotations

import re

_NUM = re.compile(r"\d+")


def version_sort_key(version: str) -> tuple[tuple[int, ...], int, str]:
    core, _, prerelease = version.strip().partition("-")
    nums = tuple(int(n) for n in _NUM.findall(core)[:4])
    padded = nums + (0,) * (4 - len(nums))
    return (padded, 0 if prerelease else 1, version)
