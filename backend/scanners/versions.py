"""Just enough version ordering for semver-ish npm/PyPI versions."""

import re


def vkey(v):
    main, _, pre = str(v).lstrip("v=").partition("-")
    nums = [int(n) for n in re.findall(r"\d+", main)[:4]]
    nums += [0] * (4 - len(nums))
    # a pre-release sorts before its release: 2.0.0-rc.1 < 2.0.0
    return (*nums, 0 if pre else 1, pre)


def newest(versions):
    versions = [v for v in versions if v]
    return max(versions, key=vkey) if versions else None


def fixed_in(installed, ranges):
    """OSV ranges -> the first fixed version for `installed`; '' if affected with no fix yet; None if not affected."""
    v = vkey(installed)
    for rng in ranges:
        if rng.get("type") not in ("SEMVER", "ECOSYSTEM"):
            continue
        intro = None
        for event in rng.get("events", []):
            if "introduced" in event:
                intro = event["introduced"]
            elif intro is not None and (intro == "0" or vkey(intro) <= v):
                if "fixed" in event and v < vkey(event["fixed"]):
                    return event["fixed"]
                if "last_affected" in event and v <= vkey(event["last_affected"]):
                    return ""
                intro = None
            else:
                intro = None
        if intro is not None and (intro == "0" or vkey(intro) <= v):
            return ""  # introduced and never fixed
    return None
