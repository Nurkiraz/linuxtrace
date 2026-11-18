import os
from pathlib import Path

LOG_SOURCES = {
    "authentication": [
        "var/log/auth.log",
        "var/log/secure",
    ],
    "system": [
        "var/log/syslog",
        "var/log/messages",
        "var/log/kern.log",
        "var/log/boot.log",
    ],
    "audit": [
        "var/log/audit/audit.log",
    ],
    "package": [
        "var/log/apt/history.log",
        "var/log/dpkg.log",
        "var/log/pacman.log",
        "var/log/dnf.log",
    ],
    "user_activity": [
        "var/log/wtmp",
        "var/log/btmp",
        "var/log/lastlog",
    ],
    "journal": [
        "var/log/journal",
        "run/log/journal",
    ],
}


def discover_logs(root: Path = Path("/")) -> list[dict]:
    """Discover available Linux log sources."""

    results = []
    root = root.resolve()

    for category, sources in LOG_SOURCES.items():
        for source in sources:
            path = root / source

            try:
                if not path.resolve().is_relative_to(root):
                    status = "unsafe_path"
                elif not path.exists():
                    status = "missing"
                elif not os.access(
                    path,
                    os.R_OK | os.X_OK if path.is_dir() else os.R_OK,
                ):
                    status = "permission_denied"
                else:
                    status = "available"

            except (OSError, RuntimeError):
                status = "error"

            results.append(
                {
                    "category": category,
                    "path": str(path),
                    "status": status,
                }
            )

    return results


def discover_rotated_logs(root: Path = Path("/")) -> list[dict]:
    """Discover rotated and compressed Linux log files."""

    results = []
    root = root.resolve()

    for category, sources in LOG_SOURCES.items():
        if category == "journal":
            continue

        for source in sources:
            path = root / source

            try:
                if not path.parent.resolve().is_relative_to(root):
                    continue

                for rotated in sorted(path.parent.glob(f"{path.name}.*")):
                    suffix = rotated.name[len(path.name) + 1 :]

                    if suffix.endswith(".gz"):
                        suffix = suffix[:-3]

                    if not (suffix.isdigit() or suffix == "old"):
                        continue

                    if not rotated.resolve().is_relative_to(root):
                        status = "unsafe_path"
                    elif not rotated.is_file():
                        continue
                    elif not os.access(rotated, os.R_OK):
                        status = "permission_denied"
                    else:
                        status = "available"

                    results.append(
                        {
                            "category": category,
                            "path": str(rotated),
                            "status": status,
                            "rotated": True,
                            "compressed": rotated.suffix == ".gz",
                        }
                    )

            except (OSError, RuntimeError):
                results.append(
                    {
                        "category": category,
                        "path": str(path),
                        "status": "error",
                    }
                )

    return results
