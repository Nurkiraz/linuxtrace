import os
import platform
import shutil
import socket
import sys
from pathlib import Path


def get_distribution(root: Path = Path("/")) -> dict:
    """Read Linux distribution information."""

    os_release = root / "etc/os-release"
    result = {}

    try:
        for line in os_release.read_text().splitlines():
            if "=" in line and not line.startswith("#"):
                key, value = line.split("=", 1)
                result[key] = value.strip('"')

    except OSError:
        pass

    return result


def get_system_info() -> dict:
    """Collect information about the running system."""

    distribution = get_distribution()

    return {
        "distribution": distribution.get("PRETTY_NAME", "Unknown"),
        "distribution_id": distribution.get("ID", "Unknown"),
        "distribution_family": distribution.get("ID_LIKE", "Unknown"),
        "hostname": socket.gethostname(),
        "kernel": platform.release(),
        "architecture": platform.machine(),
        "python_version": platform.python_version(),
        "python_executable": sys.executable,
        "is_root": os.geteuid() == 0,
        "journalctl_available": shutil.which("journalctl") is not None,
    }
