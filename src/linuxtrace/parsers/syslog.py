import re

SYSLOG_PATTERN = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}"
    r"\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<process>[\w./-]+)"
    r"(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<message>.*)$"
)


def parse_syslog(line: str) -> dict | None:
    """Parse a traditional syslog header."""

    match = SYSLOG_PATTERN.match(line)

    if not match:
        return None

    result = match.groupdict()

    if result["pid"] is not None:
        result["pid"] = int(result["pid"])

    return result
