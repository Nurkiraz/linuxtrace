from linuxtrace.utils.system import (
    get_distribution,
    get_system_info,
)


def test_get_distribution(tmp_path):
    etc = tmp_path / "etc"
    etc.mkdir()

    os_release = etc / "os-release"

    os_release.write_text('PRETTY_NAME="Test Linux"\nID=testlinux\nID_LIKE=debian\n')

    result = get_distribution(tmp_path)

    assert result["PRETTY_NAME"] == "Test Linux"
    assert result["ID"] == "testlinux"
    assert result["ID_LIKE"] == "debian"


def test_missing_os_release(tmp_path):
    result = get_distribution(tmp_path)

    assert result == {}


def test_get_system_info():
    result = get_system_info()

    assert "distribution" in result
    assert "hostname" in result
    assert "kernel" in result
    assert "python_version" in result
    assert isinstance(result["is_root"], bool)
    assert isinstance(result["journalctl_available"], bool)
