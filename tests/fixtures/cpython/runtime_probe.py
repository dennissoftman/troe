"""Exercise TROE-backed filesystem, clock, environment, and entropy behavior."""

import errno
import os
import pathlib
import secrets
import random
import sys
import tempfile
import time

SHARED = "/vol/shared"


def main() -> int:
    assert sys.platform == "troe", sys.platform
    assert sys.flags.no_user_site == 1
    assert sys.dont_write_bytecode is True
    assert not any("site-packages" in entry for entry in sys.path), sys.path

    directory = pathlib.Path(SHARED) / "cpython-runtime-probe"
    directory.mkdir(exist_ok=True)
    target = directory / "written.txt"
    target.write_text("runtime-probe-content\n", encoding="utf-8")
    assert target.read_text(encoding="utf-8") == "runtime-probe-content\n"
    assert target.stat().st_size == 22
    assert sorted(item.name for item in directory.iterdir()) == ["written.txt"]

    scratch = pathlib.Path(tempfile.mkdtemp(dir=directory))
    member = scratch / "member.txt"
    member.write_text("temporary", encoding="utf-8")
    assert member.read_text(encoding="utf-8") == "temporary"
    member.unlink()
    scratch.rmdir()

    with tempfile.NamedTemporaryFile(dir=directory, suffix=".tmp") as handle:
        handle.write(b"temporary-round-trip")
        handle.flush()
        handle.seek(0)
        assert handle.read() == b"temporary-round-trip"
        named = pathlib.Path(handle.name)
        assert named.parent == directory, named

    descriptor, path_name = tempfile.mkstemp(dir=directory, suffix=".mk")
    with os.fdopen(descriptor, "w+b") as handle:
        handle.write(b"mkstemp")
        handle.seek(0)
        assert handle.read() == b"mkstemp"
    pathlib.Path(path_name).unlink()

    # Staged bytes stay immutable, so rewriting an earlier offset is refused
    # rather than silently corrupting the streamed replacement. Use raw
    # descriptors: a buffered writer would retry the rejected byte on close.
    rewrite = directory / "rewrite.txt"
    descriptor = os.open(rewrite, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        assert os.write(descriptor, b"abcdef") == 6
        assert os.lseek(descriptor, 0, os.SEEK_SET) == 0
        assert os.read(descriptor, 6) == b"abcdef"
        os.lseek(descriptor, 0, os.SEEK_SET)
        try:
            os.write(descriptor, b"z")
        except OSError as error:
            assert error.errno == errno.ENOTSUP, error.errno
        else:
            raise AssertionError("rewriting staged bytes unexpectedly succeeded")
    finally:
        os.close(descriptor)
    rewrite.unlink()

    target.unlink()
    directory.rmdir()

    os.chdir(SHARED)
    assert os.getcwd() == SHARED, os.getcwd()

    monotonic = time.monotonic()
    assert time.monotonic() >= monotonic
    assert time.time() > 1_600_000_000
    assert time.process_time() >= 0.0

    first = os.urandom(32)
    assert len(first) == 32
    assert first != os.urandom(32)
    assert len(secrets.token_bytes(16)) == 16
    generator = random.Random()
    assert generator.random() != random.Random().random()
    assert 0 <= random.randrange(1000) < 1000

    print("runtime-probe", len(first), os.getcwd())
    return 0


if __name__ == "__main__":
    sys.exit(main())
