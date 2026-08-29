"""Assert that every excluded facility fails explicitly and deterministically."""

import sys

EXCLUDED = (
    "socket",
    "ssl",
    "sqlite3",
    "ctypes",
    "multiprocessing",
    "subprocess",
    "asyncio",
    "curses",
    "zlib",
    "select",
)


def main() -> int:
    for name in EXCLUDED:
        try:
            __import__(name)
        except ImportError:
            continue
        raise AssertionError(f"excluded module imported: {name}")

    import _thread

    lock = _thread.allocate_lock()
    with lock:
        assert lock.locked() is True
    assert lock.locked() is False

    local = _thread._local()
    local.value = "thread-state"
    assert local.value == "thread-state"

    try:
        _thread.start_new_thread(lambda: None, ())
    except (RuntimeError, PermissionError, OSError) as error:
        rendered = type(error).__name__
    else:
        raise AssertionError("thread creation unexpectedly succeeded")

    print("negative-probe", len(EXCLUDED), rendered)
    return 0


if __name__ == "__main__":
    sys.exit(main())
