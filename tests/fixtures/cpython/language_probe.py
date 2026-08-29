"""Assert upstream CPython language semantics on TROE."""

import gc
import sys
import traceback
import weakref


class Cycle:
    def __init__(self) -> None:
        self.self_reference = self


def generate():
    yield 1
    yield 2


async def coroutine():
    return 3


def main() -> int:
    text = "café中"
    assert len(text) == 5, text
    assert text.encode("utf-8") == b"caf\xc3\xa9\xe4\xb8\xad"
    assert text.upper() == "CAFÉ中"

    assert 2**70 == 1180591620717411303424
    assert round(0.1 + 0.2, 2) == 0.3
    assert list(generate()) == [1, 2]
    pending = coroutine()
    assert pending.__class__.__name__ == "coroutine"
    pending.close()

    reference = weakref.ref(Cycle())
    assert reference() is not None
    gc.collect()
    assert reference() is None

    cycle = Cycle()
    del cycle
    assert gc.collect() >= 1

    try:
        raise ValueError("language-probe-failure")
    except ValueError:
        rendered = traceback.format_exc()
    assert "ValueError: language-probe-failure" in rendered, rendered
    assert "language_probe.py" in rendered, rendered

    try:
        {}["absent"]
    except KeyError as error:
        assert error.args == ("absent",), error.args

    print("language-probe", sys.platform, ".".join(map(str, sys.version_info[:3])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
