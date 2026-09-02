"""Import and exercise the accepted pure-Python standard-library profile."""

import sys

REQUIRED = (
    "argparse",
    "collections",
    "contextlib",
    "dataclasses",
    "decimal",
    "enum",
    "functools",
    "importlib",
    "io",
    "json",
    "pathlib",
    "random",
    "re",
    "statistics",
    "tempfile",
    "textwrap",
    "time",
    "traceback",
    "typing",
    "xml",
    "cProfile",
    "plistlib",
)


def main() -> int:
    for name in REQUIRED:
        __import__(name)

    import dataclasses
    import decimal
    import json
    import re
    import statistics
    import textwrap

    @dataclasses.dataclass
    class Point:
        x: int
        y: int

    assert dataclasses.asdict(Point(1, 2)) == {"x": 1, "y": 2}
    assert json.loads(json.dumps({"k": [1, 2.5, None]})) == {"k": [1, 2.5, None]}
    assert re.findall(r"\d+", "a1b22c333") == ["1", "22", "333"]
    assert decimal.Decimal("0.1") + decimal.Decimal("0.2") == decimal.Decimal("0.3")
    assert statistics.median([3, 1, 2]) == 2
    assert textwrap.shorten("alpha beta gamma", width=11) == "alpha [...]"

    # The vendored accelerators must be the implementations actually in use.
    import _decimal

    assert decimal.Decimal is _decimal.Decimal

    import xml.etree.ElementTree as elementtree

    root = elementtree.fromstring("<a><b k='v'>text</b></a>")
    assert root[0].tag == "b" and root[0].attrib == {"k": "v"}
    assert root[0].text == "text"

    import cProfile

    profiler = cProfile.Profile()
    profiler.enable()
    sum(range(100))
    profiler.disable()

    print(
        "stdlib-probe", len(REQUIRED), sys.flags.no_user_site, sys.dont_write_bytecode
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
