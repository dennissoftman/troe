"""Import every shipped top-level module and report the ones that fail."""

import pathlib
import sys


def shipped() -> list[str]:
    root = (
        pathlib.Path(sys.prefix) / f"python{sys.version_info[0]}.{sys.version_info[1]}"
    )
    names = set()
    for entry in root.iterdir():
        if entry.name.startswith(("_", ".")) or entry.name == "site-packages":
            continue
        if entry.is_dir() and (entry / "__init__.py").is_file():
            names.add(entry.name)
        elif entry.suffix == ".py":
            names.add(entry.stem)
    return sorted(names)


def main() -> int:
    names = shipped()
    failures = []
    for name in names:
        try:
            __import__(name)
        except BaseException as error:  # Report, never abort the sweep.
            failures.append(f"{name}:{type(error).__name__}")
    print("profile-probe", len(names), len(failures))
    if failures:
        print("profile-failures", " ".join(failures))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
