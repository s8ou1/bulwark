"""Environment self-check: `python3 tools/doctor.py` (also run by `make test-py`)."""
import sys

problems = []
if sys.version_info < (3, 10):
    problems.append(
        f"Python {sys.version.split()[0]} is too old (need 3.10+). macOS ships 3.9.\n"
        "   Fix:  brew install python@3.12   then use  python3.12 -m venv .venv && source .venv/bin/activate"
    )
try:
    import pydantic  # noqa: F401
    if int(pydantic.VERSION.split(".")[0]) < 2:
        problems.append(f"pydantic {pydantic.VERSION} is too old (need v2).  Fix: pip install -U 'pydantic>=2.5'")
except ImportError:
    problems.append("pydantic is not installed.  Fix:  pip install -r requirements.txt")

if problems:
    print("ENVIRONMENT PROBLEMS:\n")
    for p in problems:
        print(" -", p, "\n")
    sys.exit(1)
print(f"environment OK (python {sys.version.split()[0]}, pydantic {pydantic.VERSION})")
