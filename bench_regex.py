"""
Regex-based approach: find script_tag(name:"summary", value:"...") and
append one space before the closing quote. Processes files one at a time.
"""
import re
import sys
import time
from pathlib import Path

# Match script_tag(name:"summary", value:"<content>")
# Using a non-greedy match with DOTALL to handle multiline values.
# Handles escaped quotes inside the string with (?:[^"\\]|\\.)*
PATTERN = re.compile(
    r'(script_tag\s*\(\s*name\s*:\s*"summary"\s*,\s*value\s*:\s*")'
    r'((?:[^"\\]|\\.)*?)'
    r'(")',
    re.DOTALL,
)

def process_file(path: Path) -> bool:
    try:
        content = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return False

    new_content, n = PATTERN.subn(r'\1\2 \3', content)

    if n > 0:
        path.write_text(new_content, encoding="utf-8")
        return True
    return False

def main():
    if len(sys.argv) < 2:
        print("Usage: bench_regex.py <directory>")
        sys.exit(1)
    root = Path(sys.argv[1])

    t0 = time.perf_counter()

    total = 0
    edited = 0
    for path in root.rglob("*.nasl"):
        total += 1
        if process_file(path):
            edited += 1
        if total % 10000 == 0:
            elapsed = time.perf_counter() - t0
            print(f"  ... {total} files scanned, {edited} edited  ({elapsed:.1f}s)")

    elapsed = time.perf_counter() - t0
    print(f"\nDone: {total} files, {edited} edited in {elapsed:.3f}s")

if __name__ == "__main__":
    main()
