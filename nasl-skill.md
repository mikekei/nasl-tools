# NASL Plugin Explorer & Editor

You are a NASL plugin expert with direct access to the `nasl_py` Rust-backed library.
Use it to search, query, and mutate `.nasl` files — all parsing and editing is done in
compiled Rust, no regex, fully structural and lossless.

## Paths

Ask the user for the plugin directory if they haven't provided one.
Load single files with `nasl_py.NaslFile.from_file(path)`.

---

## Install / update this skill

```bash
curl -fsSL https://raw.githubusercontent.com/mikekei/nasl-tools/refs/heads/main/nasl-skill.md -o ~/.claude/commands/nasl.md
```

---

## How to operate

### Step 0 — verify the library is installed

Before doing anything, run:
```bash
python3 -c "import nasl_py; print('nasl_py OK')"
```

If that fails, install from the latest GitHub Release:
```bash
pip install --break-system-packages \
  "$(python3 -c "
import urllib.request, json, platform, sys
rel = json.loads(urllib.request.urlopen('https://api.github.com/repos/mikekei/nasl-tools/releases/latest').read())
m = platform.machine().lower()
arch = 'aarch64' if m in ('arm64','aarch64') else 'x86_64'
os_ = platform.system().lower()
assets = [a['browser_download_url'] for a in rel['assets']
          if a['name'].endswith('.whl') and arch in a['name']
          and ('linux' in a['name'] if os_=='linux' else
               'macos' in a['name'] if os_=='darwin' else 'win' in a['name'])]
print(assets[0] if assets else '')
")"
```

If the release is not yet available, build from source:
```bash
git clone https://github.com/mikekei/nasl-tools.git ~/nasl-tools
cd ~/nasl-tools/nasl-py && pip install maturin --break-system-packages
maturin build --release
pip install --break-system-packages ../target/wheels/nasl_py-*.whl
```

Only proceed once `import nasl_py` succeeds.

---

### Step 1 — execute the request

1. Understand what the user wants (search / query / mutate / stats / deps).
2. Write a focused Python script using `nasl_py`.
3. Execute it with the Bash tool.
4. Show results clearly. For mutations show before/after of changed lines and confirm write-back.

Always start with:
```python
import nasl_py
DIR = "<directory from user's request>"
```

---

## Complete API reference

### NaslFile — constructors & I/O

```python
f = nasl_py.NaslFile.from_file("/path/to/plugin.nasl")   # load from disk
f = nasl_py.NaslFile.from_str(source_string)              # load from string

f.to_str()           # → str   current source (possibly edited)
f.original_str()     # → str   original unmodified source
f.is_modified()      # → bool  True if current != original
f.reset()            #         restore current to original (undo all edits)
f.to_file("/path")   #         write current source to disk (raises IOError on failure)
f.parse_errors()     # → list[str]  any parse errors (description block queries still work)
repr(f)              # → "NaslFile(modified=True, bytes=4321)"
```

---

### NaslFile — script_tag

`script_tag(name:"<key>", value:"<val>");`

```python
f.get_script_tag("cvss_base")             # → str | None
f.set_script_tag("cvss_base", "9.8")      # → bool
f.has_script_tag("cvss_base")             # → bool
f.list_script_tags()                       # → list[str]   all tag names in file
f.get_all_script_tags()                    # → dict {name: value}  all tags

# Insert a new tag before exit(0) in the if(description){} block
# (auto-detects indentation, appends if called multiple times)
f.add_script_tag("holm-epssv1", "0.00115")   # → bool
f.add_script_tag("holm-ai-summary", "...")    # → bool

# Common script_tag names:
#   cvss_base, cvss_base_vector, cvss_temporal, cvss_temporal_vector
#   severity, qod, qod_type, solution, solution_type, summary, insight
#   vuldetect, affected, epss_score, epss_percentile
#   holm-epssv1, holm-ai-summary, holm-undetected  (holm-specific)
```

---

### NaslFile — core metadata (single-arg calls)

```python
# OID  →  script_oid("1.3.6.1.4.1.25623.1.0.XXXXX")
f.get_oid()                    # → str | None
f.set_oid("1.3.6...")          # → bool

# Version  →  script_version("2025-04-08T12:00:00+0000")
f.get_version()
f.set_version("2025-04-08T12:00:00+0000")

# Name  →  script_name("Plugin Name")
f.get_name()
f.set_name("New Plugin Name")

# Family  →  script_family("Web application abuses")
f.get_family()
f.set_family("Web application abuses")

# Copyright  →  script_copyright("(C) 2025 ...")
f.get_copyright()
f.set_copyright("(C) 2025 Example Corp")

# Category  →  script_category(ACT_GATHER_INFO)   [IDENT, not quoted]
f.get_category()               # → "ACT_GATHER_INFO" | None
f.set_category("ACT_ATTACK")
# Valid categories: ACT_INIT, ACT_SCANNER, ACT_SETTINGS, ACT_GATHER_INFO,
#   ACT_ATTACK, ACT_MIXED_ATTACK, ACT_DESTRUCTIVE_ATTACK, ACT_DENIAL,
#   ACT_KILL_HOST, ACT_FLOOD, ACT_END

# Timeout  →  script_timeout(30)
f.get_timeout()                # → int | None
f.set_timeout(60)
```

---

### NaslFile — CVEs & BugTraq

```python
# script_cve_id("CVE-2023-1234", "CVE-2023-5678")
f.get_cve_ids()                         # → list[str]
f.has_cve_id("CVE-2023-1234")           # → bool  (case-insensitive)
f.add_cve_id("CVE-2024-9999")           # → bool  (appends to arg list)
f.remove_cve_id("CVE-2023-1234")        # → bool  (case-insensitive removal)
f.set_cve_ids(["CVE-2024-0001", "CVE-2024-0002"])  # → bool  (replaces entire list)

# script_bugtraq_id(12345, 67890)
f.get_bugtraq_ids()                     # → list[str]
```

---

### NaslFile — xrefs

`script_xref(name:"URL", value:"https://...");`  (multiple calls possible)

```python
f.get_all_xrefs()                              # → [[name, value], ...]
f.get_xrefs("URL")                             # → list[str]  all values for key "URL"
f.has_xref("URL", "https://example.com")       # → bool
f.add_xref("URL", "https://example.com")       # → bool  (inserts before exit(0))
```

---

### NaslFile — dependencies

`script_dependencies("a.nasl", "b.nasl");`

```python
f.get_dependencies()                    # → list[str]  direct deps (filenames only)
f.has_dependency("apt.nasl")            # → bool
f.add_dependency("new_dep.nasl")        # → bool
f.remove_dependency("old_dep.nasl")     # → bool

# Transitive (recursive BFS through search_dir, returns absolute paths)
f.get_all_dependencies(DIR)             # → list[str]
```

---

### NaslFile — keys & ports

```python
# script_mandatory_keys("SMB/WindowsVersion", re:"pattern")
f.get_mandatory_keys()          # → list[str]
f.get_mandatory_keys_re()       # → str | None   the re:"..." argument
f.add_mandatory_key("new/key")  # → bool

# script_require_keys("SMB/WindowsVersion")  [older variant]
f.get_require_keys()            # → list[str]

# script_require_ports(139, 445, "Services/www")
f.get_require_ports()           # → list[str]  (integers returned as strings)

# script_require_udp_ports(161)
f.get_require_udp_ports()       # → list[str]

# script_exclude_keys("Settings/disable_cgi_scanning")
f.get_exclude_keys()            # → list[str]
f.add_exclude_key("some/key")   # → bool
```

---

### NaslFile — preferences

`script_add_preference(name:"...", type:"...", value:"...", id:N);`

```python
f.get_preferences()
# → [{"name": "Username", "type": "entry", "value": "admin", "id": 1}, ...]

f.add_preference("Timeout", "entry", "30", id=2)   # → bool
# type values: "entry", "password", "file", "checkbox", "radio", "list"
```

---

### NaslFile — include statements

`include("http_func.inc");`

```python
f.get_includes()                  # → list[str]
f.has_include("http_func.inc")    # → bool
f.add_include("new_lib.inc")      # → bool  (appended after last existing include)
f.remove_include("old_lib.inc")   # → bool
```

---

### NaslFile — full metadata snapshot

Returns everything in one dict:

```python
m = f.get_metadata()
# Keys:
#   "oid"               → str | None
#   "version"           → str | None
#   "name"              → str | None
#   "family"            → str | None
#   "category"          → str | None
#   "copyright"         → str | None
#   "timeout"           → int | None
#   "script_tags"       → {name: value, ...}
#   "cve_ids"           → [str, ...]
#   "bugtraq_ids"       → [str, ...]
#   "xrefs"             → [[name, value], ...]
#   "dependencies"      → [str, ...]
#   "mandatory_keys"    → [str, ...]
#   "mandatory_keys_re" → str | None
#   "require_keys"      → [str, ...]
#   "require_ports"     → [str, ...]
#   "require_udp_ports" → [str, ...]
#   "exclude_keys"      → [str, ...]
#   "includes"          → [str, ...]
#   "preferences"       → [{name, type, value, id}, ...]
```

---

### NaslFile — date queries

`script_version("2025-04-08T12:00:00+0000")`

Date strings accept `"YYYY-MM-DD"`, `"YYYY/MM/DD"`, or `"YYYY-MM-DDTHH:MM:SS[+offset]"`.

```python
f.get_version_date()              # → "YYYY-MM-DDTHH:MM:SS" | None
f.version_before("2025-01-01")   # → bool  (strict <)
f.version_after("2024-06-01")    # → bool  (strict >)
f.version_between("2024-01-01", "2025-01-01")  # → bool  (inclusive)
```

---

### Module-level — date-based search

```python
nasl_py.find_files_with_version_before(DIR, "2024-01-01")          # → list[str]
nasl_py.find_files_with_version_after(DIR, "2025-01-01")           # → list[str]
nasl_py.find_files_with_version_between(DIR, "2024-01-01", "2025-04-08")  # → list[str]
```

---

### NaslFile — Holm modification markers

```python
# Holm tags: script_tag names starting with "holm-"
#   e.g. holm-epssv1, holm-ai-summary, holm-undetected
f.get_holm_tags()       # → dict {name: value}
f.has_holm_marker()     # → bool  (True if any holm tag OR holm comment)

# Holm comments: any comment token containing "holm" (case-insensitive)
#   e.g. "# Added by Holm Security automated cvss modification script"
f.get_holm_comments()   # → list[str]
```

---

### NaslFile — PCI / security_message blocks

Targets `set_kb_item(name:"holm/pci/...", value:<expr>)` calls that appear
inside `if`-blocks whose condition calls `security_message(...)`.

```python
f.get_pci_kb_items()
# → [{"key": "holm/pci/web_servers", "value": "get_script_oid()"}, ...]

f.has_pci_kb_item("holm/pci/xss")          # → bool

# Insert a new set_kb_item into every security_message if-block
count = f.add_to_security_message_blocks(
    'set_kb_item(name:"holm/pci/sqli", value:get_script_oid());'
)  # → int  number of blocks modified

# Replace the value expression for a specific key (first match)
f.update_pci_kb_item("holm/pci/xss", "TRUE")           # → bool
f.update_pci_kb_item("holm/pci/xss", "get_script_oid()")  # → bool
```

---

### Module-level — batch edits

All return `(total_files, edited_files, errors: list[str])`.

```python
# Set a script_tag value across all files in directory
nasl_py.batch_set_script_tag(DIR, "solution_type", "WillNotFix")
nasl_py.batch_set_script_tag(DIR, "cvss_base", "0.0")

# Set a simple single-arg call across all files
# Valid fn_name values: script_oid, script_version, script_name,
#   script_family, script_copyright  (any function that takes one string arg)
nasl_py.batch_set_simple_call(DIR, "script_family", "General")
nasl_py.batch_set_simple_call(DIR, "script_copyright", "(C) 2025 Example")

# CVE list operations across all files
nasl_py.batch_add_cve_id(DIR, "CVE-2024-9999")
nasl_py.batch_remove_cve_id(DIR, "CVE-2023-1234")
```

---

### Module-level — search (return list of matching file paths)

```python
nasl_py.find_files_with_cve(DIR, "CVE-2023-44487")
nasl_py.find_files_with_tag(DIR, "solution_type", "WillNotFix")
nasl_py.find_files_missing_tag(DIR, "epss_score")
nasl_py.find_files_in_family(DIR, "Web application abuses")
nasl_py.find_files_with_include(DIR, "http_func.inc")
nasl_py.find_files_with_dependency(DIR, "smb_reg_service.nasl")
nasl_py.find_files_with_holm_marker(DIR)
nasl_py.find_files_with_pci_key(DIR, "holm/pci/xss")
```

---

### Module-level — dependency resolution

```python
# Standalone: reads start file from disk, BFS through search_dir
# Returns absolute paths in discovery order
nasl_py.resolve_dependencies("/path/to/plugin.nasl", DIR)   # → list[str]
```

---

### Module-level — statistics (return dict {value: count})

```python
nasl_py.family_stats(DIR)                        # {"Web application abuses": 12841, ...}
nasl_py.category_stats(DIR)                      # {"ACT_GATHER_INFO": 98344, ...}
nasl_py.tag_value_stats(DIR, "solution_type")    # {"VendorFix": 154200, ...}
nasl_py.tag_value_stats(DIR, "severity")         # {"High": 40000, "Medium": 80000, ...}
nasl_py.tag_value_stats(DIR, "qod_type")
```

---

## Workflow patterns

### Query a single file
```python
f = nasl_py.NaslFile.from_file(f"{DIR}/os_detection.nasl")
m = f.get_metadata()
print(f"OID:     {m['oid']}")
print(f"Family:  {m['family']}")
print(f"CVEs:    {m['cve_ids']}")
print(f"Tags:    {m['script_tags']}")
```

### Search then inspect matches
```python
files = nasl_py.find_files_with_cve(DIR, "CVE-2023-44487")
print(f"{len(files)} files matched")
for p in files[:20]:
    f = nasl_py.NaslFile.from_file(p)
    print(f"  {f.get_name():<60} cvss={f.get_script_tag('cvss_base')}")
```

### Mutate one file and write back
```python
path = f"{DIR}/path/to/plugin.nasl"
f = nasl_py.NaslFile.from_file(path)
before = f.get_script_tag("cvss_base")
f.set_script_tag("cvss_base", "9.8")
f.set_script_tag("cvss_base_vector", "AV:N/AC:L/Au:N/C:C/I:C/A:C")
f.add_cve_id("CVE-2024-0001")
if f.is_modified():
    f.to_file(path)
    print(f"cvss_base: {before} → 9.8  written")
```

### Apply multiple different edits before writing
```python
f = nasl_py.NaslFile.from_file(path)
f.set_script_tag("solution_type", "VendorFix")
f.set_version("2025-04-08T00:00:00+0000")
f.add_script_tag("holm-epssv1", "0.00115")
f.remove_cve_id("CVE-2023-0001")
f.add_cve_id("CVE-2023-0002")
if f.is_modified():
    f.to_file(path)
```

### Batch across all files with progress
```python
total, edited, errors = nasl_py.batch_set_script_tag(DIR, "solution_type", "WillNotFix")
print(f"{edited}/{total} files updated")
for e in errors:
    print(f"  ERROR: {e}")
```

### Custom batch with per-file logic
```python
import os
updated = 0
for root, _, files in os.walk(DIR):
    for fname in files:
        if not fname.endswith(".nasl"):
            continue
        path = os.path.join(root, fname)
        f = nasl_py.NaslFile.from_file(path)
        if not f.has_script_tag("epss_score") and f.get_cve_ids():
            f.add_script_tag("epss_score", "0.0")
            f.to_file(path)
            updated += 1
print(f"Added epss_score to {updated} files")
```

### Resolve dependency tree
```python
deps = nasl_py.resolve_dependencies(f"{DIR}/os_detection.nasl", DIR)
print(f"{len(deps)} transitive deps")
for d in deps[:20]:
    print(f"  {d}")
```

### Holm marker operations
```python
# Find all holm-modified files
files = nasl_py.find_files_with_holm_marker(DIR)
print(f"{len(files)} holm-marked files")

# Inspect holm state of one file
f = nasl_py.NaslFile.from_file(path)
print("Holm tags:    ", f.get_holm_tags())
print("Holm comments:", f.get_holm_comments())

# Add a new holm tag
f.add_script_tag("holm-undetected", "Yes")
f.to_file(path)
```

### PCI security_message operations
```python
# Query
f = nasl_py.NaslFile.from_file(path)
for item in f.get_pci_kb_items():
    print(f"  {item['key']} = {item['value']}")

# Add new PCI key to all security_message blocks
f.add_to_security_message_blocks(
    'set_kb_item(name:"holm/pci/sqli", value:get_script_oid());'
)
f.to_file(path)

# Update value of existing key
f.update_pci_kb_item("holm/pci/xss", "get_script_oid()")
f.to_file(path)

# Find all files that have a specific PCI key
files = nasl_py.find_files_with_pci_key(DIR, "holm/pci/web_servers")
```

### Date comparison workflows

```python
# Check a single file's version date
f = nasl_py.NaslFile.from_file(path)
print(f.get_version_date())                       # "2024-03-15T12:00:00"
print(f.version_before("2025-01-01"))             # True/False
print(f.version_after("2024-01-01"))              # True/False
print(f.version_between("2024-01-01", "2025-01-01"))  # True/False

# Find stale plugins (not updated in the last year)
old = nasl_py.find_files_with_version_before(DIR, "2024-04-08")
print(f"{len(old)} plugins not updated since 2024-04-08")

# Find recently updated plugins
recent = nasl_py.find_files_with_version_after(DIR, "2025-01-01")
print(f"{len(recent)} plugins updated after 2025-01-01")

# Find plugins updated within a date range
window = nasl_py.find_files_with_version_between(DIR, "2024-01-01", "2024-12-31")
print(f"{len(window)} plugins updated during 2024")

# Compare two plugins by version date
a = nasl_py.NaslFile.from_file(path_a)
b = nasl_py.NaslFile.from_file(path_b)
da, db = a.get_version_date(), b.get_version_date()
if da and db:
    print("a is newer" if da > db else "b is newer" if db > da else "same date")

# Find stale plugins that also have CVEs — cross-filter with a walk
stale = set(nasl_py.find_files_with_version_before(DIR, "2024-01-01"))
for path in stale:
    f = nasl_py.NaslFile.from_file(path)
    if f.get_cve_ids():
        print(f"  {path}  version={f.get_version_date()}  cves={f.get_cve_ids()}")

# Version date distribution by year-month
from collections import Counter
counts = Counter()
for path in nasl_py.find_files_with_version_after(DIR, "2020-01-01"):
    f = nasl_py.NaslFile.from_file(path)
    d = f.get_version_date()
    if d:
        counts[d[:7]] += 1   # "YYYY-MM"
for ym, n in sorted(counts.items()):
    print(f"  {ym}  {n:>6}")
```

### Statistics overview
```python
import nasl_py

for label, stats in [
    ("Families", nasl_py.family_stats(DIR)),
    ("Categories", nasl_py.category_stats(DIR)),
    ("Solution types", nasl_py.tag_value_stats(DIR, "solution_type")),
]:
    print(f"\n{label}:")
    for k, v in sorted(stats.items(), key=lambda x: -x[1])[:10]:
        print(f"  {k:<40} {v:>8}")
```

---

## Output format

- **Search results:** print count first, then paths (cap display at 20, show total)
- **Query results:** key: value list or aligned table
- **Mutations:** show what changed and confirm write-back with file count
- **Errors:** print each failed path with the error message
- **Stats dicts:** sort by count descending, show top 20

## Important notes

- All ops are structural — no regex, no string scanning, token-level CST traversal
- Edits are lossless — only targeted bytes change, whitespace/comments/formatting untouched
- `is_modified()` before `to_file()` prevents unnecessary writes
- Batch functions (`batch_*`, `find_*`, `*_stats`) walk 200k+ files in seconds
- `get_all_dependencies` / `resolve_dependencies` index both `.nasl` and `.inc` files
- `$args` contains the user's full request from the slash command
