# nasl-tools

Lossless NASL parser and programmatic editor for large NVT plugin repositories.

Built on [Rowan](https://github.com/rust-analyzer/rowan) (the same CST library used by rust-analyzer). Every whitespace character, comment, and newline is preserved in the tree, making round-trip editing guaranteed lossless — `parse(source).to_string() == source` for all 207 k+ NVT files.

---

## Contents

- [Architecture](#architecture)
- [Install](#install)
- [Python API — NaslFile](#python-api--naslfile)
  - [Constructors & I/O](#constructors--io)
  - [script\_tag](#script_tag)
  - [Core metadata](#core-metadata)
  - [script\_cve\_id](#script_cve_id)
  - [script\_xref](#script_xref)
  - [script\_dependencies](#script_dependencies)
  - [script\_mandatory\_keys / require\_keys / ports](#script_mandatory_keys--require_keys--ports)
  - [script\_add\_preference](#script_add_preference)
  - [include statements](#include-statements)
  - [Full metadata snapshot](#full-metadata-snapshot)
  - [Holm modification markers](#holm-modification-markers)
  - [Recursive dependency resolution](#recursive-dependency-resolution)
  - [Security message blocks & PCI KB items](#security-message-blocks--pci-kb-items)
- [Python API — Module-level functions](#python-api--module-level-functions)
  - [Batch edits](#batch-edits)
  - [Search / find](#search--find)
  - [Statistics](#statistics)
  - [Dependency resolution](#dependency-resolution)
- [Rust API (nasl-cst)](#rust-api-nasl-cst)
- [Design notes](#design-notes)

---

## Architecture

```
nasl-tools/
├── nasl-cst/          Rust library — lexer, parser, CST queries, edit primitives
│   └── src/
│       ├── lexer.rs       Full-fidelity byte-level lexer (every byte is a token)
│       ├── parser.rs      Recursive-descent parser → Rowan green tree
│       ├── syntax_kind.rs SyntaxKind enum (~100 variants) + NaslLanguage trait
│       ├── queries.rs     All structural query/edit helpers (pub API)
│       └── lib.rs         Edit struct, apply_edits, find_nodes helpers
│
└── nasl-py/           Python extension built with PyO3 + maturin
    └── src/lib.rs     NaslFile class + module-level pyfunctions
```

**Key principle — CST not AST.** A standard AST discards whitespace and comments, making lossless round-trip impossible. The Rowan CST stores every token (including `WHITESPACE`, `NEWLINE`, `COMMENT`) as leaf nodes. `node.to_string()` always reconstructs the exact original source.

**Edit model.** All mutations produce an `Edit { range: TextRange, replacement: String }`. Edits are collected, sorted descending by byte offset, then applied via `String::replace_range` so earlier offsets stay valid. Only the targeted bytes change; everything else is untouched.

---

## Install

Download the pre-built wheel for your platform from the
[latest release](https://github.com/mikekei/nasl-tools/releases/latest) and install it:

```bash
pip install https://github.com/mikekei/nasl-tools/releases/latest/download/nasl_py-0.1.0-cp312-cp312-manylinux_2_34_x86_64.whl
```

Wheels are available for:

| Platform | File suffix |
|---|---|
| Linux x86\_64 | `manylinux_2_34_x86_64` |
| Linux aarch64 | `manylinux_2_34_aarch64` |
| macOS x86\_64 | `macosx_..._x86_64` |
| macOS arm64 | `macosx_..._arm64` |
| Windows x86\_64 | `win_amd64` |

Pick the file that matches your OS and Python version from the
[releases page](https://github.com/mikekei/nasl-tools/releases).

### Build from source

Requires Rust (stable), Python 3.8+, and [maturin](https://github.com/PyO3/maturin).

```bash
git clone https://github.com/mikekei/nasl-tools.git
cd nasl-tools/nasl-py
maturin build --release
pip install ../target/wheels/nasl_py-*.whl
```

---

## Python API — NaslFile

```python
import nasl_py
```

`NaslFile` holds the source text of one `.nasl` file. Every query reads from `current` (the possibly-modified source) and every setter produces a new `current`. The original is always accessible via `original_str()`.

### Constructors & I/O

```python
# Load from disk
f = nasl_py.NaslFile.from_file("/path/to/plugin.nasl")

# Load from a string
f = nasl_py.NaslFile.from_str(source_string)

# Read current (possibly modified) source
f.to_str() -> str

# Read original unmodified source
f.original_str() -> str

# True if the source has been changed
f.is_modified() -> bool

# Undo all edits, restore to original
f.reset()

# Write current source to disk
f.to_file("/path/to/plugin.nasl")   # raises IOError on failure

# Any parse errors encountered (description block queries still work)
f.parse_errors() -> list[str]

repr(f)  # → "NaslFile(modified=True, bytes=4321)"
```

---

### script\_tag

`script_tag(name:"<key>", value:"<val>");`

```python
# Read
f.get_script_tag("cvss_base")           # → "7.5"  or  None
f.has_script_tag("cvss_base")           # → True / False
f.list_script_tags()                    # → ["cvss_base", "cvss_base_vector", ...]
f.get_all_script_tags()                 # → {"cvss_base": "7.5", "summary": "...", ...}

# Write — mutates f.current, returns True on success
f.set_script_tag("cvss_base", "9.8")   # → True / False

# Insert a new tag before exit(0) in the if(description){} block
f.add_script_tag("holm-epssv1", "0.00115")   # → True / False
```

`add_script_tag` automatically detects the indentation used by the surrounding block and inserts with matching whitespace. Calling it multiple times appends multiple tags (each before `exit(0)`).

---

### Core metadata

```python
# OID  →  script_oid("1.3.6.1.4.1.25623.1.0.XXXXX")
f.get_oid()               # → str | None
f.set_oid("1.3...")       # → bool

# Version  →  script_version("2025-01-01T00:00:00+0000")
f.get_version()           # → str | None
f.set_version("2025-04-08T12:00:00+0000")

# Name  →  script_name("My Plugin Name")
f.get_name()
f.set_name("New Name")

# Family  →  script_family("Web application abuses")
f.get_family()
f.set_family("General")

# Copyright  →  script_copyright("(C) 2025 Example Corp")
f.get_copyright()
f.set_copyright("(C) 2025 Holm Security AB")

# Category  →  script_category(ACT_GATHER_INFO)   [identifier, not a string]
f.get_category()          # → "ACT_GATHER_INFO" | None
f.set_category("ACT_ATTACK")

# Timeout  →  script_timeout(30)
f.get_timeout()           # → int | None
f.set_timeout(60)
```

---

### script\_cve\_id

`script_cve_id("CVE-2023-1234", "CVE-2023-5678");`

```python
f.get_cve_ids()                         # → ["CVE-2023-1234", ...]
f.has_cve_id("CVE-2023-1234")           # → bool  (case-insensitive)
f.add_cve_id("CVE-2024-9999")           # → bool
f.remove_cve_id("CVE-2023-1234")        # → bool  (case-insensitive)
f.set_cve_ids(["CVE-2024-0001", "CVE-2024-0002"])   # replace entire list → bool
f.get_bugtraq_ids()                     # → list[str]
```

---

### script\_xref

`script_xref(name:"URL", value:"https://...");`

```python
f.get_all_xrefs()                       # → [["URL", "https://..."], ...]
f.get_xrefs("URL")                      # → ["https://example.com", ...]
f.has_xref("URL", "https://example.com")   # → bool
f.add_xref("URL", "https://new.example.com")   # → bool
```

---

### script\_dependencies

`script_dependencies("apt.nasl", "smb_reg_service.nasl");`

```python
f.get_dependencies()                    # → ["apt.nasl", "smb_reg_service.nasl"]
f.has_dependency("apt.nasl")            # → bool
f.add_dependency("new_dep.nasl")        # → bool
f.remove_dependency("apt.nasl")         # → bool
```

---

### script\_mandatory\_keys / require\_keys / ports

```python
# script_mandatory_keys("ssh/login/suse_sles", re:"ssh/login/release=(SLES.*)")
f.get_mandatory_keys()          # → ["ssh/login/suse_sles"]
f.get_mandatory_keys_re()       # → "ssh/login/release=(SLES.*)"  or  None
f.add_mandatory_key("new/key")  # → bool

# script_require_keys("SMB/WindowsVersion")
f.get_require_keys()            # → list[str]

# script_require_ports(139, 445, "Services/www")
f.get_require_ports()           # → list[str]   (port numbers become strings)
f.get_require_udp_ports()       # → list[str]

# script_exclude_keys("Settings/disable_cgi_scanning")
f.get_exclude_keys()            # → list[str]
f.add_exclude_key("some/key")   # → bool
```

---

### script\_add\_preference

`script_add_preference(name:"Username", type:"entry", value:"admin", id:1);`

```python
f.get_preferences()
# → [{"name": "Username", "type": "entry", "value": "admin", "id": 1}, ...]

f.add_preference("Timeout", "entry", "30", id=2)   # → bool
```

---

### include statements

`include("http_func.inc");`

```python
f.get_includes()                        # → ["http_func.inc", "cpe.inc", ...]
f.has_include("http_func.inc")          # → bool
f.add_include("new_lib.inc")            # → bool  (appended after last include)
f.remove_include("old_lib.inc")         # → bool
```

---

### Full metadata snapshot

Returns everything in one call.

```python
m = f.get_metadata()
# m is a dict with keys:
#   oid, version, name, family, category, copyright, timeout
#   script_tags       → {name: value, ...}
#   cve_ids           → [str, ...]
#   bugtraq_ids       → [str, ...]
#   xrefs             → [[name, value], ...]
#   dependencies      → [str, ...]
#   mandatory_keys    → [str, ...]
#   mandatory_keys_re → str | None
#   require_keys      → [str, ...]
#   require_ports     → [str, ...]
#   require_udp_ports → [str, ...]
#   exclude_keys      → [str, ...]
#   includes          → [str, ...]
#   preferences       → [{name, type, value, id}, ...]
```

---

### Holm modification markers

These detect files that have been modified by Holm Security automation scripts.

**Holm tags** are `script_tag` calls whose `name` starts with `"holm-"`:
```
script_tag(name:"holm-epssv1", value:"0.06041");
script_tag(name:"holm-ai-summary", value:"...");
```

**Holm comments** are any comment token containing `"holm"` (case-insensitive):
```
# Added by Holm Security automated cvss modification script
# Modified by Holm Security AB 2025-04-22
```

```python
f.has_holm_marker()         # → bool  (True if any holm tag OR holm comment)
f.get_holm_tags()           # → {"holm-epssv1": "0.06041", ...}
f.get_holm_comments()       # → ["# Added by Holm Security ...", ...]
```

---

### Recursive dependency resolution

Follows `script_dependencies(...)` chains transitively via BFS through a plugin directory. Works with both `.nasl` and `.inc` dependencies. If the same filename exists in multiple subdirectories, the first path found wins.

```python
# From a NaslFile object (uses its current source as the starting point)
paths = f.get_all_dependencies("/path/to/NVT-plugins")
# → ["/path/to/NVT-plugins/apt.nasl",
#    "/path/to/NVT-plugins/toolset/smb_reg.nasl", ...]

# As a standalone function (reads the file from disk)
paths = nasl_py.resolve_dependencies(
    "/path/to/plugin.nasl",
    "/path/to/NVT-plugins"
)
```

Both return a flat list of absolute paths in BFS discovery order. Files not found in `search_dir` are silently skipped (e.g. `.inc` files outside the indexed directory).

---

### Security message blocks & PCI KB items

Holm Security PCI compliance checks insert `set_kb_item` calls inside
`if`-blocks whose condition calls `security_message(...)`:

```nasl
if(security_message(port:port, data:report)) {
  set_kb_item(name:"holm/pci/web_servers", value:get_script_oid());
  set_kb_item(name:"holm/pci/xss",         value:get_script_oid());
}
```

The `value` side is a raw NASL expression (usually a function call), not a string literal.

```python
# Query
f.get_pci_kb_items()
# → [{"key": "holm/pci/web_servers", "value": "get_script_oid()"}, ...]

f.has_pci_kb_item("holm/pci/xss")          # → bool

# Insert a new set_kb_item into every security_message block
count = f.add_to_security_message_blocks(
    'set_kb_item(name:"holm/pci/sqli", value:get_script_oid());'
)
# count = number of blocks that were modified

# Replace the value expression of an existing key (first match)
f.update_pci_kb_item("holm/pci/xss", "TRUE")   # → bool
```

`add_to_security_message_blocks` detects indentation from existing statements in the block and inserts with matching whitespace.

---

## Python API — Module-level functions

### Batch edits

All batch functions walk every `.nasl` file under `directory` (recursive) and return `(total_files, edited_files, errors)`.

```python
# Set script_tag value across all files
total, edited, errors = nasl_py.batch_set_script_tag(
    "/path/to/NVT-plugins", "solution_type", "WillNotFix"
)

# Set any simple single-arg call
total, edited, errors = nasl_py.batch_set_simple_call(
    "/path/to/NVT-plugins", "script_family", "Web application abuses"
)

# CVE list operations
total, edited, errors = nasl_py.batch_add_cve_id("/path/to/NVT-plugins", "CVE-2024-9999")
total, edited, errors = nasl_py.batch_remove_cve_id("/path/to/NVT-plugins", "CVE-2023-1234")
```

---

### Search / find

All search functions walk `directory` recursively and return a list of absolute `.nasl` file paths.

```python
# Files containing a specific CVE
nasl_py.find_files_with_cve("/path/to/NVT-plugins", "CVE-2023-44487")

# Files where a script_tag has a specific value
nasl_py.find_files_with_tag("/path/to/NVT-plugins", "solution_type", "WillNotFix")

# Files missing a script_tag entirely
nasl_py.find_files_missing_tag("/path/to/NVT-plugins", "epss_score")

# Files in a specific family
nasl_py.find_files_in_family("/path/to/NVT-plugins", "Web application abuses")

# Files with a specific include
nasl_py.find_files_with_include("/path/to/NVT-plugins", "http_func.inc")

# Files with a specific direct dependency
nasl_py.find_files_with_dependency("/path/to/NVT-plugins", "gb_nmap_installed_lin.nasl")

# Files with any Holm modification marker
nasl_py.find_files_with_holm_marker("/path/to/NVT-plugins")

# Files whose security_message blocks contain a specific PCI key
nasl_py.find_files_with_pci_key("/path/to/NVT-plugins", "holm/pci/xss")
```

---

### Statistics

All stats functions return a `dict` of `{value: count}` across every `.nasl` file.

```python
nasl_py.family_stats("/path/to/NVT-plugins")
# → {"Web application abuses": 12841, "General": 4302, ...}

nasl_py.category_stats("/path/to/NVT-plugins")
# → {"ACT_GATHER_INFO": 98344, "ACT_ATTACK": 11203, ...}

nasl_py.tag_value_stats("/path/to/NVT-plugins", "solution_type")
# → {"VendorFix": 154200, "WillNotFix": 8400, "NoneAvailable": 1200, ...}
```

---

### Dependency resolution

```python
# Standalone — reads start file from disk, indexes search_dir
paths = nasl_py.resolve_dependencies(
    "/path/to/NVT-plugins/2023/roundcube/plugin.nasl",
    "/path/to/NVT-plugins"
)
# Returns all transitive dependencies as absolute paths (BFS order)
```

---

## Rust API (nasl-cst)

For users who want to extend the parser or embed it in other Rust tools.

```rust
use nasl_cst::{parse, apply_edits, Edit};
use nasl_cst::queries::*;

let source = std::fs::read_to_string("plugin.nasl").unwrap();
let result = parse(&source);            // ParseResult { root: SyntaxNode, errors: Vec<String> }

// Lossless: always true
assert_eq!(result.root.to_string(), source);

// Query
let oid  = get_simple_call(&result.root, "script_oid");
let tags = get_all_script_tags(&result.root);
let deps = get_dependencies(&result.root);

// Edit — returns Option<Edit> (None if the target wasn't found)
let edit = set_script_tag(&result.root, "cvss_base", "9.8");
let new_source = apply_edits(&source, vec![edit.unwrap()]);

// Multiple non-overlapping edits applied in one pass
let edits: Vec<Edit> = add_to_security_message_blocks(
    &result.root,
    r#"set_kb_item(name:"holm/pci/sqli", value:get_script_oid());"#,
);
let new_source = apply_edits(&source, edits);
```

All `queries::*` functions are pure: they take `&SyntaxNode` and return plain values or `Edit` structs. No mutable state, no allocations beyond the returned values.

---

## Design notes

**No regex anywhere.** Every operation — search, extraction, insertion — is driven by `SyntaxKind` matching and token traversal on the Rowan CST. String operations (`starts_with`, `contains`) are applied only *after* a token has already been identified by its kind, never for initial parsing or structure discovery.

**Named-arg disambiguation.** NASL uses `name:"value"` syntax for named function arguments. The lexer/parser identifies these by the `IDENT COLON` two-token lookahead pattern, producing `NAMED_ARG` nodes distinct from positional `ARG` nodes.

**NASL operators.** The lexer handles NASL-specific operators (`><`, `>!<`, `=~`, `!~`) with multi-character lookahead so they tokenise correctly without ambiguity.

**Windows registry strings.** Some NVT files contain strings ending in `\"` (backslash-quote), which the lexer treats as an escaped quote. This causes parse errors in the code body but does not affect description-block queries or round-trip correctness, since all tokens are stored in the CST regardless.

**Round-trip verified.** 207,577 / 207,577 NVT files produce zero diff after `parse → to_string` (release mode, ~33 s).
