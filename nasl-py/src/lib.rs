use nasl_cst::{
    apply_edits, parse,
    queries::*,
    Edit,
};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::collections::{HashMap, HashSet, VecDeque};
use walkdir::WalkDir;

// ============================================================================
// Helpers
// ============================================================================

fn walk_nasl(directory: &str) -> impl Iterator<Item = std::path::PathBuf> {
    WalkDir::new(directory)
        .into_iter()
        .filter_map(|e: Result<walkdir::DirEntry, _>| e.ok())
        .filter(|e| e.path().extension().map_or(false, |x| x == "nasl"))
        .map(|e| e.path().to_path_buf())
}

/// Read file as UTF-8; skip non-UTF-8.
fn read_nasl(path: &std::path::Path) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

fn write_nasl(path: &std::path::Path, content: &str) -> bool {
    std::fs::write(path, content.as_bytes()).is_ok()
}

/// Apply one optional edit and return new source. If no edit, return original.
fn apply_one(source: &str, edit: Option<Edit>) -> String {
    match edit {
        Some(e) => apply_edits(source, vec![e]),
        None => source.to_string(),
    }
}

/// Build a filename → full-path index for every .nasl and .inc file under
/// `search_dir`. If the same filename appears in multiple subdirectories,
/// the first one found wins.
fn build_dep_index(search_dir: &str) -> HashMap<String, String> {
    let mut index = HashMap::new();
    for entry in WalkDir::new(search_dir).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext == "nasl" || ext == "inc" {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                index
                    .entry(name.to_string())
                    .or_insert_with(|| path.display().to_string());
            }
        }
    }
    index
}

/// BFS resolution of all transitive dependencies starting from `source` text.
fn resolve_all_deps_from_source(source: &str, search_dir: &str) -> Vec<String> {
    let index = build_dep_index(search_dir);
    let mut visited: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<String> = VecDeque::new();
    let mut result: Vec<String> = Vec::new();

    // Seed with direct dependencies
    let r = parse(source);
    for dep in get_dependencies(&r.root) {
        if visited.insert(dep.clone()) {
            queue.push_back(dep);
        }
    }

    while let Some(dep_name) = queue.pop_front() {
        if let Some(dep_path) = index.get(&dep_name) {
            result.push(dep_path.clone());
            if let Ok(src) = std::fs::read_to_string(dep_path) {
                let r2 = parse(&src);
                for transitive in get_dependencies(&r2.root) {
                    if visited.insert(transitive.clone()) {
                        queue.push_back(transitive);
                    }
                }
            }
        }
    }
    result
}

// ============================================================================
// NaslFile
// ============================================================================

/// A parsed NASL file. All query/edit operations are done in Rust.
/// The Python layer only sees plain strings, lists, booleans, dicts.
#[pyclass]
pub struct NaslFile {
    original: String,
    current: String,
}

#[pymethods]
impl NaslFile {
    // ── Constructors ─────────────────────────────────────────────────────────

    #[staticmethod]
    fn from_file(path: &str) -> PyResult<Self> {
        let source = std::fs::read_to_string(path)
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;
        Ok(NaslFile { original: source.clone(), current: source })
    }

    #[staticmethod]
    fn from_str(source: &str) -> Self {
        NaslFile { original: source.to_string(), current: source.to_string() }
    }

    // ── I/O ──────────────────────────────────────────────────────────────────

    fn to_str(&self) -> &str { &self.current }
    fn original_str(&self) -> &str { &self.original }
    fn is_modified(&self) -> bool { self.current != self.original }
    fn reset(&mut self) { self.current = self.original.clone(); }

    fn to_file(&self, path: &str) -> PyResult<()> {
        std::fs::write(path, self.current.as_bytes())
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))
    }

    fn parse_errors(&self) -> Vec<String> {
        parse(&self.current).errors
    }

    // ── script_tag ───────────────────────────────────────────────────────────

    fn get_script_tag(&self, tag_name: &str) -> Option<String> {
        let r = parse(&self.current);
        get_script_tag(&r.root, tag_name)
    }

    fn set_script_tag(&mut self, tag_name: &str, new_value: &str) -> bool {
        let r = parse(&self.current);
        let edit = set_script_tag(&r.root, tag_name, new_value);
        if edit.is_some() { self.current = apply_one(&self.current, edit); true } else { false }
    }

    fn has_script_tag(&self, tag_name: &str) -> bool {
        let r = parse(&self.current);
        has_script_tag(&r.root, tag_name)
    }

    /// Returns list of tag name strings.
    fn list_script_tags(&self) -> Vec<String> {
        let r = parse(&self.current);
        list_script_tag_names(&r.root)
    }

    /// Returns dict { name: value } for every script_tag call.
    fn get_all_script_tags<'py>(&self, py: Python<'py>) -> Bound<'py, PyDict> {
        let r = parse(&self.current);
        let d = PyDict::new_bound(py);
        for (k, v) in get_all_script_tags(&r.root) {
            let _ = d.set_item(k, v);
        }
        d
    }

    // ── script_version / script_oid / script_name / script_family / … ────────

    fn get_oid(&self) -> Option<String> {
        let r = parse(&self.current); get_simple_call(&r.root, "script_oid")
    }
    fn set_oid(&mut self, v: &str) -> bool {
        let r = parse(&self.current);
        let e = set_simple_call(&r.root, "script_oid", v);
        if e.is_some() { self.current = apply_one(&self.current, e); true } else { false }
    }

    fn get_version(&self) -> Option<String> {
        let r = parse(&self.current); get_simple_call(&r.root, "script_version")
    }
    fn set_version(&mut self, v: &str) -> bool {
        let r = parse(&self.current);
        let e = set_simple_call(&r.root, "script_version", v);
        if e.is_some() { self.current = apply_one(&self.current, e); true } else { false }
    }

    fn get_name(&self) -> Option<String> {
        let r = parse(&self.current); get_simple_call(&r.root, "script_name")
    }
    fn set_name(&mut self, v: &str) -> bool {
        let r = parse(&self.current);
        let e = set_simple_call(&r.root, "script_name", v);
        if e.is_some() { self.current = apply_one(&self.current, e); true } else { false }
    }

    fn get_family(&self) -> Option<String> {
        let r = parse(&self.current); get_simple_call(&r.root, "script_family")
    }
    fn set_family(&mut self, v: &str) -> bool {
        let r = parse(&self.current);
        let e = set_simple_call(&r.root, "script_family", v);
        if e.is_some() { self.current = apply_one(&self.current, e); true } else { false }
    }

    fn get_copyright(&self) -> Option<String> {
        let r = parse(&self.current); get_simple_call(&r.root, "script_copyright")
    }
    fn set_copyright(&mut self, v: &str) -> bool {
        let r = parse(&self.current);
        let e = set_simple_call(&r.root, "script_copyright", v);
        if e.is_some() { self.current = apply_one(&self.current, e); true } else { false }
    }

    // ── script_category ──────────────────────────────────────────────────────

    fn get_category(&self) -> Option<String> {
        let r = parse(&self.current); get_script_category(&r.root)
    }
    fn set_category(&mut self, v: &str) -> bool {
        let r = parse(&self.current);
        let e = set_script_category(&r.root, v);
        if e.is_some() { self.current = apply_one(&self.current, e); true } else { false }
    }

    // ── script_timeout ───────────────────────────────────────────────────────

    fn get_timeout(&self) -> Option<u32> {
        let r = parse(&self.current); get_script_timeout(&r.root)
    }
    fn set_timeout(&mut self, v: u32) -> bool {
        let r = parse(&self.current);
        let e = set_script_timeout(&r.root, v);
        if e.is_some() { self.current = apply_one(&self.current, e); true } else { false }
    }

    // ── script_cve_id ────────────────────────────────────────────────────────

    fn get_cve_ids(&self) -> Vec<String> {
        let r = parse(&self.current); get_cve_ids(&r.root)
    }
    fn has_cve_id(&self, cve: &str) -> bool {
        let r = parse(&self.current); has_cve_id(&r.root, cve)
    }
    fn add_cve_id(&mut self, cve: &str) -> bool {
        let r = parse(&self.current);
        let e = add_cve_id(&r.root, cve);
        if e.is_some() { self.current = apply_one(&self.current, e); true } else { false }
    }
    fn remove_cve_id(&mut self, cve: &str) -> bool {
        let r = parse(&self.current);
        let e = remove_cve_id(&r.root, cve);
        if e.is_some() { self.current = apply_one(&self.current, e); true } else { false }
    }
    fn set_cve_ids(&mut self, cves: Vec<String>) -> bool {
        let r = parse(&self.current);
        let e = set_cve_ids(&r.root, &cves);
        if e.is_some() { self.current = apply_one(&self.current, e); true } else { false }
    }

    // ── script_bugtraq_id ────────────────────────────────────────────────────

    fn get_bugtraq_ids(&self) -> Vec<String> {
        let r = parse(&self.current); get_bugtraq_ids(&r.root)
    }

    // ── script_xref ──────────────────────────────────────────────────────────

    fn get_xrefs(&self, xref_name: &str) -> Vec<String> {
        let r = parse(&self.current); get_xrefs(&r.root, xref_name)
    }
    /// Returns list of [name, value] pairs.
    fn get_all_xrefs<'py>(&self, py: Python<'py>) -> Bound<'py, PyList> {
        let r = parse(&self.current);
        let pairs = get_all_xrefs(&r.root);
        PyList::new_bound(py, pairs.iter().map(|(n, v)| vec![n.as_str(), v.as_str()]))
    }
    fn has_xref(&self, xref_name: &str, xref_value: &str) -> bool {
        let r = parse(&self.current); has_xref(&r.root, xref_name, xref_value)
    }
    fn add_xref(&mut self, name: &str, value: &str) -> bool {
        let r = parse(&self.current);
        let e = add_xref(&r.root, name, value);
        if e.is_some() { self.current = apply_one(&self.current, e); true } else { false }
    }

    // ── script_dependencies ──────────────────────────────────────────────────

    fn get_dependencies(&self) -> Vec<String> {
        let r = parse(&self.current); get_dependencies(&r.root)
    }
    fn has_dependency(&self, dep: &str) -> bool {
        let r = parse(&self.current); has_dependency(&r.root, dep)
    }
    fn add_dependency(&mut self, dep: &str) -> bool {
        let r = parse(&self.current);
        let e = add_dependency(&r.root, dep);
        if e.is_some() { self.current = apply_one(&self.current, e); true } else { false }
    }
    fn remove_dependency(&mut self, dep: &str) -> bool {
        let r = parse(&self.current);
        let e = remove_dependency(&r.root, dep);
        if e.is_some() { self.current = apply_one(&self.current, e); true } else { false }
    }

    // ── script_mandatory_keys ────────────────────────────────────────────────

    fn get_mandatory_keys(&self) -> Vec<String> {
        let r = parse(&self.current); get_mandatory_keys(&r.root)
    }
    fn get_mandatory_keys_re(&self) -> Option<String> {
        let r = parse(&self.current); get_mandatory_keys_re(&r.root)
    }
    fn add_mandatory_key(&mut self, key: &str) -> bool {
        let r = parse(&self.current);
        let e = add_mandatory_key(&r.root, key);
        if e.is_some() { self.current = apply_one(&self.current, e); true } else { false }
    }

    // ── script_require_keys / ports / udp_ports / exclude_keys ───────────────

    fn get_require_keys(&self) -> Vec<String> {
        let r = parse(&self.current); get_require_keys(&r.root)
    }
    fn get_require_ports(&self) -> Vec<String> {
        let r = parse(&self.current); get_require_ports(&r.root)
    }
    fn get_require_udp_ports(&self) -> Vec<String> {
        let r = parse(&self.current); get_require_udp_ports(&r.root)
    }
    fn get_exclude_keys(&self) -> Vec<String> {
        let r = parse(&self.current); get_exclude_keys(&r.root)
    }
    fn add_exclude_key(&mut self, key: &str) -> bool {
        let r = parse(&self.current);
        let e = add_exclude_key(&r.root, key);
        if e.is_some() { self.current = apply_one(&self.current, e); true } else { false }
    }

    // ── script_add_preference ────────────────────────────────────────────────

    /// Returns list of dicts: [{name, type, value, id}, ...]
    fn get_preferences<'py>(&self, py: Python<'py>) -> Vec<Bound<'py, PyDict>> {
        let r = parse(&self.current);
        get_preferences(&r.root)
            .into_iter()
            .map(|p| {
                let d = PyDict::new_bound(py);
                let _ = d.set_item("name", &p.name);
                let _ = d.set_item("type", &p.type_);
                let _ = d.set_item("value", &p.value);
                let _ = d.set_item("id", p.id);
                d
            })
            .collect()
    }

    fn add_preference(&mut self, name: &str, type_: &str, value: &str, id: u32) -> bool {
        let r = parse(&self.current);
        let e = add_preference(&r.root, name, type_, value, id);
        if e.is_some() { self.current = apply_one(&self.current, e); true } else { false }
    }

    // ── include statements ───────────────────────────────────────────────────

    fn get_includes(&self) -> Vec<String> {
        let r = parse(&self.current); get_includes(&r.root)
    }
    fn has_include(&self, filename: &str) -> bool {
        let r = parse(&self.current); has_include(&r.root, filename)
    }
    fn add_include(&mut self, filename: &str) -> bool {
        let r = parse(&self.current);
        let e = add_include(&r.root, filename);
        if e.is_some() { self.current = apply_one(&self.current, e); true } else { false }
    }
    fn remove_include(&mut self, filename: &str) -> bool {
        let r = parse(&self.current);
        let e = remove_include(&r.root, filename);
        if e.is_some() { self.current = apply_one(&self.current, e); true } else { false }
    }

    // ── Full metadata snapshot ────────────────────────────────────────────────

    /// Returns a flat dict containing every piece of metadata from the file.
    fn get_metadata<'py>(&self, py: Python<'py>) -> Bound<'py, PyDict> {
        let r = parse(&self.current);
        let m = get_metadata(&r.root);
        let d = PyDict::new_bound(py);

        macro_rules! set_opt {
            ($key:expr, $val:expr) => { let _ = d.set_item($key, $val); };
        }

        set_opt!("oid", m.oid.as_deref());
        set_opt!("version", m.version.as_deref());
        set_opt!("name", m.name.as_deref());
        set_opt!("family", m.family.as_deref());
        set_opt!("category", m.category.as_deref());
        set_opt!("copyright", m.copyright.as_deref());
        set_opt!("timeout", m.timeout);

        // script_tags as nested dict
        let tags = PyDict::new_bound(py);
        for (k, v) in &m.script_tags { let _ = tags.set_item(k, v); }
        let _ = d.set_item("script_tags", tags);

        set_opt!("cve_ids", m.cve_ids.clone());
        set_opt!("bugtraq_ids", m.bugtraq_ids.clone());

        // xrefs as list of [name, value] pairs
        let xrefs = PyList::new_bound(
            py,
            m.xrefs.iter().map(|(n, v)| vec![n.as_str(), v.as_str()]),
        );
        let _ = d.set_item("xrefs", xrefs);

        set_opt!("dependencies", m.dependencies.clone());
        set_opt!("mandatory_keys", m.mandatory_keys.clone());
        set_opt!("mandatory_keys_re", m.mandatory_keys_re.as_deref());
        set_opt!("require_keys", m.require_keys.clone());
        set_opt!("require_ports", m.require_ports.clone());
        set_opt!("require_udp_ports", m.require_udp_ports.clone());
        set_opt!("exclude_keys", m.exclude_keys.clone());
        set_opt!("includes", m.includes.clone());

        // preferences as list of dicts
        let prefs: Vec<Bound<PyDict>> = m.preferences.iter().map(|p| {
            let pd = PyDict::new_bound(py);
            let _ = pd.set_item("name", &p.name);
            let _ = pd.set_item("type", &p.type_);
            let _ = pd.set_item("value", &p.value);
            let _ = pd.set_item("id", p.id);
            pd
        }).collect();
        let _ = d.set_item("preferences", PyList::new_bound(py, prefs));

        d
    }

    // ── add_script_tag ───────────────────────────────────────────────────────

    /// Insert `script_tag(name:"<name>", value:"<value>");` before `exit(0)`
    /// in the `if(description){}` block.
    fn add_script_tag(&mut self, name: &str, value: &str) -> bool {
        let r = parse(&self.current);
        let e = add_script_tag(&r.root, name, value);
        if e.is_some() { self.current = apply_one(&self.current, e); true } else { false }
    }

    // ── Holm markers ─────────────────────────────────────────────────────────

    /// Returns a dict `{name: value}` for every `script_tag` whose name starts
    /// with `"holm-"`.
    fn get_holm_tags<'py>(&self, py: Python<'py>) -> Bound<'py, PyDict> {
        let r = parse(&self.current);
        let d = PyDict::new_bound(py);
        for (k, v) in get_holm_tags(&r.root) {
            let _ = d.set_item(k, v);
        }
        d
    }

    /// Returns a list of comment strings that contain `"holm"` (case-insensitive).
    fn get_holm_comments(&self) -> Vec<String> {
        let r = parse(&self.current);
        get_holm_comments(&r.root)
    }

    /// `True` if the file has any holm-prefixed `script_tag` or holm comment.
    fn has_holm_marker(&self) -> bool {
        let r = parse(&self.current);
        has_holm_marker(&r.root)
    }

    // ── Recursive dependency resolution ──────────────────────────────────────

    /// Resolve all transitive dependencies by BFS through `search_dir`.
    /// Returns a list of absolute file paths.
    fn get_all_dependencies(&self, search_dir: &str) -> Vec<String> {
        resolve_all_deps_from_source(&self.current, search_dir)
    }

    // ── Security message blocks + PCI keys ───────────────────────────────────

    /// Returns a list of `{key, value}` dicts for every
    /// `set_kb_item(name:"holm/pci/...", value:<expr>)` inside an if-block
    /// that calls `security_message(...)`.
    fn get_pci_kb_items<'py>(&self, py: Python<'py>) -> Vec<Bound<'py, PyDict>> {
        let r = parse(&self.current);
        get_pci_kb_items(&r.root)
            .into_iter()
            .map(|(k, v)| {
                let d = PyDict::new_bound(py);
                let _ = d.set_item("key", k);
                let _ = d.set_item("value", v);
                d
            })
            .collect()
    }

    /// `True` if any security_message block contains
    /// `set_kb_item(name:"<key>", ...)`.
    fn has_pci_kb_item(&self, key: &str) -> bool {
        let r = parse(&self.current);
        has_pci_kb_item(&r.root, key)
    }

    /// Insert `stmt` before the closing `}` of every security_message if-block.
    /// Returns the number of blocks that were modified.
    fn add_to_security_message_blocks(&mut self, stmt: &str) -> usize {
        let r = parse(&self.current);
        let edits = add_to_security_message_blocks(&r.root, stmt);
        let count = edits.len();
        if count > 0 {
            self.current = apply_edits(&self.current, edits);
        }
        count
    }

    /// Replace the value expression of `set_kb_item(name:"<key>", value:<old>)`
    /// inside any security_message if-block. Returns `True` if updated.
    fn update_pci_kb_item(&mut self, key: &str, value_expr: &str) -> bool {
        let r = parse(&self.current);
        let e = update_pci_kb_item(&r.root, key, value_expr);
        if e.is_some() { self.current = apply_one(&self.current, e); true } else { false }
    }

    // ── Repr ─────────────────────────────────────────────────────────────────

    fn __repr__(&self) -> String {
        format!("NaslFile(modified={}, bytes={})", self.is_modified(), self.current.len())
    }
}

// ============================================================================
// Batch operations  (pure Rust loop over a directory)
// ============================================================================

macro_rules! batch_fn {
    ($name:ident, $fn:expr, $label:expr) => {
        #[pyfunction]
        fn $name(
            directory: &str,
            tag_name: &str,
            new_value: &str,
        ) -> PyResult<(usize, usize, Vec<String>)> {
            let mut total = 0usize;
            let mut edited = 0usize;
            let mut errors: Vec<String> = Vec::new();
            for path in walk_nasl(directory) {
                let source = match read_nasl(&path) { Some(s) => s, None => continue };
                total += 1;
                let r = parse(&source);
                let edit = $fn(&r.root, tag_name, new_value);
                if let Some(e) = edit {
                    let updated = apply_edits(&source, vec![e]);
                    if write_nasl(&path, &updated) { edited += 1; }
                    else { errors.push(format!("write failed: {}", path.display())); }
                }
            }
            Ok((total, edited, errors))
        }
    };
}

batch_fn!(batch_set_script_tag, set_script_tag, "script_tag");
batch_fn!(batch_set_simple_call, set_simple_call, "simple call");

/// Append a CVE to script_cve_id(...) across every file in directory.
#[pyfunction]
fn batch_add_cve_id(
    directory: &str,
    cve: &str,
) -> PyResult<(usize, usize, Vec<String>)> {
    let mut total = 0usize;
    let mut edited = 0usize;
    let mut errors: Vec<String> = Vec::new();
    for path in walk_nasl(directory) {
        let source = match read_nasl(&path) { Some(s) => s, None => continue };
        total += 1;
        let r = parse(&source);
        if let Some(e) = add_cve_id(&r.root, cve) {
            let updated = apply_edits(&source, vec![e]);
            if write_nasl(&path, &updated) { edited += 1; }
            else { errors.push(format!("write failed: {}", path.display())); }
        }
    }
    Ok((total, edited, errors))
}

/// Remove a CVE from script_cve_id(...) across every file in directory.
#[pyfunction]
fn batch_remove_cve_id(
    directory: &str,
    cve: &str,
) -> PyResult<(usize, usize, Vec<String>)> {
    let mut total = 0usize;
    let mut edited = 0usize;
    let mut errors: Vec<String> = Vec::new();
    for path in walk_nasl(directory) {
        let source = match read_nasl(&path) { Some(s) => s, None => continue };
        total += 1;
        let r = parse(&source);
        if let Some(e) = remove_cve_id(&r.root, cve) {
            let updated = apply_edits(&source, vec![e]);
            if write_nasl(&path, &updated) { edited += 1; }
            else { errors.push(format!("write failed: {}", path.display())); }
        }
    }
    Ok((total, edited, errors))
}

// ============================================================================
// Search / find operations  (return matching file paths)
// ============================================================================

#[pyfunction]
fn find_files_with_cve(directory: &str, cve: &str) -> Vec<String> {
    walk_nasl(directory)
        .filter(|p| {
            read_nasl(p)
                .map(|src| has_cve_id(&parse(&src).root, cve))
                .unwrap_or(false)
        })
        .map(|p| p.display().to_string())
        .collect()
}

#[pyfunction]
fn find_files_with_tag(directory: &str, tag_name: &str, tag_value: &str) -> Vec<String> {
    walk_nasl(directory)
        .filter(|p| {
            read_nasl(p)
                .map(|src| {
                    get_script_tag(&parse(&src).root, tag_name)
                        .map_or(false, |v| v == tag_value)
                })
                .unwrap_or(false)
        })
        .map(|p| p.display().to_string())
        .collect()
}

#[pyfunction]
fn find_files_missing_tag(directory: &str, tag_name: &str) -> Vec<String> {
    walk_nasl(directory)
        .filter(|p| {
            read_nasl(p)
                .map(|src| !has_script_tag(&parse(&src).root, tag_name))
                .unwrap_or(false)
        })
        .map(|p| p.display().to_string())
        .collect()
}

#[pyfunction]
fn find_files_in_family(directory: &str, family: &str) -> Vec<String> {
    walk_nasl(directory)
        .filter(|p| {
            read_nasl(p)
                .map(|src| {
                    get_simple_call(&parse(&src).root, "script_family")
                        .map_or(false, |v| v == family)
                })
                .unwrap_or(false)
        })
        .map(|p| p.display().to_string())
        .collect()
}

#[pyfunction]
fn find_files_with_include(directory: &str, include_name: &str) -> Vec<String> {
    walk_nasl(directory)
        .filter(|p| {
            read_nasl(p)
                .map(|src| has_include(&parse(&src).root, include_name))
                .unwrap_or(false)
        })
        .map(|p| p.display().to_string())
        .collect()
}

#[pyfunction]
fn find_files_with_dependency(directory: &str, dep: &str) -> Vec<String> {
    walk_nasl(directory)
        .filter(|p| {
            read_nasl(p)
                .map(|src| has_dependency(&parse(&src).root, dep))
                .unwrap_or(false)
        })
        .map(|p| p.display().to_string())
        .collect()
}

// ============================================================================
// Statistics
// ============================================================================

#[pyfunction]
fn family_stats<'py>(py: Python<'py>, directory: &str) -> Bound<'py, PyDict> {
    let d = PyDict::new_bound(py);
    for path in walk_nasl(directory) {
        if let Some(src) = read_nasl(&path) {
            if let Some(family) = get_simple_call(&parse(&src).root, "script_family") {
                let count: usize = d.get_item(&family)
                    .ok().flatten()
                    .and_then(|v| v.extract().ok())
                    .unwrap_or(0);
                let _ = d.set_item(&family, count + 1);
            }
        }
    }
    d
}

#[pyfunction]
fn category_stats<'py>(py: Python<'py>, directory: &str) -> Bound<'py, PyDict> {
    let d = PyDict::new_bound(py);
    for path in walk_nasl(directory) {
        if let Some(src) = read_nasl(&path) {
            if let Some(cat) = get_script_category(&parse(&src).root) {
                let count: usize = d.get_item(&cat)
                    .ok().flatten()
                    .and_then(|v| v.extract().ok())
                    .unwrap_or(0);
                let _ = d.set_item(&cat, count + 1);
            }
        }
    }
    d
}

/// Find all .nasl files under `directory` that have any holm marker.
#[pyfunction]
fn find_files_with_holm_marker(directory: &str) -> Vec<String> {
    walk_nasl(directory)
        .filter(|p| {
            read_nasl(p)
                .map(|src| has_holm_marker(&parse(&src).root))
                .unwrap_or(false)
        })
        .map(|p| p.display().to_string())
        .collect()
}

/// Find all .nasl files under `directory` whose security_message blocks
/// contain `set_kb_item(name:"<key>", ...)`.
#[pyfunction]
fn find_files_with_pci_key(directory: &str, key: &str) -> Vec<String> {
    walk_nasl(directory)
        .filter(|p| {
            read_nasl(p)
                .map(|src| has_pci_kb_item(&parse(&src).root, key))
                .unwrap_or(false)
        })
        .map(|p| p.display().to_string())
        .collect()
}

/// Resolve all transitive dependencies of the file at `file_path` by walking
/// `search_dir`. Returns a list of absolute paths (BFS order).
#[pyfunction]
fn resolve_dependencies(file_path: &str, search_dir: &str) -> Vec<String> {
    match std::fs::read_to_string(file_path) {
        Ok(src) => resolve_all_deps_from_source(&src, search_dir),
        Err(_) => Vec::new(),
    }
}

/// Count occurrences of each value for a given script_tag name.
#[pyfunction]
fn tag_value_stats<'py>(py: Python<'py>, directory: &str, tag_name: &str) -> Bound<'py, PyDict> {
    let d = PyDict::new_bound(py);
    for path in walk_nasl(directory) {
        if let Some(src) = read_nasl(&path) {
            if let Some(val) = get_script_tag(&parse(&src).root, tag_name) {
                let count: usize = d.get_item(&val)
                    .ok().flatten()
                    .and_then(|v| v.extract().ok())
                    .unwrap_or(0);
                let _ = d.set_item(&val, count + 1);
            }
        }
    }
    d
}

// ============================================================================
// Module
// ============================================================================

#[pymodule]
fn nasl_py(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<NaslFile>()?;

    // Batch edits
    m.add_function(wrap_pyfunction!(batch_set_script_tag, m)?)?;
    m.add_function(wrap_pyfunction!(batch_set_simple_call, m)?)?;
    m.add_function(wrap_pyfunction!(batch_add_cve_id, m)?)?;
    m.add_function(wrap_pyfunction!(batch_remove_cve_id, m)?)?;

    // Search
    m.add_function(wrap_pyfunction!(find_files_with_cve, m)?)?;
    m.add_function(wrap_pyfunction!(find_files_with_tag, m)?)?;
    m.add_function(wrap_pyfunction!(find_files_missing_tag, m)?)?;
    m.add_function(wrap_pyfunction!(find_files_in_family, m)?)?;
    m.add_function(wrap_pyfunction!(find_files_with_include, m)?)?;
    m.add_function(wrap_pyfunction!(find_files_with_dependency, m)?)?;
    m.add_function(wrap_pyfunction!(find_files_with_holm_marker, m)?)?;
    m.add_function(wrap_pyfunction!(find_files_with_pci_key, m)?)?;

    // Dependency resolution
    m.add_function(wrap_pyfunction!(resolve_dependencies, m)?)?;

    // Stats
    m.add_function(wrap_pyfunction!(family_stats, m)?)?;
    m.add_function(wrap_pyfunction!(category_stats, m)?)?;
    m.add_function(wrap_pyfunction!(tag_value_stats, m)?)?;

    Ok(())
}
