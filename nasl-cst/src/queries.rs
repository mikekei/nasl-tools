/// Comprehensive structural queries and edits over the NASL CST.
///
/// Every public function accepts a `&SyntaxNode` (parsed root) and returns
/// plain Rust values or `Edit` structs. No parser state is retained.
use rowan::{TextRange, TextSize};

use crate::{nodes_of_kind, Edit, SyntaxKind, SyntaxNode, SyntaxToken};

// ============================================================================
// Internal low-level helpers
// ============================================================================

/// True if the ARG_LIST's parent contains an IDENT_EXPR with text == `name`.
pub fn parent_fn_is(arg_list: SyntaxNode, name: &str) -> bool {
    let parent = match arg_list.parent() {
        Some(p) => p,
        None => return false,
    };
    parent.children().any(|child| {
        child.kind() == SyntaxKind::IDENT_EXPR
            && child
                .descendants_with_tokens()
                .filter_map(|e| e.into_token())
                // Match both regular identifiers and NASL keyword-calls (e.g. exit → KW_EXIT)
                .any(|t| {
                    matches!(t.kind(), SyntaxKind::IDENT | SyntaxKind::KW_EXIT)
                        && t.text() == name
                })
    })
}

/// All NAMED_ARG children of a node.
pub fn named_arg_children(node: &SyntaxNode) -> Vec<SyntaxNode> {
    node.children()
        .filter(|n| n.kind() == SyntaxKind::NAMED_ARG)
        .collect()
}

/// The identifier text of a NAMED_ARG (the part before the colon).
pub fn na_ident(na: &SyntaxNode) -> Option<String> {
    na.descendants_with_tokens()
        .filter_map(|e| e.into_token())
        .find(|t| t.kind() == SyntaxKind::IDENT)
        .map(|t| t.text().to_string())
}

/// First string token (double or single quoted) anywhere inside `node`.
pub fn find_string_token(node: &SyntaxNode) -> Option<SyntaxToken> {
    node.descendants_with_tokens()
        .filter_map(|e| e.into_token())
        .find(|t| {
            matches!(
                t.kind(),
                SyntaxKind::STRING_DOUBLE | SyntaxKind::STRING_SINGLE
            )
        })
}

/// Strip surrounding quotes from a raw token slice.
pub fn unquote(s: &str) -> String {
    let s = s.trim();
    if s.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"'))
            || (s.starts_with('\'') && s.ends_with('\'')))
    {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

fn quote_char(tok: &SyntaxToken) -> char {
    if tok.kind() == SyntaxKind::STRING_SINGLE { '\'' } else { '"' }
}

/// Find a direct-child token of `node` with `kind`.
fn find_direct_token(node: &SyntaxNode, kind: SyntaxKind) -> Option<SyntaxToken> {
    node.children_with_tokens()
        .filter_map(|e| e.into_token())
        .find(|t| t.kind() == kind)
}

/// Collect all positional ARG values as strings (handles STRING and INT_LIT tokens).
fn positional_arg_values(arg_list: &SyntaxNode) -> Vec<String> {
    arg_list
        .children()
        .filter(|n| n.kind() == SyntaxKind::ARG)
        .filter_map(|arg| {
            arg.descendants_with_tokens()
                .filter_map(|e| e.into_token())
                .find(|t| {
                    matches!(
                        t.kind(),
                        SyntaxKind::STRING_DOUBLE
                            | SyntaxKind::STRING_SINGLE
                            | SyntaxKind::INT_LIT
                            | SyntaxKind::IDENT
                    )
                })
                .map(|t| {
                    if matches!(
                        t.kind(),
                        SyntaxKind::STRING_DOUBLE | SyntaxKind::STRING_SINGLE
                    ) {
                        unquote(t.text())
                    } else {
                        t.text().to_string()
                    }
                })
        })
        .collect()
}

/// Replace the entire content between `(` and `)` of `fn_name`'s arg list.
/// `values` are emitted as double-quoted strings.
fn set_positional_string_args(
    root: &SyntaxNode,
    fn_name: &str,
    values: &[String],
) -> Option<Edit> {
    for arg_list in nodes_of_kind(root, SyntaxKind::ARG_LIST) {
        if !parent_fn_is(arg_list.clone(), fn_name) {
            continue;
        }
        let lparen = find_direct_token(&arg_list, SyntaxKind::L_PAREN)?;
        let rparen = find_direct_token(&arg_list, SyntaxKind::R_PAREN)?;
        let new_content = values
            .iter()
            .map(|v| format!("\"{}\"", v))
            .collect::<Vec<_>>()
            .join(", ");
        return Some(Edit {
            range: TextRange::new(lparen.text_range().end(), rparen.text_range().start()),
            replacement: new_content,
        });
    }
    None
}

/// Add a quoted string arg just before `)` of `fn_name`.
fn add_positional_string_arg(
    root: &SyntaxNode,
    fn_name: &str,
    value: &str,
) -> Option<Edit> {
    for arg_list in nodes_of_kind(root, SyntaxKind::ARG_LIST) {
        if !parent_fn_is(arg_list.clone(), fn_name) {
            continue;
        }
        let rparen = find_direct_token(&arg_list, SyntaxKind::R_PAREN)?;
        let insert_at = rparen.text_range().start();
        let has_args = arg_list.children().any(|n| n.kind() == SyntaxKind::ARG);
        let prefix = if has_args { ", " } else { "" };
        return Some(Edit {
            range: TextRange::new(insert_at, insert_at),
            replacement: format!("{}\"{}\"", prefix, value),
        });
    }
    // No existing call — insert a new statement before exit(0)
    let exit_stmt = find_description_exit(root)?;
    let indent = detect_indent(&exit_stmt);
    let insert_at = exit_stmt.text_range().start();
    Some(Edit {
        range: TextRange::new(insert_at, insert_at),
        replacement: format!("{}(\"{}\")\n{}", fn_name, value, indent),
    })
}

/// Find the exit(0) EXPR_STMT inside the if(description){} block.
fn find_description_exit(root: &SyntaxNode) -> Option<SyntaxNode> {
    for if_stmt in nodes_of_kind(root, SyntaxKind::IF_STMT) {
        let has_description_cond = if_stmt
            .descendants_with_tokens()
            .filter_map(|e| e.into_token())
            .take(20) // only look at condition area tokens
            .any(|t| t.kind() == SyntaxKind::IDENT && t.text() == "description");
        if !has_description_cond {
            continue;
        }
        if let Some(block) = if_stmt.children().find(|n| n.kind() == SyntaxKind::BLOCK) {
            for stmt in block.children().filter(|n| n.kind() == SyntaxKind::EXPR_STMT) {
                let has_exit = stmt
                    .descendants_with_tokens()
                    .filter_map(|e| e.into_token())
                    .any(|t| {
                        t.kind() == SyntaxKind::KW_EXIT
                            || (t.kind() == SyntaxKind::IDENT && t.text() == "exit")
                    });
                if has_exit {
                    return Some(stmt);
                }
            }
        }
    }
    None
}

/// Detect the indentation used for statements in the description block.
fn detect_indent(exit_stmt: &SyntaxNode) -> String {
    let mut saw_newline = false;
    for elem in exit_stmt.children_with_tokens() {
        if let Some(tok) = elem.into_token() {
            match tok.kind() {
                SyntaxKind::NEWLINE => saw_newline = true,
                SyntaxKind::WHITESPACE if saw_newline => return tok.text().to_string(),
                _ => {}
            }
        }
    }
    "  ".to_string()
}

/// Insert `text` just before the exit(0) statement in the description block.
fn insert_before_exit(root: &SyntaxNode, text: &str) -> Option<Edit> {
    let exit_stmt = find_description_exit(root)?;
    let insert_at = exit_stmt.text_range().start();
    Some(Edit {
        range: TextRange::new(insert_at, insert_at),
        replacement: text.to_string(),
    })
}

// ============================================================================
// script_tag(name:"<key>", value:"<val>")
// ============================================================================

/// Returns the `value:"..."` of the first `script_tag(name:"<tag_name>", ...)` call, or `None`.
pub fn get_script_tag(root: &SyntaxNode, tag_name: &str) -> Option<String> {
    for arg_list in nodes_of_kind(root, SyntaxKind::ARG_LIST) {
        if !parent_fn_is(arg_list.clone(), "script_tag") {
            continue;
        }
        let named_args = named_arg_children(&arg_list);
        if !has_named_string_value(&named_args, "name", tag_name) {
            continue;
        }
        if let Some(val) = named_args.iter().find(|na| na_ident(na).as_deref() == Some("value")) {
            if let Some(tok) = find_string_token(val) {
                return Some(unquote(tok.text()));
            }
        }
    }
    None
}

/// Returns an [`Edit`] that replaces the value string of `script_tag(name:"<tag_name>", ...)`.
pub fn set_script_tag(root: &SyntaxNode, tag_name: &str, new_value: &str) -> Option<Edit> {
    for arg_list in nodes_of_kind(root, SyntaxKind::ARG_LIST) {
        if !parent_fn_is(arg_list.clone(), "script_tag") {
            continue;
        }
        let named_args = named_arg_children(&arg_list);
        if !has_named_string_value(&named_args, "name", tag_name) {
            continue;
        }
        if let Some(val) = named_args.iter().find(|na| na_ident(na).as_deref() == Some("value")) {
            if let Some(tok) = find_string_token(val) {
                let q = quote_char(&tok);
                return Some(Edit {
                    range: tok.text_range(),
                    replacement: format!("{}{}{}", q, new_value, q),
                });
            }
        }
    }
    None
}

/// Returns `true` if any `script_tag(name:"<tag_name>", ...)` call exists.
pub fn has_script_tag(root: &SyntaxNode, tag_name: &str) -> bool {
    get_script_tag(root, tag_name).is_some()
}

/// All (name, value) pairs from every script_tag call.
pub fn get_all_script_tags(root: &SyntaxNode) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for arg_list in nodes_of_kind(root, SyntaxKind::ARG_LIST) {
        if !parent_fn_is(arg_list.clone(), "script_tag") {
            continue;
        }
        let named_args = named_arg_children(&arg_list);
        let name = named_args
            .iter()
            .find(|na| na_ident(na).as_deref() == Some("name"))
            .and_then(|na| find_string_token(na))
            .map(|t| unquote(t.text()));
        let value = named_args
            .iter()
            .find(|na| na_ident(na).as_deref() == Some("value"))
            .and_then(|na| find_string_token(na))
            .map(|t| unquote(t.text()));
        if let (Some(n), Some(v)) = (name, value) {
            out.push((n, v));
        }
    }
    out
}

/// List of all distinct script_tag name values.
pub fn list_script_tag_names(root: &SyntaxNode) -> Vec<String> {
    get_all_script_tags(root).into_iter().map(|(n, _)| n).collect()
}

fn has_named_string_value(named_args: &[SyntaxNode], ident: &str, value: &str) -> bool {
    named_args.iter().any(|na| {
        na_ident(na).as_deref() == Some(ident)
            && find_string_token(na)
                .map(|t| unquote(t.text()) == value)
                .unwrap_or(false)
    })
}

// ============================================================================
// Simple single-string-arg calls: script_version, script_oid, script_name …
// ============================================================================

/// Returns the single quoted-string argument of `fn_name("...")`, e.g. `script_oid`, `script_name`.
pub fn get_simple_call(root: &SyntaxNode, fn_name: &str) -> Option<String> {
    for arg_list in nodes_of_kind(root, SyntaxKind::ARG_LIST) {
        if !parent_fn_is(arg_list.clone(), fn_name) {
            continue;
        }
        if let Some(arg) = arg_list.children().find(|n| n.kind() == SyntaxKind::ARG) {
            if let Some(tok) = find_string_token(&arg) {
                return Some(unquote(tok.text()));
            }
        }
    }
    None
}

/// Returns an [`Edit`] replacing the string argument of `fn_name("...")`.
pub fn set_simple_call(root: &SyntaxNode, fn_name: &str, new_value: &str) -> Option<Edit> {
    for arg_list in nodes_of_kind(root, SyntaxKind::ARG_LIST) {
        if !parent_fn_is(arg_list.clone(), fn_name) {
            continue;
        }
        if let Some(arg) = arg_list.children().find(|n| n.kind() == SyntaxKind::ARG) {
            if let Some(tok) = find_string_token(&arg) {
                let q = quote_char(&tok);
                return Some(Edit {
                    range: tok.text_range(),
                    replacement: format!("{}{}{}", q, new_value, q),
                });
            }
        }
    }
    None
}

// ============================================================================
// script_category(ACT_GATHER_INFO)  — IDENT arg, not a string
// ============================================================================

/// Returns the category identifier from `script_category(ACT_GATHER_INFO)` (bare IDENT, not quoted).
pub fn get_script_category(root: &SyntaxNode) -> Option<String> {
    for arg_list in nodes_of_kind(root, SyntaxKind::ARG_LIST) {
        if !parent_fn_is(arg_list.clone(), "script_category") {
            continue;
        }
        if let Some(arg) = arg_list.children().find(|n| n.kind() == SyntaxKind::ARG) {
            return arg
                .descendants_with_tokens()
                .filter_map(|e| e.into_token())
                .find(|t| t.kind() == SyntaxKind::IDENT)
                .map(|t| t.text().to_string());
        }
    }
    None
}

/// Returns an [`Edit`] replacing the category identifier in `script_category(...)`.
pub fn set_script_category(root: &SyntaxNode, category: &str) -> Option<Edit> {
    for arg_list in nodes_of_kind(root, SyntaxKind::ARG_LIST) {
        if !parent_fn_is(arg_list.clone(), "script_category") {
            continue;
        }
        if let Some(arg) = arg_list.children().find(|n| n.kind() == SyntaxKind::ARG) {
            if let Some(tok) = arg
                .descendants_with_tokens()
                .filter_map(|e| e.into_token())
                .find(|t| t.kind() == SyntaxKind::IDENT)
            {
                return Some(Edit {
                    range: tok.text_range(),
                    replacement: category.to_string(),
                });
            }
        }
    }
    None
}

// ============================================================================
// script_timeout(N)  — INT arg
// ============================================================================

/// Returns the integer argument of `script_timeout(N)`.
pub fn get_script_timeout(root: &SyntaxNode) -> Option<u32> {
    for arg_list in nodes_of_kind(root, SyntaxKind::ARG_LIST) {
        if !parent_fn_is(arg_list.clone(), "script_timeout") {
            continue;
        }
        if let Some(arg) = arg_list.children().find(|n| n.kind() == SyntaxKind::ARG) {
            return arg
                .descendants_with_tokens()
                .filter_map(|e| e.into_token())
                .find(|t| t.kind() == SyntaxKind::INT_LIT)
                .and_then(|t| t.text().parse().ok());
        }
    }
    None
}

/// Returns an [`Edit`] replacing the integer in `script_timeout(N)`.
pub fn set_script_timeout(root: &SyntaxNode, timeout: u32) -> Option<Edit> {
    for arg_list in nodes_of_kind(root, SyntaxKind::ARG_LIST) {
        if !parent_fn_is(arg_list.clone(), "script_timeout") {
            continue;
        }
        if let Some(arg) = arg_list.children().find(|n| n.kind() == SyntaxKind::ARG) {
            if let Some(tok) = arg
                .descendants_with_tokens()
                .filter_map(|e| e.into_token())
                .find(|t| t.kind() == SyntaxKind::INT_LIT)
            {
                return Some(Edit {
                    range: tok.text_range(),
                    replacement: timeout.to_string(),
                });
            }
        }
    }
    None
}

// ============================================================================
// script_cve_id("CVE-...", ...)  — multi-value positional strings
// ============================================================================

/// Returns all CVE strings from `script_cve_id("CVE-...", ...)`.
pub fn get_cve_ids(root: &SyntaxNode) -> Vec<String> {
    for arg_list in nodes_of_kind(root, SyntaxKind::ARG_LIST) {
        if !parent_fn_is(arg_list.clone(), "script_cve_id") {
            continue;
        }
        return arg_list
            .children()
            .filter(|n| n.kind() == SyntaxKind::ARG)
            .filter_map(|arg| find_string_token(&arg).map(|t| unquote(t.text())))
            .collect();
    }
    Vec::new()
}

/// Case-insensitive check for a CVE in `script_cve_id(...)`.
pub fn has_cve_id(root: &SyntaxNode, cve: &str) -> bool {
    get_cve_ids(root).iter().any(|c| c.eq_ignore_ascii_case(cve))
}

/// Returns an [`Edit`] appending `cve` to `script_cve_id(...)`.
pub fn add_cve_id(root: &SyntaxNode, cve: &str) -> Option<Edit> {
    add_positional_string_arg(root, "script_cve_id", cve)
}

/// Returns an [`Edit`] removing `cve` (case-insensitive) from `script_cve_id(...)`.
pub fn remove_cve_id(root: &SyntaxNode, cve: &str) -> Option<Edit> {
    let mut ids = get_cve_ids(root);
    let before = ids.len();
    ids.retain(|c| !c.eq_ignore_ascii_case(cve));
    if ids.len() == before {
        return None;
    }
    set_positional_string_args(root, "script_cve_id", &ids)
}

/// Returns an [`Edit`] replacing the entire CVE list in `script_cve_id(...)`.
pub fn set_cve_ids(root: &SyntaxNode, cves: &[String]) -> Option<Edit> {
    set_positional_string_args(root, "script_cve_id", cves)
}

// ============================================================================
// script_bugtraq_id(N, ...)  — multi-value INT args
// ============================================================================

/// Returns all bugtraq IDs from `script_bugtraq_id(N, ...)` as strings.
pub fn get_bugtraq_ids(root: &SyntaxNode) -> Vec<String> {
    for arg_list in nodes_of_kind(root, SyntaxKind::ARG_LIST) {
        if !parent_fn_is(arg_list.clone(), "script_bugtraq_id") {
            continue;
        }
        return positional_arg_values(&arg_list);
    }
    Vec::new()
}

// ============================================================================
// script_xref(name:"...", value:"...")  — multiple calls possible
// ============================================================================

/// All xrefs as (name, value) pairs.
pub fn get_all_xrefs(root: &SyntaxNode) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for arg_list in nodes_of_kind(root, SyntaxKind::ARG_LIST) {
        if !parent_fn_is(arg_list.clone(), "script_xref") {
            continue;
        }
        let named_args = named_arg_children(&arg_list);
        let name = named_args
            .iter()
            .find(|na| na_ident(na).as_deref() == Some("name"))
            .and_then(|na| find_string_token(na))
            .map(|t| unquote(t.text()));
        let value = named_args
            .iter()
            .find(|na| na_ident(na).as_deref() == Some("value"))
            .and_then(|na| find_string_token(na))
            .map(|t| unquote(t.text()));
        if let (Some(n), Some(v)) = (name, value) {
            out.push((n, v));
        }
    }
    out
}

/// All xref values for a specific name key.
pub fn get_xrefs(root: &SyntaxNode, xref_name: &str) -> Vec<String> {
    get_all_xrefs(root)
        .into_iter()
        .filter(|(n, _)| n == xref_name)
        .map(|(_, v)| v)
        .collect()
}

/// Returns `true` if a `script_xref(name:"<xref_name>", value:"<xref_value>")` exists.
pub fn has_xref(root: &SyntaxNode, xref_name: &str, xref_value: &str) -> bool {
    get_all_xrefs(root)
        .iter()
        .any(|(n, v)| n == xref_name && v == xref_value)
}

/// Insert a new script_xref call before exit(0) in the description block.
pub fn add_xref(root: &SyntaxNode, name: &str, value: &str) -> Option<Edit> {
    let exit_stmt = find_description_exit(root)?;
    let indent = detect_indent(&exit_stmt);
    let insert_at = exit_stmt.text_range().start();
    Some(Edit {
        range: TextRange::new(insert_at, insert_at),
        replacement: format!("\n{}script_xref(name:\"{}\", value:\"{}\");", indent, name, value),
    })
}

// ============================================================================
// script_dependencies("a.nasl", ...)
// ============================================================================

/// Returns all filenames from `script_dependencies("a.nasl", ...)`.
pub fn get_dependencies(root: &SyntaxNode) -> Vec<String> {
    for arg_list in nodes_of_kind(root, SyntaxKind::ARG_LIST) {
        if !parent_fn_is(arg_list.clone(), "script_dependencies") {
            continue;
        }
        return arg_list
            .children()
            .filter(|n| n.kind() == SyntaxKind::ARG)
            .filter_map(|arg| find_string_token(&arg).map(|t| unquote(t.text())))
            .collect();
    }
    Vec::new()
}

/// Returns `true` if `dep` appears in `script_dependencies(...)`.
pub fn has_dependency(root: &SyntaxNode, dep: &str) -> bool {
    get_dependencies(root).iter().any(|d| d == dep)
}

/// Returns an [`Edit`] appending `dep` to `script_dependencies(...)`.
pub fn add_dependency(root: &SyntaxNode, dep: &str) -> Option<Edit> {
    add_positional_string_arg(root, "script_dependencies", dep)
}

/// Returns an [`Edit`] removing `dep` from `script_dependencies(...)`.
pub fn remove_dependency(root: &SyntaxNode, dep: &str) -> Option<Edit> {
    let mut deps = get_dependencies(root);
    let before = deps.len();
    deps.retain(|d| d != dep);
    if deps.len() == before {
        return None;
    }
    set_positional_string_args(root, "script_dependencies", &deps)
}

// ============================================================================
// script_mandatory_keys("k1", re:"pattern")
// ============================================================================

/// Returns positional string keys from `script_mandatory_keys("k1", ...)`.
pub fn get_mandatory_keys(root: &SyntaxNode) -> Vec<String> {
    for arg_list in nodes_of_kind(root, SyntaxKind::ARG_LIST) {
        if !parent_fn_is(arg_list.clone(), "script_mandatory_keys") {
            continue;
        }
        return arg_list
            .children()
            .filter(|n| n.kind() == SyntaxKind::ARG)
            .filter_map(|arg| find_string_token(&arg).map(|t| unquote(t.text())))
            .collect();
    }
    Vec::new()
}

/// Returns the `re:"..."` named argument of `script_mandatory_keys(...)`, if present.
pub fn get_mandatory_keys_re(root: &SyntaxNode) -> Option<String> {
    for arg_list in nodes_of_kind(root, SyntaxKind::ARG_LIST) {
        if !parent_fn_is(arg_list.clone(), "script_mandatory_keys") {
            continue;
        }
        return named_arg_children(&arg_list)
            .iter()
            .find(|na| na_ident(na).as_deref() == Some("re"))
            .and_then(|na| find_string_token(na))
            .map(|t| unquote(t.text()));
    }
    None
}

/// Returns an [`Edit`] appending `key` to `script_mandatory_keys(...)`.
pub fn add_mandatory_key(root: &SyntaxNode, key: &str) -> Option<Edit> {
    add_positional_string_arg(root, "script_mandatory_keys", key)
}

// ============================================================================
// script_require_keys("k1", ...)  — older variant of mandatory_keys
// ============================================================================

/// Returns all keys from `script_require_keys(...)` (older variant of mandatory_keys).
pub fn get_require_keys(root: &SyntaxNode) -> Vec<String> {
    for arg_list in nodes_of_kind(root, SyntaxKind::ARG_LIST) {
        if !parent_fn_is(arg_list.clone(), "script_require_keys") {
            continue;
        }
        return arg_list
            .children()
            .filter(|n| n.kind() == SyntaxKind::ARG)
            .filter_map(|arg| find_string_token(&arg).map(|t| unquote(t.text())))
            .collect();
    }
    Vec::new()
}

// ============================================================================
// script_require_ports / script_require_udp_ports  — mixed int+string args
// ============================================================================

/// Returns mixed int/string args from `script_require_ports(...)` as strings.
pub fn get_require_ports(root: &SyntaxNode) -> Vec<String> {
    for arg_list in nodes_of_kind(root, SyntaxKind::ARG_LIST) {
        if !parent_fn_is(arg_list.clone(), "script_require_ports") {
            continue;
        }
        return positional_arg_values(&arg_list);
    }
    Vec::new()
}

/// Returns mixed int/string args from `script_require_udp_ports(...)` as strings.
pub fn get_require_udp_ports(root: &SyntaxNode) -> Vec<String> {
    for arg_list in nodes_of_kind(root, SyntaxKind::ARG_LIST) {
        if !parent_fn_is(arg_list.clone(), "script_require_udp_ports") {
            continue;
        }
        return positional_arg_values(&arg_list);
    }
    Vec::new()
}

// ============================================================================
// script_exclude_keys("k1", ...)
// ============================================================================

/// Returns all keys from `script_exclude_keys(...)`.
pub fn get_exclude_keys(root: &SyntaxNode) -> Vec<String> {
    for arg_list in nodes_of_kind(root, SyntaxKind::ARG_LIST) {
        if !parent_fn_is(arg_list.clone(), "script_exclude_keys") {
            continue;
        }
        return arg_list
            .children()
            .filter(|n| n.kind() == SyntaxKind::ARG)
            .filter_map(|arg| find_string_token(&arg).map(|t| unquote(t.text())))
            .collect();
    }
    Vec::new()
}

/// Returns an [`Edit`] appending `key` to `script_exclude_keys(...)`.
pub fn add_exclude_key(root: &SyntaxNode, key: &str) -> Option<Edit> {
    add_positional_string_arg(root, "script_exclude_keys", key)
}

// ============================================================================
// script_add_preference(name:"...", type:"...", value:"...", id:N)
// ============================================================================

#[derive(Debug, Clone)]
pub struct Preference {
    pub name: String,
    pub type_: String,
    pub value: String,
    pub id: Option<u32>,
}

/// Returns all preferences from `script_add_preference(name:"...", type:"...", value:"...", id:N)`.
pub fn get_preferences(root: &SyntaxNode) -> Vec<Preference> {
    let mut out = Vec::new();
    for arg_list in nodes_of_kind(root, SyntaxKind::ARG_LIST) {
        if !parent_fn_is(arg_list.clone(), "script_add_preference") {
            continue;
        }
        let named_args = named_arg_children(&arg_list);
        let get_str = |key: &str| {
            named_args
                .iter()
                .find(|na| na_ident(na).as_deref() == Some(key))
                .and_then(|na| find_string_token(na))
                .map(|t| unquote(t.text()))
        };
        let id = named_args
            .iter()
            .find(|na| na_ident(na).as_deref() == Some("id"))
            .and_then(|na| {
                na.descendants_with_tokens()
                    .filter_map(|e| e.into_token())
                    .find(|t| t.kind() == SyntaxKind::INT_LIT)
            })
            .and_then(|t| t.text().parse().ok());

        if let (Some(name), Some(type_), Some(value)) =
            (get_str("name"), get_str("type"), get_str("value"))
        {
            out.push(Preference { name, type_, value, id });
        }
    }
    out
}

/// Insert a new script_add_preference call before exit(0).
pub fn add_preference(
    root: &SyntaxNode,
    name: &str,
    type_: &str,
    value: &str,
    id: u32,
) -> Option<Edit> {
    let exit_stmt = find_description_exit(root)?;
    let indent = detect_indent(&exit_stmt);
    let insert_at = exit_stmt.text_range().start();
    Some(Edit {
        range: TextRange::new(insert_at, insert_at),
        replacement: format!(
            "\n{}script_add_preference(name:\"{}\", type:\"{}\", value:\"{}\", id:{});",
            indent, name, type_, value, id
        ),
    })
}

// ============================================================================
// include("file.inc")  statements
// ============================================================================

/// Returns all include filenames from `include("file.inc")` statements.
pub fn get_includes(root: &SyntaxNode) -> Vec<String> {
    nodes_of_kind(root, SyntaxKind::INCLUDE_STMT)
        .iter()
        .filter_map(|stmt| {
            stmt.descendants_with_tokens()
                .filter_map(|e| e.into_token())
                .find(|t| {
                    matches!(
                        t.kind(),
                        SyntaxKind::STRING_DOUBLE | SyntaxKind::STRING_SINGLE
                    )
                })
                .map(|t| unquote(t.text()))
        })
        .collect()
}

/// Returns `true` if `include("<filename>")` is present.
pub fn has_include(root: &SyntaxNode, filename: &str) -> bool {
    get_includes(root).iter().any(|f| f == filename)
}

/// Append `include("filename");` after the last existing include statement.
pub fn add_include(root: &SyntaxNode, filename: &str) -> Option<Edit> {
    let stmts = nodes_of_kind(root, SyntaxKind::INCLUDE_STMT);
    if let Some(last) = stmts.last() {
        let insert_at = last.text_range().end();
        return Some(Edit {
            range: TextRange::new(insert_at, insert_at),
            replacement: format!("\ninclude(\"{}\");", filename),
        });
    }
    // No existing include — insert before exit(0)
    let exit_stmt = find_description_exit(root)?;
    let indent = detect_indent(&exit_stmt);
    let insert_at = exit_stmt.text_range().start();
    Some(Edit {
        range: TextRange::new(insert_at, insert_at),
        replacement: format!("include(\"{}\")\n{}", filename, indent),
    })
}

/// Remove the `include("filename");` statement (including its leading newline).
pub fn remove_include(root: &SyntaxNode, filename: &str) -> Option<Edit> {
    for stmt in nodes_of_kind(root, SyntaxKind::INCLUDE_STMT) {
        let matches = stmt
            .descendants_with_tokens()
            .filter_map(|e| e.into_token())
            .any(|t| {
                matches!(
                    t.kind(),
                    SyntaxKind::STRING_DOUBLE | SyntaxKind::STRING_SINGLE
                ) && unquote(t.text()) == filename
            });
        if matches {
            return Some(Edit {
                range: stmt.text_range(),
                replacement: String::new(),
            });
        }
    }
    None
}

// ============================================================================
// insert_before_closing_quote helper  (used externally)
// ============================================================================

pub fn insert_before_closing_quote(tok: &SyntaxToken, text: &str) -> Edit {
    let end = tok.text_range().end();
    let q_len = if tok.kind() == SyntaxKind::STRING_SINGLE { "'" } else { "\"" };
    let insert_at = end - TextSize::of(q_len);
    Edit {
        range: TextRange::new(insert_at, insert_at),
        replacement: text.to_string(),
    }
}

// ============================================================================
// Full metadata snapshot
// ============================================================================

#[derive(Debug, Default)]
pub struct NaslMetadata {
    pub oid: Option<String>,
    pub version: Option<String>,
    pub name: Option<String>,
    pub family: Option<String>,
    pub category: Option<String>,
    pub copyright: Option<String>,
    pub timeout: Option<u32>,
    /// All script_tag (name, value) pairs.
    pub script_tags: Vec<(String, String)>,
    pub cve_ids: Vec<String>,
    pub bugtraq_ids: Vec<String>,
    /// All script_xref (name, value) pairs.
    pub xrefs: Vec<(String, String)>,
    pub dependencies: Vec<String>,
    pub mandatory_keys: Vec<String>,
    /// The `re:"..."` argument of script_mandatory_keys, if any.
    pub mandatory_keys_re: Option<String>,
    pub require_keys: Vec<String>,
    /// Port requirements as strings (may be integers or service names).
    pub require_ports: Vec<String>,
    pub require_udp_ports: Vec<String>,
    pub exclude_keys: Vec<String>,
    pub includes: Vec<String>,
    pub preferences: Vec<Preference>,
}

/// Returns a [`NaslMetadata`] snapshot of every piece of structured metadata in the file.
pub fn get_metadata(root: &SyntaxNode) -> NaslMetadata {
    NaslMetadata {
        oid: get_simple_call(root, "script_oid"),
        version: get_simple_call(root, "script_version"),
        name: get_simple_call(root, "script_name"),
        family: get_simple_call(root, "script_family"),
        category: get_script_category(root),
        copyright: get_simple_call(root, "script_copyright"),
        timeout: get_script_timeout(root),
        script_tags: get_all_script_tags(root),
        cve_ids: get_cve_ids(root),
        bugtraq_ids: get_bugtraq_ids(root),
        xrefs: get_all_xrefs(root),
        dependencies: get_dependencies(root),
        mandatory_keys: get_mandatory_keys(root),
        mandatory_keys_re: get_mandatory_keys_re(root),
        require_keys: get_require_keys(root),
        require_ports: get_require_ports(root),
        require_udp_ports: get_require_udp_ports(root),
        exclude_keys: get_exclude_keys(root),
        includes: get_includes(root),
        preferences: get_preferences(root),
    }
}

// ============================================================================
// add_script_tag — insert new script_tag before exit(0) in description block
// ============================================================================

/// Insert `script_tag(name:"<name>", value:"<value>");` before `exit(0)` in
/// the `if(description){}` block.
pub fn add_script_tag(root: &SyntaxNode, name: &str, value: &str) -> Option<Edit> {
    let exit_stmt = find_description_exit(root)?;
    let indent = detect_indent(&exit_stmt);
    let insert_at = exit_stmt.text_range().start();
    // Insert with a leading "\n" — the exit_stmt already starts with "\n<indent>"
    // so the trailing newline before exit(0) comes from the exit stmt itself.
    Some(Edit {
        range: TextRange::new(insert_at, insert_at),
        replacement: format!("\n{}script_tag(name:\"{}\", value:\"{}\");", indent, name, value),
    })
}

// ============================================================================
// Holm modified markers
// ============================================================================

/// All `script_tag` pairs whose name starts with `"holm-"`.
pub fn get_holm_tags(root: &SyntaxNode) -> Vec<(String, String)> {
    get_all_script_tags(root)
        .into_iter()
        .filter(|(name, _)| name.starts_with("holm-"))
        .collect()
}

/// All `COMMENT` tokens whose text contains `"holm"` (case-insensitive).
pub fn get_holm_comments(root: &SyntaxNode) -> Vec<String> {
    root.descendants_with_tokens()
        .filter_map(|e| e.into_token())
        .filter(|t| {
            t.kind() == SyntaxKind::COMMENT
                && t.text().to_ascii_lowercase().contains("holm")
        })
        .map(|t| t.text().to_string())
        .collect()
}

/// `true` if the file has any holm-prefixed `script_tag` or any comment
/// that mentions "holm".
pub fn has_holm_marker(root: &SyntaxNode) -> bool {
    !get_holm_tags(root).is_empty() || !get_holm_comments(root).is_empty()
}

// ============================================================================
// Security message blocks + PCI keys
// ============================================================================

/// `true` if `node` (or any descendant) contains a call to `fn_name`.
fn contains_call(node: &SyntaxNode, fn_name: &str) -> bool {
    nodes_of_kind(node, SyntaxKind::ARG_LIST)
        .into_iter()
        .any(|al| parent_fn_is(al, fn_name))
}

/// Detect the statement indent from the first child node of a block.
fn detect_block_stmt_indent(block: &SyntaxNode) -> String {
    block
        .children()
        .next()
        .as_ref()
        .map(detect_indent)
        .unwrap_or_else(|| "  ".to_string())
}

/// Return the value expression text from a `NAMED_ARG` — the portion after
/// the `:`, trimmed of leading/trailing whitespace.
fn named_arg_value_expr_text(na: &SyntaxNode) -> Option<String> {
    let na_start = na.text_range().start();
    let na_text = na.text().to_string();

    let colon_end = na
        .children_with_tokens()
        .filter_map(|e| e.into_token())
        .find(|t| t.kind() == SyntaxKind::COLON)
        .map(|t| t.text_range().end())?;

    let offset: usize = (colon_end - na_start).into();
    if offset >= na_text.len() {
        return None;
    }
    Some(na_text[offset..].trim().to_string())
}

/// All `set_kb_item(name:"holm/pci/...", value:<expr>)` calls inside any
/// if-block whose condition or body calls `security_message(...)`.
/// Returns `(key, value_expr_text)` pairs.
pub fn get_pci_kb_items(root: &SyntaxNode) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for if_stmt in nodes_of_kind(root, SyntaxKind::IF_STMT) {
        if !contains_call(&if_stmt, "security_message") {
            continue;
        }
        for arg_list in nodes_of_kind(&if_stmt, SyntaxKind::ARG_LIST) {
            if !parent_fn_is(arg_list.clone(), "set_kb_item") {
                continue;
            }
            let named_args = named_arg_children(&arg_list);
            let key = named_args
                .iter()
                .find(|na| na_ident(na).as_deref() == Some("name"))
                .and_then(|na| find_string_token(na))
                .map(|t| unquote(t.text()));
            let val_expr = named_args
                .iter()
                .find(|na| na_ident(na).as_deref() == Some("value"))
                .and_then(|na| named_arg_value_expr_text(na));
            if let (Some(k), Some(v)) = (key, val_expr) {
                if k.starts_with("holm/pci/") {
                    out.push((k, v));
                }
            }
        }
    }
    out
}

/// `true` if any security_message if-block contains
/// `set_kb_item(name:"<key>", ...)`.
pub fn has_pci_kb_item(root: &SyntaxNode, key: &str) -> bool {
    get_pci_kb_items(root).iter().any(|(k, _)| k == key)
}

/// Insert `stmt` before the closing `}` of every if-block that calls
/// `security_message(...)`. Returns one `Edit` per matched block.
/// Caller should pass all edits to `apply_edits`.
pub fn add_to_security_message_blocks(root: &SyntaxNode, stmt: &str) -> Vec<Edit> {
    let mut edits = Vec::new();
    for if_stmt in nodes_of_kind(root, SyntaxKind::IF_STMT) {
        if !contains_call(&if_stmt, "security_message") {
            continue;
        }
        if let Some(block) = if_stmt.children().find(|n| n.kind() == SyntaxKind::BLOCK) {
            let indent = detect_block_stmt_indent(&block);
            if let Some(rbrace) = block
                .children_with_tokens()
                .filter_map(|e| e.into_token())
                .find(|t| t.kind() == SyntaxKind::R_BRACE)
            {
                let insert_at = rbrace.text_range().start();
                edits.push(Edit {
                    range: TextRange::new(insert_at, insert_at),
                    replacement: format!("{}{}\n", indent, stmt),
                });
            }
        }
    }
    edits
}

/// Replace the value expression of `set_kb_item(name:"<key>", value:<old>)`
/// inside a security_message if-block. Returns the first matching edit.
pub fn update_pci_kb_item(root: &SyntaxNode, key: &str, value_expr: &str) -> Option<Edit> {
    for if_stmt in nodes_of_kind(root, SyntaxKind::IF_STMT) {
        if !contains_call(&if_stmt, "security_message") {
            continue;
        }
        for arg_list in nodes_of_kind(&if_stmt, SyntaxKind::ARG_LIST) {
            if !parent_fn_is(arg_list.clone(), "set_kb_item") {
                continue;
            }
            let named_args = named_arg_children(&arg_list);
            let key_matches = named_args
                .iter()
                .find(|na| na_ident(na).as_deref() == Some("name"))
                .and_then(|na| find_string_token(na))
                .map(|t| unquote(t.text()) == key)
                .unwrap_or(false);
            if !key_matches {
                continue;
            }
            if let Some(val_na) = named_args
                .iter()
                .find(|na| na_ident(na).as_deref() == Some("value"))
            {
                // Walk direct children: find COLON, then first non-whitespace
                // element after it is the start of the value expression.
                let mut past_colon = false;
                let mut expr_start: Option<TextSize> = None;
                let val_na_end = val_na.text_range().end();

                'outer: for elem in val_na.children_with_tokens() {
                    if past_colon {
                        // Skip leading whitespace tokens
                        if let Some(tok) = elem.clone().into_token() {
                            if tok.kind() == SyntaxKind::WHITESPACE {
                                continue 'outer;
                            }
                        }
                        expr_start = Some(elem.text_range().start());
                        break;
                    }
                    if let Some(tok) = elem.into_token() {
                        if tok.kind() == SyntaxKind::COLON {
                            past_colon = true;
                        }
                    }
                }

                if let Some(start) = expr_start {
                    return Some(Edit {
                        range: TextRange::new(start, val_na_end),
                        replacement: value_expr.to_string(),
                    });
                }
            }
        }
    }
    None
}

// ============================================================================
// Date parsing and comparison
// ============================================================================

/// A parsed NASL script version date.
///
/// Derives `Ord` so dates are directly comparable with `<`, `>`, etc.
/// The version string format is typically `"2025-04-08T12:00:00+0000"`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NaslDate {
    pub year: i32,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
}

impl NaslDate {
    /// Returns the date as an ISO 8601 string `"YYYY-MM-DDTHH:MM:SS"`.
    pub fn to_iso_string(&self) -> String {
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )
    }
}

/// Parse a NASL version/date string into a [`NaslDate`].
///
/// Accepts:
/// - `"2025-04-08T12:00:00+0000"` — full timestamp (timezone stripped)
/// - `"2025-04-08T12:00:00+00:00"` — with colon in timezone
/// - `"2025-04-08"` — date only (time set to 00:00:00)
/// - `"2025/04/08"` — slash-separated date
///
/// Returns `None` if the string cannot be parsed.
pub fn parse_nasl_date(s: &str) -> Option<NaslDate> {
    let s = s.trim();

    // Split on 'T' to separate date and optional time
    let (date_part, time_part) = match s.find('T') {
        Some(i) => (&s[..i], Some(&s[i + 1..])),
        None => (s, None),
    };

    // Parse YYYY-MM-DD or YYYY/MM/DD
    let d: Vec<&str> = date_part.splitn(3, |c| c == '-' || c == '/').collect();
    if d.len() < 3 {
        return None;
    }
    let year: i32 = d[0].parse().ok()?;
    let month: u8 = d[1].parse().ok()?;
    let day: u8 = d[2].parse().ok()?;
    if year < 1900 || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }

    // Parse HH:MM:SS from time part (ignore timezone offset)
    let (hour, minute, second) = if let Some(t) = time_part {
        // Take at most 8 chars ("HH:MM:SS") — any trailing +0000 is beyond that
        let t8 = &t[..t.len().min(8)];
        let parts: Vec<&str> = t8.splitn(3, ':').collect();
        let h: u8 = parts.first().and_then(|s| s.parse().ok()).unwrap_or(0);
        let m: u8 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        // Seconds field may have a trailing sign char if timestamp is short
        let sec: u8 = parts
            .get(2)
            .map(|s| s.chars().take_while(|c| c.is_ascii_digit()).collect::<String>())
            .as_deref()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        (h, m, sec)
    } else {
        (0, 0, 0)
    };

    Some(NaslDate { year, month, day, hour, minute, second })
}

/// Extract and parse the `script_version(...)` string as a [`NaslDate`].
/// Returns `None` if the call is absent or unparseable.
pub fn get_version_date(root: &SyntaxNode) -> Option<NaslDate> {
    let v = get_simple_call(root, "script_version")?;
    parse_nasl_date(&v)
}

/// `true` if the file's version date is strictly before `cutoff`.
pub fn version_is_before(root: &SyntaxNode, cutoff: &NaslDate) -> bool {
    get_version_date(root).map_or(false, |d| d < *cutoff)
}

/// `true` if the file's version date is strictly after `cutoff`.
pub fn version_is_after(root: &SyntaxNode, cutoff: &NaslDate) -> bool {
    get_version_date(root).map_or(false, |d| d > *cutoff)
}

/// `true` if the file's version date is within `[start, end]` inclusive.
pub fn version_is_between(root: &SyntaxNode, start: &NaslDate, end: &NaslDate) -> bool {
    get_version_date(root).map_or(false, |d| d >= *start && d <= *end)
}

// ============================================================================
// General code block operations
// ============================================================================

/// A resolved function call site anywhere in the file.
#[derive(Debug, Clone)]
pub struct CallSite {
    /// Full source text of the call expression, e.g. `foo("bar", x:1)`.
    pub text: String,
    /// Byte offset of the call's start in the source.
    pub offset: u32,
    /// Positional argument texts (trimmed; strings are unquoted).
    pub args: Vec<String>,
    /// Named argument `(name, value_text)` pairs.
    pub named_args: Vec<(String, String)>,
}

/// A located if-statement.
#[derive(Debug, Clone)]
pub struct IfBlockInfo {
    /// Condition text between the outer `(` and `)` (trimmed).
    pub condition: String,
    /// Full source text of the entire if-statement.
    pub text: String,
    /// Byte offset of the `if` keyword.
    pub offset: u32,
}

/// A located variable assignment.
#[derive(Debug, Clone)]
pub struct AssignmentInfo {
    /// Variable name on the left-hand side.
    pub var_name: String,
    /// Assignment operator (`=`, `+=`, `-=`, `*=`, `/=`, `%=`).
    pub operator: String,
    /// Source text of the right-hand side expression (trimmed).
    pub value: String,
    /// Byte offset of the assignment expression.
    pub offset: u32,
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// All CALL_EXPR nodes whose leading IDENT_EXPR has text == `fn_name`.
fn find_call_nodes(root: &SyntaxNode, fn_name: &str) -> Vec<SyntaxNode> {
    // The NASL CST has no CALL_EXPR kind. A call is represented as an
    // IDENT_EXPR followed by an ARG_LIST as siblings inside the parent node.
    // Find all ARG_LIST nodes whose parent has an IDENT_EXPR sibling with the
    // right name, then return those parents (the containing statement/block).
    nodes_of_kind(root, SyntaxKind::ARG_LIST)
        .into_iter()
        .filter(|arg_list| parent_fn_is(arg_list.clone(), fn_name))
        .filter_map(|arg_list| arg_list.parent())
        .collect()
}

/// Build a [`CallSite`] snapshot from a CALL_EXPR node.
fn call_site_from_node(call: &SyntaxNode) -> CallSite {
    let (args, named_args) = call
        .children()
        .find(|n| n.kind() == SyntaxKind::ARG_LIST)
        .map(|al| {
            let pos: Vec<String> = al
                .children()
                .filter(|n| n.kind() == SyntaxKind::ARG)
                .map(|n| n.text().to_string().trim().to_string())
                .collect();
            let named: Vec<(String, String)> = al
                .children()
                .filter(|n| n.kind() == SyntaxKind::NAMED_ARG)
                .filter_map(|n| Some((na_ident(&n)?, named_arg_value_expr_text(&n)?)))
                .collect();
            (pos, named)
        })
        .unwrap_or_default();

    CallSite {
        text: call.text().to_string(),
        offset: u32::from(call.text_range().start()),
        args,
        named_args,
    }
}

/// Text of an IF_STMT's condition — the content between the outer `(` and `)`.
fn if_stmt_condition_text(if_stmt: &SyntaxNode) -> String {
    let mut inside = false;
    let mut text = String::new();
    for child in if_stmt.children_with_tokens() {
        match child.kind() {
            SyntaxKind::L_PAREN if !inside => inside = true,
            SyntaxKind::R_PAREN | SyntaxKind::BLOCK if inside => break,
            _ if inside => {
                if let Some(t) = child.as_token() {
                    text.push_str(t.text());
                } else if let Some(n) = child.as_node() {
                    text.push_str(&n.text().to_string());
                }
            }
            _ => {}
        }
    }
    text.trim().to_string()
}

/// Replace the value portion of a NAMED_ARG (from after `:` to end of node).
fn replace_named_arg_value_edit(na: &SyntaxNode, new_value: &str) -> Option<Edit> {
    let mut past_colon = false;
    let mut expr_start: Option<TextSize> = None;
    let na_end = na.text_range().end();

    for elem in na.children_with_tokens() {
        if past_colon {
            if let Some(t) = elem.as_token() {
                if t.kind() == SyntaxKind::WHITESPACE {
                    continue;
                }
            }
            expr_start = Some(elem.text_range().start());
            break;
        }
        if let Some(t) = elem.as_token() {
            if t.kind() == SyntaxKind::COLON {
                past_colon = true;
            }
        }
    }

    expr_start.map(|start| Edit {
        range: TextRange::new(start, na_end),
        replacement: new_value.to_string(),
    })
}

/// Walk up the parent chain to find the enclosing EXPR_STMT.
/// Returns `None` if the call is inside a condition or other non-statement context.
fn expr_stmt_ancestor(node: &SyntaxNode) -> Option<SyntaxNode> {
    // Check the node itself first (find_call_nodes already returns EXPR_STMTs).
    if node.kind() == SyntaxKind::EXPR_STMT {
        return Some(node.clone());
    }
    let mut cur = node.parent();
    while let Some(n) = cur {
        match n.kind() {
            SyntaxKind::EXPR_STMT => return Some(n),
            // Control-flow nodes that own conditions — call is not a standalone stmt
            SyntaxKind::SOURCE_FILE
            | SyntaxKind::FUNCTION_DEF
            | SyntaxKind::IF_STMT
            | SyntaxKind::FOR_STMT
            | SyntaxKind::FOREACH_STMT
            | SyntaxKind::WHILE_STMT
            | SyntaxKind::REPEAT_STMT => return None,
            _ => {}
        }
        cur = n.parent();
    }
    None
}

/// Shared logic for extracting `(op_tok, rhs_start)` from an ASSIGN_EXPR.
fn assign_op_and_rhs(assign: &SyntaxNode) -> Option<(SyntaxToken, TextSize)> {
    let op_tok = assign
        .children_with_tokens()
        .filter_map(|e| e.into_token())
        .find(|t| {
            matches!(
                t.kind(),
                SyntaxKind::EQ
                    | SyntaxKind::PLUS_EQ
                    | SyntaxKind::MINUS_EQ
                    | SyntaxKind::STAR_EQ
                    | SyntaxKind::SLASH_EQ
                    | SyntaxKind::PERCENT_EQ
            )
        })?;

    let op_range = op_tok.text_range();
    let mut past = false;
    let mut rhs_start = None;
    for elem in assign.children_with_tokens() {
        if past {
            if let Some(t) = elem.as_token() {
                if t.kind() == SyntaxKind::WHITESPACE {
                    continue;
                }
            }
            rhs_start = Some(elem.text_range().start());
            break;
        }
        if let Some(t) = elem.as_token() {
            if t.text_range() == op_range {
                past = true;
            }
        }
    }
    Some((op_tok, rhs_start?))
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Return all call sites of `fn_name` anywhere in the file.
pub fn find_calls(root: &SyntaxNode, fn_name: &str) -> Vec<CallSite> {
    find_call_nodes(root, fn_name)
        .iter()
        .map(call_site_from_node)
        .collect()
}

/// Replace a positional argument in the `occurrence`-th call to `fn_name`.
///
/// Both `occurrence` and `arg_index` are 0-based.
/// Returns `None` if the call or arg is not found.
pub fn replace_call_positional_arg(
    root: &SyntaxNode,
    fn_name: &str,
    occurrence: usize,
    arg_index: usize,
    new_value: &str,
) -> Option<Edit> {
    let call = find_call_nodes(root, fn_name).into_iter().nth(occurrence)?;
    let arg_list = call.children().find(|n| n.kind() == SyntaxKind::ARG_LIST)?;
    let arg = arg_list
        .children()
        .filter(|n| n.kind() == SyntaxKind::ARG)
        .nth(arg_index)?;
    Some(Edit {
        range: arg.text_range(),
        replacement: new_value.to_string(),
    })
}

/// Replace the value of named argument `arg_name` in every call to `fn_name`.
///
/// Returns one `Edit` per matched call. Pass all to `apply_edits`.
pub fn replace_call_named_arg(
    root: &SyntaxNode,
    fn_name: &str,
    arg_name: &str,
    new_value: &str,
) -> Vec<Edit> {
    find_call_nodes(root, fn_name)
        .iter()
        .filter_map(|call| {
            let al = call.children().find(|n| n.kind() == SyntaxKind::ARG_LIST)?;
            let na = al
                .children()
                .filter(|n| n.kind() == SyntaxKind::NAMED_ARG)
                .find(|n| na_ident(n).as_deref() == Some(arg_name))?;
            replace_named_arg_value_edit(&na, new_value)
        })
        .collect()
}

/// All if-blocks whose condition or body contains a call to `fn_name`.
pub fn find_if_blocks_with_call(root: &SyntaxNode, fn_name: &str) -> Vec<IfBlockInfo> {
    nodes_of_kind(root, SyntaxKind::IF_STMT)
        .into_iter()
        .filter(|if_stmt| contains_call(if_stmt, fn_name))
        .map(|if_stmt| IfBlockInfo {
            condition: if_stmt_condition_text(&if_stmt),
            text: if_stmt.text().to_string(),
            offset: u32::from(if_stmt.text_range().start()),
        })
        .collect()
}

/// All if-blocks whose condition text contains `substr` (substring match).
pub fn find_if_blocks_with_condition_text(root: &SyntaxNode, substr: &str) -> Vec<IfBlockInfo> {
    nodes_of_kind(root, SyntaxKind::IF_STMT)
        .into_iter()
        .filter_map(|if_stmt| {
            let cond = if_stmt_condition_text(&if_stmt);
            if cond.contains(substr) {
                Some(IfBlockInfo {
                    condition: cond,
                    text: if_stmt.text().to_string(),
                    offset: u32::from(if_stmt.text_range().start()),
                })
            } else {
                None
            }
        })
        .collect()
}

/// Insert `stmt` as a new statement immediately before every standalone call to `fn_name`.
///
/// "Standalone" means the call is an EXPR_STMT, not inside a condition or RHS.
/// Returns one `Edit` per matched site; pass all to `apply_edits`.
pub fn insert_before_call(root: &SyntaxNode, fn_name: &str, stmt: &str) -> Vec<Edit> {
    find_call_nodes(root, fn_name)
        .into_iter()
        .filter_map(|call| {
            let expr_stmt = expr_stmt_ancestor(&call)?;
            let indent = detect_indent(&expr_stmt);
            let insert_at = expr_stmt.text_range().start();
            Some(Edit {
                range: TextRange::new(insert_at, insert_at),
                replacement: format!("\n{}{}", indent, stmt),
            })
        })
        .collect()
}

/// Insert `stmt` as a new statement immediately after every standalone call to `fn_name`.
pub fn insert_after_call(root: &SyntaxNode, fn_name: &str, stmt: &str) -> Vec<Edit> {
    find_call_nodes(root, fn_name)
        .into_iter()
        .filter_map(|call| {
            let expr_stmt = expr_stmt_ancestor(&call)?;
            let indent = detect_indent(&expr_stmt);
            let insert_at = expr_stmt.text_range().end();
            Some(Edit {
                range: TextRange::new(insert_at, insert_at),
                replacement: format!("\n{}{}", indent, stmt),
            })
        })
        .collect()
}

/// Insert `stmt` at the start (after `{`) of every if-block that calls `fn_name`.
pub fn insert_at_start_of_if_block(root: &SyntaxNode, fn_name: &str, stmt: &str) -> Vec<Edit> {
    nodes_of_kind(root, SyntaxKind::IF_STMT)
        .into_iter()
        .filter(|if_stmt| contains_call(if_stmt, fn_name))
        .filter_map(|if_stmt| {
            let block = if_stmt.children().find(|n| n.kind() == SyntaxKind::BLOCK)?;
            let lbrace = block
                .children_with_tokens()
                .filter_map(|e| e.into_token())
                .find(|t| t.kind() == SyntaxKind::L_BRACE)?;
            let indent = detect_block_stmt_indent(&block);
            let insert_at = lbrace.text_range().end();
            Some(Edit {
                range: TextRange::new(insert_at, insert_at),
                replacement: format!("\n{}{}", indent, stmt),
            })
        })
        .collect()
}

/// Insert `stmt` at the end (before `}`) of every if-block that calls `fn_name`.
pub fn insert_at_end_of_if_block(root: &SyntaxNode, fn_name: &str, stmt: &str) -> Vec<Edit> {
    nodes_of_kind(root, SyntaxKind::IF_STMT)
        .into_iter()
        .filter(|if_stmt| contains_call(if_stmt, fn_name))
        .filter_map(|if_stmt| {
            let block = if_stmt.children().find(|n| n.kind() == SyntaxKind::BLOCK)?;
            let indent = detect_block_stmt_indent(&block);
            let rbrace = block
                .children_with_tokens()
                .filter_map(|e| e.into_token())
                .find(|t| t.kind() == SyntaxKind::R_BRACE)?;
            let insert_at = rbrace.text_range().start();
            Some(Edit {
                range: TextRange::new(insert_at, insert_at),
                replacement: format!("{}{}\n", indent, stmt),
            })
        })
        .collect()
}

/// All assignments to `var_name` anywhere in the file.
///
/// Handles `=`, `+=`, `-=`, `*=`, `/=`, `%=`. Only simple `ident = expr`
/// left-hand sides are matched (not array subscripts).
pub fn find_assignments(root: &SyntaxNode, var_name: &str) -> Vec<AssignmentInfo> {
    // The NASL CST has no ASSIGN_EXPR kind. Assignments are EXPR_STMT nodes
    // whose first child IDENT_EXPR matches the variable name and that contain
    // an assignment operator token as a direct child.
    nodes_of_kind(root, SyntaxKind::EXPR_STMT)
        .into_iter()
        .filter_map(|stmt| {
            // LHS must be a bare IDENT_EXPR with the target name
            let lhs = stmt.children().next()?;
            if lhs.kind() != SyntaxKind::IDENT_EXPR {
                return None;
            }
            let ident = lhs
                .descendants_with_tokens()
                .filter_map(|e| e.into_token())
                .find(|t| t.kind() == SyntaxKind::IDENT)?;
            if ident.text() != var_name {
                return None;
            }

            let (op_tok, rhs_start) = assign_op_and_rhs(&stmt)?;
            let full = stmt.text().to_string();
            let rhs_off: usize = (rhs_start - stmt.text_range().start()).into();
            let value = full[rhs_off..].trim().trim_end_matches(';').trim().to_string();

            Some(AssignmentInfo {
                var_name: var_name.to_string(),
                operator: op_tok.text().to_string(),
                value,
                offset: u32::from(stmt.text_range().start()),
            })
        })
        .collect()
}

/// Replace the RHS of the **first** assignment to `var_name` with `new_expr`.
pub fn replace_assignment(root: &SyntaxNode, var_name: &str, new_expr: &str) -> Option<Edit> {
    for stmt in nodes_of_kind(root, SyntaxKind::EXPR_STMT) {
        let lhs = match stmt.children().next() {
            Some(n) => n,
            None => continue,
        };
        if lhs.kind() != SyntaxKind::IDENT_EXPR {
            continue;
        }
        let matches = lhs
            .descendants_with_tokens()
            .filter_map(|e| e.into_token())
            .any(|t| t.kind() == SyntaxKind::IDENT && t.text() == var_name);
        if !matches {
            continue;
        }
        if let Some((_, rhs_start)) = assign_op_and_rhs(&stmt) {
            // Replace from rhs_start to just before the trailing SEMICOLON
            let end = stmt
                .children_with_tokens()
                .filter_map(|e| e.into_token())
                .find(|t| t.kind() == SyntaxKind::SEMICOLON)
                .map(|t| t.text_range().start())
                .unwrap_or_else(|| stmt.text_range().end());
            return Some(Edit {
                range: TextRange::new(rhs_start, end),
                replacement: new_expr.to_string(),
            });
        }
    }
    None
}

// ============================================================================
// Full tree access
// ============================================================================

/// A node or token in the CST, suitable for Python-side manual traversal.
///
/// Obtain via [`get_tree`], walk `children`, then use `offset` + `length`
/// with [`replace_range_edit`] to target any edit precisely.
#[derive(Debug, Clone)]
pub struct TreeNode {
    /// `SyntaxKind` name (e.g. `"IF_STMT"`, `"IDENT"`, `"STRING_DOUBLE"`).
    pub kind: String,
    /// Byte offset of this node/token in the source.
    pub offset: u32,
    /// Byte length of this node/token.
    pub length: u32,
    /// `true` for leaf tokens, `false` for composite nodes.
    pub is_token: bool,
    /// Raw source text — only set when `is_token == true`.
    pub text: Option<String>,
    /// Child nodes and tokens — only non-empty when `is_token == false`.
    pub children: Vec<TreeNode>,
}

fn build_tree_node(node: &SyntaxNode) -> TreeNode {
    let children = node
        .children_with_tokens()
        .map(|child| {
            if let Some(t) = child.as_token() {
                TreeNode {
                    kind: format!("{:?}", t.kind()),
                    offset: u32::from(t.text_range().start()),
                    length: u32::from(t.text_range().len()),
                    is_token: true,
                    text: Some(t.text().to_string()),
                    children: Vec::new(),
                }
            } else {
                build_tree_node(child.as_node().unwrap())
            }
        })
        .collect();

    TreeNode {
        kind: format!("{:?}", node.kind()),
        offset: u32::from(node.text_range().start()),
        length: u32::from(node.text_range().len()),
        is_token: false,
        text: None,
        children,
    }
}

/// Return the entire CST as a [`TreeNode`] tree rooted at `root`.
///
/// Walk `children` recursively. Leaf tokens carry `text`, `offset`, and
/// `length`. Use `offset` + `length` with [`replace_range_edit`] to build
/// an edit for any node or token you find.
pub fn get_tree(root: &SyntaxNode) -> TreeNode {
    build_tree_node(root)
}

/// Build an [`Edit`] that replaces `length` bytes starting at `offset`.
///
/// Pair this with offsets from [`get_tree`] for arbitrary structural edits.
pub fn replace_range_edit(offset: u32, length: u32, replacement: &str) -> Edit {
    Edit {
        range: TextRange::new(TextSize::from(offset), TextSize::from(offset + length)),
        replacement: replacement.to_string(),
    }
}

// ============================================================================
// Comment operations
// ============================================================================

/// A located comment token.
#[derive(Debug, Clone)]
pub struct CommentInfo {
    /// Full comment text including the leading `#`.
    pub text: String,
    /// Byte offset of this comment token in the source.
    pub offset: u32,
}

/// All comment tokens in the file, in source order.
pub fn get_comments(root: &SyntaxNode) -> Vec<CommentInfo> {
    root.descendants_with_tokens()
        .filter_map(|e| e.into_token())
        .filter(|t| t.kind() == SyntaxKind::COMMENT)
        .map(|t| CommentInfo {
            text: t.text().to_string(),
            offset: u32::from(t.text_range().start()),
        })
        .collect()
}

/// All comment tokens whose text contains `substr` (case-sensitive).
pub fn find_comments_containing(root: &SyntaxNode, substr: &str) -> Vec<CommentInfo> {
    get_comments(root)
        .into_iter()
        .filter(|c| c.text.contains(substr))
        .collect()
}

/// Replace the comment token at byte `offset` with `new_text`.
///
/// `new_text` must include the leading `#` (e.g. `"# revised comment"`).
/// Returns `None` if no comment starts at `offset`.
pub fn replace_comment_at(root: &SyntaxNode, offset: u32, new_text: &str) -> Option<Edit> {
    let target = TextSize::from(offset);
    root.descendants_with_tokens()
        .filter_map(|e| e.into_token())
        .find(|t| t.kind() == SyntaxKind::COMMENT && t.text_range().start() == target)
        .map(|t| Edit {
            range: t.text_range(),
            replacement: new_text.to_string(),
        })
}
