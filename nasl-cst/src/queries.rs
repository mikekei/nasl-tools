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
                .any(|t| t.kind() == SyntaxKind::IDENT && t.text() == name)
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
    None
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
    let last = stmts.last()?;
    let insert_at = last.text_range().end();
    Some(Edit {
        range: TextRange::new(insert_at, insert_at),
        replacement: format!("\ninclude(\"{}\");", filename),
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
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
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
