pub mod syntax_kind;
pub mod lexer;
pub mod parser;
pub mod queries;

pub use syntax_kind::{NaslLanguage, SyntaxElement, SyntaxKind, SyntaxNode, SyntaxToken};
pub use parser::{parse, ParseResult};

// Re-export rowan types that callers will need for traversal / editing.
pub use rowan::{TextRange, TextSize};

// ============================================================================
// Edit API
// ============================================================================

/// A single targeted text replacement in the original source.
#[derive(Debug, Clone)]
pub struct Edit {
    /// Byte range to replace (from `node.text_range()`).
    pub range: TextRange,
    /// Replacement text (does not need to be the same length).
    pub replacement: String,
}

/// Apply a set of edits to `source` and return the modified string.
///
/// Edits **must not overlap**. They are applied in reverse order (last -> first)
/// so that earlier byte offsets remain valid as later ones are replaced.
pub fn apply_edits(source: &str, mut edits: Vec<Edit>) -> String {
    // Sort descending by start offset so we process from the end.
    edits.sort_by(|a, b| b.range.start().cmp(&a.range.start()));

    let mut result = source.to_string();
    for edit in edits {
        let start = usize::from(edit.range.start());
        let end   = usize::from(edit.range.end());
        result.replace_range(start..end, &edit.replacement);
    }
    result
}

// ============================================================================
// Query helpers
// ============================================================================

/// Walk every node in the CST and collect those matching `predicate`.
pub fn find_nodes<F>(root: &SyntaxNode, predicate: F) -> Vec<SyntaxNode>
where
    F: Fn(&SyntaxNode) -> bool,
{
    root.descendants().filter(|n| predicate(n)).collect()
}

/// Return all nodes of a specific `kind`.
pub fn nodes_of_kind(root: &SyntaxNode, kind: SyntaxKind) -> Vec<SyntaxNode> {
    find_nodes(root, |n| n.kind() == kind)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn check_round_trip(src: &str) {
        let result = parse(src);
        assert!(
            result.round_trips(src),
            "round-trip failed.\nOriginal:\n{src}\nGot:\n{}",
            result.root
        );
    }

    #[test]
    fn test_empty_file() {
        check_round_trip("");
    }

    #[test]
    fn test_comment_only() {
        check_round_trip("# This is a comment\n");
    }

    #[test]
    fn test_include() {
        check_round_trip("include(\"cpe.inc\");\n");
    }

    #[test]
    fn test_exit() {
        check_round_trip("exit(0);\n");
    }

    #[test]
    fn test_assignment() {
        check_round_trip("os_arch = get_kb_item(\"SMB/Windows/Arch\");\n");
    }

    #[test]
    fn test_if_simple() {
        check_round_trip("if(!os_arch){\n  exit(0);\n}\n");
    }

    #[test]
    fn test_foreach() {
        check_round_trip("foreach item( make_list(\"a\", \"b\") ) {\n  log(item);\n}\n");
    }

    #[test]
    fn test_script_tag() {
        check_round_trip(
            "script_tag(name:\"cvss_base\", value:\"7.8\");\n"
        );
    }

    #[test]
    fn test_string_contains() {
        check_round_trip("if( 'foo' >< res ) { exit(0); }\n");
    }

    #[test]
    fn test_string_not_contains() {
        check_round_trip("if( 'foo' >!< res ) { exit(0); }\n");
    }

    #[test]
    fn test_regex_match() {
        check_round_trip("if( version =~ \"^5\\.[0-4]\\.\" ) { exit(0); }\n");
    }

    #[test]
    fn test_local_var() {
        check_round_trip("local_var a, b, c;\n");
    }

    #[test]
    fn test_function_def() {
        check_round_trip("function foo(a, b) {\n  return a;\n}\n");
    }

    #[test]
    fn test_description_block() {
        let src = "if(description)\n{\n  script_oid(\"1.3.6.1.4.1.25623.1.0.808032\");\n  script_version(\"2025-03-04T05:38:25+0000\");\n  script_tag(name:\"cvss_base\", value:\"0.0\");\n  exit(0);\n}\n";
        check_round_trip(src);
    }

    #[test]
    fn test_named_arg_re() {
        check_round_trip(
            "script_mandatory_keys(\"ssh/login/suse_sles\", re:\"ssh/login/release=(SLES15\\.0)\");\n"
        );
    }
}
