/// For every `script_tag(name:"summary", value:"...")` call, append one
/// extra space before the closing quote of the value string, then write
/// the file back. Git diff should show exactly those lines changed.
use walkdir::WalkDir;
use nasl_cst::{SyntaxKind, SyntaxNode, SyntaxToken, Edit, apply_edits, nodes_of_kind};
use rowan::TextSize;
use std::path::Path;

fn main() {
    let dir_str = match std::env::args().nth(1) {
        Some(d) => d,
        None => {
            eprintln!("Usage: edit_summary <directory>");
            std::process::exit(1);
        }
    };
    let dir = Path::new(&dir_str);

    let mut total = 0usize;
    let mut edited = 0usize;
    let mut failed = 0usize;

    for entry in WalkDir::new(dir)
        .into_iter()
        .filter_map(|e: Result<walkdir::DirEntry, _>| e.ok())
        .filter(|e| e.path().extension().map_or(false, |x| x == "nasl"))
    {
        let path = entry.path();
        let source = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(_) => continue,
        };

        total += 1;
        let result = nasl_cst::parse(&source);

        // Collect edit targets: the STRING token inside value:"..." of every
        // script_tag(name:"summary", ...) call.
        let edits: Vec<Edit> = collect_summary_edits(&result.root);

        if edits.is_empty() {
            continue;
        }

        let updated = apply_edits(&source, edits);

        match std::fs::write(path, updated.as_bytes()) {
            Ok(_) => edited += 1,
            Err(e) => {
                eprintln!("ERR   {} ({})", path.display(), e);
                failed += 1;
            }
        }

        if total % 10000 == 0 {
            println!("  ... {} files scanned, {} edited", total, edited);
        }
    }

    println!("\nDone: {} files scanned, {} edited, {} errors", total, edited, failed);
}

// ─────────────────────────────────────────────────────────────────────────────
// Query helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Return one Edit per `script_tag(name:"summary", value:"...")` found in root.
/// The edit inserts a single space just before the closing quote of value.
fn collect_summary_edits(root: &SyntaxNode) -> Vec<Edit> {
    let mut edits = Vec::new();

    for arg_list in nodes_of_kind(root, SyntaxKind::ARG_LIST) {
        if !parent_is_script_tag(&arg_list) {
            continue;
        }

        let named_args: Vec<SyntaxNode> = arg_list
            .children()
            .filter(|n| n.kind() == SyntaxKind::NAMED_ARG)
            .collect();

        // Must have name:"summary"
        let is_summary = named_args.iter().any(|na| {
            named_arg_ident(na).as_deref() == Some("name")
                && named_arg_string_text(na).as_deref() == Some("\"summary\"")
        });
        if !is_summary {
            continue;
        }

        // Find the value named arg
        if let Some(value_na) = named_args
            .iter()
            .find(|na| named_arg_ident(na).as_deref() == Some("value"))
        {
            if let Some(str_tok) = find_string_token(value_na) {
                let range = str_tok.text_range();
                // Insert one space just before the closing quote/apostrophe.
                let insert_at = range.end() - TextSize::of(closing_quote_char(&str_tok));
                edits.push(Edit {
                    range: rowan::TextRange::new(insert_at, insert_at),
                    replacement: " ".to_string(),
                });
            }
        }
    }

    edits
}

/// True if the ARG_LIST's parent node contains an IDENT_EXPR whose
/// identifier text is "script_tag".
fn parent_is_script_tag(arg_list: &SyntaxNode) -> bool {
    let parent = match arg_list.parent() {
        Some(p) => p,
        None => return false,
    };
    parent.children().any(|child| {
        child.kind() == SyntaxKind::IDENT_EXPR
            && child
                .descendants_with_tokens()
                .filter_map(|e| e.into_token())
                .any(|t| t.kind() == SyntaxKind::IDENT && t.text() == "script_tag")
    })
}

/// The identifier name of a NAMED_ARG node (the part before the colon).
fn named_arg_ident(na: &SyntaxNode) -> Option<String> {
    na.descendants_with_tokens()
        .filter_map(|e| e.into_token())
        .find(|t| t.kind() == SyntaxKind::IDENT)
        .map(|t| t.text().to_string())
}

/// The raw text of the string literal in a NAMED_ARG (including quotes).
fn named_arg_string_text(na: &SyntaxNode) -> Option<String> {
    find_string_token(na).map(|t| t.text().to_string())
}

/// Find the first STRING_DOUBLE or STRING_SINGLE token anywhere inside `node`.
fn find_string_token(node: &SyntaxNode) -> Option<SyntaxToken> {
    node.descendants_with_tokens()
        .filter_map(|e| e.into_token())
        .find(|t| {
            matches!(
                t.kind(),
                SyntaxKind::STRING_DOUBLE | SyntaxKind::STRING_SINGLE
            )
        })
}

/// Return the closing quote character as a str slice for TextSize::of.
fn closing_quote_char(tok: &SyntaxToken) -> &'static str {
    if tok.kind() == SyntaxKind::STRING_SINGLE {
        "'"
    } else {
        "\""
    }
}
