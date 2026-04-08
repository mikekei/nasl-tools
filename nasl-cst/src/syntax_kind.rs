/// Every token and node kind in the NASL CST.
///
/// Tokens (leaves) have text. Composite nodes have children.
/// The ordering matters: rowan uses the u16 value internally.
///
/// INVARIANT: Every byte of the original source appears in exactly one
/// leaf token. Whitespace, newlines, and comments are first-class tokens.
/// This guarantees lossless round-trip: `root.to_string() == original_source`.
#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub enum SyntaxKind {
    // =========================================================
    // TRIVIA — preserved verbatim in the CST
    // =========================================================
    /// One or more space/tab characters (not newlines)
    WHITESPACE,
    /// \n or \r\n
    NEWLINE,
    /// # comment text (including the # and up to but not including the newline)
    COMMENT,

    // =========================================================
    // LITERALS
    // =========================================================
    /// Decimal integer: 0, 42, 65535
    INT_LIT,
    /// Hex integer: 0x1A, 0xFF
    HEX_LIT,
    /// Double-quoted string: "hello\nworld"
    STRING_DOUBLE,
    /// Single-quoted string: 'raw bytes'
    STRING_SINGLE,

    // =========================================================
    // KEYWORDS
    // =========================================================
    KW_IF,
    KW_ELSE,
    KW_FOR,
    KW_FOREACH,
    KW_WHILE,
    KW_REPEAT,
    KW_UNTIL,
    KW_RETURN,
    KW_BREAK,
    KW_CONTINUE,
    KW_EXIT,
    KW_INCLUDE,
    KW_FUNCTION,
    KW_LOCAL_VAR,
    KW_GLOBAL_VAR,
    KW_TRUE,
    KW_FALSE,
    KW_NULL,

    // =========================================================
    // IDENTIFIER  (anything that is not a keyword)
    // =========================================================
    IDENT,

    // =========================================================
    // PUNCTUATION
    // =========================================================
    L_PAREN,   // (
    R_PAREN,   // )
    L_BRACE,   // {
    R_BRACE,   // }
    L_BRACKET, // [
    R_BRACKET, // ]
    SEMICOLON, // ;
    COMMA,     // ,
    COLON,     // :
    DOT,       // .

    // =========================================================
    // OPERATORS  (longest-match wins in the lexer)
    // =========================================================
    // Assignment
    EQ,         // =
    PLUS_EQ,    // +=
    MINUS_EQ,   // -=
    STAR_EQ,    // *=
    SLASH_EQ,   // /=
    PERCENT_EQ, // %=

    // Equality / comparison
    EQ_EQ,  // ==
    BANG_EQ, // !=
    LT,     // <
    GT,     // >
    LT_EQ,  // <=
    GT_EQ,  // >=

    // String containment (NASL-specific)
    GT_LT,      // ><  (contains substring)
    GT_BANG_LT, // >!< (does NOT contain substring)

    // Regex match (NASL-specific)
    EQ_TILDE,   // =~
    BANG_TILDE, // !~

    // Arithmetic
    PLUS,    // +
    MINUS,   // -
    STAR,    // *
    SLASH,   // /
    PERCENT, // %

    // Logical
    AMP_AMP,   // &&
    PIPE_PIPE, // ||
    BANG,      // !

    // Bitwise
    AMP,    // &
    PIPE,   // |
    CARET,  // ^
    TILDE,  // ~
    GT_GT,  // >>
    LT_LT,  // <<

    // Increment / decrement (rare in NASL but handle gracefully)
    PLUS_PLUS,   // ++
    MINUS_MINUS, // --

    // =========================================================
    // ERROR TOKEN — unexpected character(s)
    // =========================================================
    ERROR,

    // =========================================================
    // COMPOSITE NODES (inner nodes, no direct text)
    // =========================================================

    /// The root node — wraps the entire file
    SOURCE_FILE,

    // --- Declarations ---
    /// function foo(a, b) { ... }
    FUNCTION_DEF,
    /// (a, b, c) in a function definition
    PARAM_LIST,
    /// A single parameter name
    PARAM,

    // --- Statements ---
    /// { stmt* }
    BLOCK,
    /// expr ;
    EXPR_STMT,
    /// if (cond) block (else_clause)?
    IF_STMT,
    /// else if (...) block  |  else block
    ELSE_CLAUSE,
    /// for (init; cond; step) block
    FOR_STMT,
    /// foreach var ( list ) block
    FOREACH_STMT,
    /// while (cond) block
    WHILE_STMT,
    /// repeat block until (cond) ;
    REPEAT_STMT,
    /// return expr? ;
    RETURN_STMT,
    /// break ;
    BREAK_STMT,
    /// continue ;
    CONTINUE_STMT,
    /// include("file.inc") ;
    INCLUDE_STMT,
    /// local_var a, b, c ;
    LOCAL_VAR_STMT,
    /// global_var a, b, c ;
    GLOBAL_VAR_STMT,

    // --- Expressions ---
    /// a = b, a += b, etc.
    ASSIGN_EXPR,
    /// a || b, a && b, a + b, etc.
    BINARY_EXPR,
    /// !a, -a, ~a
    UNARY_EXPR,
    /// foo(args)
    CALL_EXPR,
    /// arr[index]
    INDEX_EXPR,
    /// (expr)
    PAREN_EXPR,
    /// Argument list of a call: (arg, named:val, ...)
    ARG_LIST,
    /// A positional argument inside ARG_LIST
    ARG,
    /// A named argument: ident : expr
    NAMED_ARG,
    /// A bare identifier used as an expression
    IDENT_EXPR,
    /// An integer, string, TRUE, FALSE, NULL literal as an expression
    LITERAL,

    #[doc(hidden)]
    __LAST,
}

impl SyntaxKind {
    /// Returns true for tokens that should be skipped by the parser's
    /// "peek" mechanism but are still stored in the CST.
    pub fn is_trivia(self) -> bool {
        matches!(self, SyntaxKind::WHITESPACE | SyntaxKind::NEWLINE | SyntaxKind::COMMENT)
    }

    /// Returns true for tokens that are syntactically meaningful.
    pub fn is_token(self) -> bool {
        (self as u16) < SyntaxKind::SOURCE_FILE as u16
    }
}

impl From<SyntaxKind> for rowan::SyntaxKind {
    fn from(kind: SyntaxKind) -> Self {
        rowan::SyntaxKind(kind as u16)
    }
}

impl From<rowan::SyntaxKind> for SyntaxKind {
    fn from(raw: rowan::SyntaxKind) -> Self {
        assert!(raw.0 < SyntaxKind::__LAST as u16, "unknown SyntaxKind: {}", raw.0);
        // SAFETY: repr(u16), all values in range are valid enum variants
        unsafe { std::mem::transmute(raw.0) }
    }
}

/// The rowan Language tag for NASL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NaslLanguage {}

impl rowan::Language for NaslLanguage {
    type Kind = SyntaxKind;

    fn kind_from_raw(raw: rowan::SyntaxKind) -> SyntaxKind {
        SyntaxKind::from(raw)
    }

    fn kind_to_raw(kind: SyntaxKind) -> rowan::SyntaxKind {
        kind.into()
    }
}

/// Type aliases for convenience.
pub type SyntaxNode = rowan::SyntaxNode<NaslLanguage>;
pub type SyntaxToken = rowan::SyntaxToken<NaslLanguage>;
pub type SyntaxElement = rowan::NodeOrToken<SyntaxNode, SyntaxToken>;
