use rowan::GreenNodeBuilder;

use crate::syntax_kind::{SyntaxKind, SyntaxNode};

// ============================================================================
// Parser state
// ============================================================================

pub struct Parser<'a> {
    /// All tokens (including trivia) from the lexer.
    tokens: Vec<(SyntaxKind, &'a str)>,
    /// Current read position in `tokens`.
    pos: usize,
    /// Rowan builder — accumulates the green tree.
    builder: GreenNodeBuilder<'static>,
    /// Parse errors collected during parsing.
    pub errors: Vec<String>,
}

impl<'a> Parser<'a> {
    pub fn new(tokens: Vec<(SyntaxKind, &'a str)>) -> Self {
        Parser {
            tokens,
            pos: 0,
            builder: GreenNodeBuilder::new(),
            errors: Vec::new(),
        }
    }

    // ------------------------------------------------------------------ //
    // Token inspection helpers
    // ------------------------------------------------------------------ //

    /// The kind of the token at `self.pos + offset`, ignoring trivia.
    /// Offset 0 = the *next* non-trivia token.
    fn nth_kind(&self, mut offset: usize) -> SyntaxKind {
        let mut i = self.pos;
        loop {
            match self.tokens.get(i) {
                None => return SyntaxKind::ERROR,
                Some((k, _)) if k.is_trivia() => i += 1,
                Some((k, _)) => {
                    if offset == 0 {
                        return *k;
                    }
                    offset -= 1;
                    i += 1;
                }
            }
        }
    }

    /// Peek the current non-trivia token kind.
    fn current(&self) -> SyntaxKind {
        self.nth_kind(0)
    }

    /// Peek the next non-trivia token kind (1 ahead).
    fn peek(&self) -> SyntaxKind {
        self.nth_kind(1)
    }

    /// True if the current non-trivia token has `kind`.
    fn at(&self, kind: SyntaxKind) -> bool {
        self.current() == kind
    }

    /// True if current OR next non-trivia token has `kind`.
    fn at_nth(&self, n: usize, kind: SyntaxKind) -> bool {
        self.nth_kind(n) == kind
    }

    // ------------------------------------------------------------------ //
    // Token consumption
    // ------------------------------------------------------------------ //

    /// Consume all leading trivia tokens, adding them to the builder.
    fn eat_trivia(&mut self) {
        while let Some((kind, text)) = self.tokens.get(self.pos) {
            if kind.is_trivia() {
                self.builder.token((*kind).into(), text);
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    /// Consume the current token (including any preceding trivia) and add
    /// both to the builder. This is the primary way to advance.
    fn bump(&mut self) {
        self.eat_trivia();
        if let Some((kind, text)) = self.tokens.get(self.pos) {
            self.builder.token((*kind).into(), text);
            self.pos += 1;
        }
    }

    /// Consume the current token only if it matches `kind`.
    /// Returns true if it was consumed.
    fn eat(&mut self, kind: SyntaxKind) -> bool {
        if self.at(kind) {
            self.bump();
            true
        } else {
            false
        }
    }

    /// Consume the current token, asserting it has `kind`.
    /// On mismatch, record an error and emit an ERROR token instead.
    fn expect(&mut self, kind: SyntaxKind) {
        if self.at(kind) {
            self.bump();
        } else {
            let actual = self.current();
            self.errors.push(format!(
                "expected {:?} but found {:?} at token {}",
                kind, actual, self.pos
            ));
            // Emit an ERROR leaf so no bytes are lost
            self.eat_trivia();
            if let Some((_, text)) = self.tokens.get(self.pos) {
                self.builder.token(SyntaxKind::ERROR.into(), text);
                self.pos += 1;
            }
        }
    }

    // ------------------------------------------------------------------ //
    // Node wrappers
    // ------------------------------------------------------------------ //

    /// Start a composite node, call `f`, finish the node.
    fn wrap<F: FnOnce(&mut Self)>(&mut self, kind: SyntaxKind, f: F) {
        self.builder.start_node(kind.into());
        f(self);
        self.builder.finish_node();
    }

    // ------------------------------------------------------------------ //
    // Entry point
    // ------------------------------------------------------------------ //

    pub fn parse_source_file(mut self) -> (SyntaxNode, Vec<String>) {
        self.builder.start_node(SyntaxKind::SOURCE_FILE.into());
        while self.pos < self.tokens.len() || self.current() != SyntaxKind::ERROR {
            // Consume any trailing trivia at EOF
            if self.tokens.get(self.pos).is_none() {
                break;
            }
            // Check if we're at only trivia left
            let all_trivia = self.tokens[self.pos..].iter().all(|(k, _)| k.is_trivia());
            if all_trivia {
                while self.pos < self.tokens.len() {
                    let (k, t) = self.tokens[self.pos];
                    self.builder.token(k.into(), t);
                    self.pos += 1;
                }
                break;
            }
            self.parse_item();
        }
        self.builder.finish_node();
        let green = self.builder.finish();
        let errors = self.errors;
        (SyntaxNode::new_root(green), errors)
    }

    // ------------------------------------------------------------------ //
    // Items (top-level)
    // ------------------------------------------------------------------ //

    fn parse_item(&mut self) {
        match self.current() {
            SyntaxKind::KW_FUNCTION => self.parse_function_def(),
            SyntaxKind::KW_IF => self.parse_if_stmt(),
            SyntaxKind::KW_FOR => self.parse_for_stmt(),
            SyntaxKind::KW_FOREACH => self.parse_foreach_stmt(),
            SyntaxKind::KW_WHILE => self.parse_while_stmt(),
            SyntaxKind::KW_REPEAT => self.parse_repeat_stmt(),
            SyntaxKind::KW_RETURN => self.parse_return_stmt(),
            SyntaxKind::KW_BREAK => self.parse_break_stmt(),
            SyntaxKind::KW_CONTINUE => self.parse_continue_stmt(),
            SyntaxKind::KW_LOCAL_VAR => self.parse_local_var_stmt(),
            SyntaxKind::KW_GLOBAL_VAR => self.parse_global_var_stmt(),
            SyntaxKind::KW_INCLUDE => self.parse_include_stmt(),
            SyntaxKind::L_BRACE => self.parse_block(),
            SyntaxKind::SEMICOLON => {
                // Empty statement
                self.wrap(SyntaxKind::EXPR_STMT, |p| { p.bump(); });
            }
            _ => self.parse_expr_stmt(),
        }
    }

    // ------------------------------------------------------------------ //
    // Function definition
    // ------------------------------------------------------------------ //

    fn parse_function_def(&mut self) {
        self.wrap(SyntaxKind::FUNCTION_DEF, |p| {
            p.bump(); // function
            // Name
            if p.at(SyntaxKind::IDENT) {
                p.bump();
            } else {
                p.errors.push(format!("expected function name at pos {}", p.pos));
            }
            // Parameter list
            p.parse_param_list();
            // Body
            if p.at(SyntaxKind::L_BRACE) {
                p.parse_block();
            } else {
                p.errors.push(format!("expected '{{' for function body at pos {}", p.pos));
            }
        });
    }

    fn parse_param_list(&mut self) {
        self.wrap(SyntaxKind::PARAM_LIST, |p| {
            p.expect(SyntaxKind::L_PAREN);
            while !p.at(SyntaxKind::R_PAREN) && !p.at_eof() {
                if p.at(SyntaxKind::IDENT) {
                    p.wrap(SyntaxKind::PARAM, |p| { p.bump(); });
                } else {
                    p.bump(); // error recovery
                }
                if !p.eat(SyntaxKind::COMMA) {
                    break;
                }
            }
            p.expect(SyntaxKind::R_PAREN);
        });
    }

    // ------------------------------------------------------------------ //
    // Block
    // ------------------------------------------------------------------ //

    fn parse_block(&mut self) {
        self.wrap(SyntaxKind::BLOCK, |p| {
            p.expect(SyntaxKind::L_BRACE);
            while !p.at(SyntaxKind::R_BRACE) && !p.at_eof() {
                p.parse_item();
            }
            p.expect(SyntaxKind::R_BRACE);
        });
    }

    // ------------------------------------------------------------------ //
    // Statements
    // ------------------------------------------------------------------ //

    fn parse_expr_stmt(&mut self) {
        self.wrap(SyntaxKind::EXPR_STMT, |p| {
            p.parse_expr();
            p.expect(SyntaxKind::SEMICOLON);
        });
    }

    fn parse_if_stmt(&mut self) {
        self.wrap(SyntaxKind::IF_STMT, |p| {
            p.bump(); // if
            p.expect(SyntaxKind::L_PAREN);
            p.parse_expr();
            p.expect(SyntaxKind::R_PAREN);
            p.parse_body();
            // else / else if
            if p.at(SyntaxKind::KW_ELSE) {
                p.wrap(SyntaxKind::ELSE_CLAUSE, |p| {
                    p.bump(); // else
                    if p.at(SyntaxKind::KW_IF) {
                        p.parse_if_stmt();
                    } else {
                        p.parse_body();
                    }
                });
            }
        });
    }

    /// Either a block `{ ... }` or a single statement (common in NASL).
    fn parse_body(&mut self) {
        if self.at(SyntaxKind::L_BRACE) {
            self.parse_block();
        } else {
            self.parse_item();
        }
    }

    fn parse_for_stmt(&mut self) {
        self.wrap(SyntaxKind::FOR_STMT, |p| {
            p.bump(); // for
            p.expect(SyntaxKind::L_PAREN);
            // init (optional expr before first ;)
            if !p.at(SyntaxKind::SEMICOLON) {
                p.parse_expr();
            }
            p.expect(SyntaxKind::SEMICOLON);
            // condition (optional)
            if !p.at(SyntaxKind::SEMICOLON) {
                p.parse_expr();
            }
            p.expect(SyntaxKind::SEMICOLON);
            // step (optional)
            if !p.at(SyntaxKind::R_PAREN) {
                p.parse_expr();
            }
            p.expect(SyntaxKind::R_PAREN);
            p.parse_body();
        });
    }

    /// `foreach varname ( expr ) { ... }`
    fn parse_foreach_stmt(&mut self) {
        self.wrap(SyntaxKind::FOREACH_STMT, |p| {
            p.bump(); // foreach
            // iterator variable name
            if p.at(SyntaxKind::IDENT) {
                p.bump();
            } else {
                p.errors.push(format!("expected foreach variable at pos {}", p.pos));
            }
            p.expect(SyntaxKind::L_PAREN);
            p.parse_expr();
            p.expect(SyntaxKind::R_PAREN);
            p.parse_body();
        });
    }

    fn parse_while_stmt(&mut self) {
        self.wrap(SyntaxKind::WHILE_STMT, |p| {
            p.bump(); // while
            p.expect(SyntaxKind::L_PAREN);
            p.parse_expr();
            p.expect(SyntaxKind::R_PAREN);
            p.parse_body();
        });
    }

    /// `repeat { ... } until ( expr ) ;`
    fn parse_repeat_stmt(&mut self) {
        self.wrap(SyntaxKind::REPEAT_STMT, |p| {
            p.bump(); // repeat
            p.parse_block();
            p.expect(SyntaxKind::KW_UNTIL);
            p.expect(SyntaxKind::L_PAREN);
            p.parse_expr();
            p.expect(SyntaxKind::R_PAREN);
            p.expect(SyntaxKind::SEMICOLON);
        });
    }

    fn parse_return_stmt(&mut self) {
        self.wrap(SyntaxKind::RETURN_STMT, |p| {
            p.bump(); // return
            if !p.at(SyntaxKind::SEMICOLON) {
                p.parse_expr();
            }
            p.expect(SyntaxKind::SEMICOLON);
        });
    }

    fn parse_break_stmt(&mut self) {
        self.wrap(SyntaxKind::BREAK_STMT, |p| {
            p.bump(); // break
            p.expect(SyntaxKind::SEMICOLON);
        });
    }

    fn parse_continue_stmt(&mut self) {
        self.wrap(SyntaxKind::CONTINUE_STMT, |p| {
            p.bump(); // continue
            p.expect(SyntaxKind::SEMICOLON);
        });
    }

    /// `include("file.inc");`
    fn parse_include_stmt(&mut self) {
        self.wrap(SyntaxKind::INCLUDE_STMT, |p| {
            p.bump(); // include
            p.expect(SyntaxKind::L_PAREN);
            // The argument is a string literal
            if matches!(p.current(), SyntaxKind::STRING_DOUBLE | SyntaxKind::STRING_SINGLE) {
                p.bump();
            } else {
                p.parse_expr();
            }
            p.expect(SyntaxKind::R_PAREN);
            p.expect(SyntaxKind::SEMICOLON);
        });
    }

    /// `local_var a, b, c;`
    fn parse_local_var_stmt(&mut self) {
        self.wrap(SyntaxKind::LOCAL_VAR_STMT, |p| {
            p.bump(); // local_var
            loop {
                if p.at(SyntaxKind::IDENT) {
                    p.bump();
                } else {
                    break;
                }
                if !p.eat(SyntaxKind::COMMA) {
                    break;
                }
            }
            p.expect(SyntaxKind::SEMICOLON);
        });
    }

    /// `global_var a, b;`
    fn parse_global_var_stmt(&mut self) {
        self.wrap(SyntaxKind::GLOBAL_VAR_STMT, |p| {
            p.bump(); // global_var
            loop {
                if p.at(SyntaxKind::IDENT) {
                    p.bump();
                } else {
                    break;
                }
                if !p.eat(SyntaxKind::COMMA) {
                    break;
                }
            }
            p.expect(SyntaxKind::SEMICOLON);
        });
    }

    // ------------------------------------------------------------------ //
    // Expressions  (Pratt / precedence-climbing style)
    // ------------------------------------------------------------------ //

    fn parse_expr(&mut self) {
        self.parse_assign();
    }

    /// Assignment is right-associative: a = b = c → a = (b = c)
    fn parse_assign(&mut self) {
        self.parse_or();
        if matches!(
            self.current(),
            SyntaxKind::EQ
            | SyntaxKind::PLUS_EQ
            | SyntaxKind::MINUS_EQ
            | SyntaxKind::STAR_EQ
            | SyntaxKind::SLASH_EQ
            | SyntaxKind::PERCENT_EQ
        ) {
            // We need to wrap the already-built left side + operator + right side
            // in an ASSIGN_EXPR. Rowan's builder doesn't support "wrapping already
            // emitted nodes", so we use a checkpoint.
            // We'll handle this in the builder directly since we started parsing
            // with parse_or() already pushed. We use a different strategy:
            // re-parse with checkpoints (see parse_expr_with_checkpoint).
            // For simplicity here we just emit the op and rhs as siblings under
            // the already-in-progress parent node.
            self.bump(); // operator
            self.parse_assign(); // rhs (right-assoc)
        }
    }

    fn parse_or(&mut self) {
        self.parse_and();
        while self.at(SyntaxKind::PIPE_PIPE) {
            self.bump();
            self.parse_and();
        }
    }

    fn parse_and(&mut self) {
        self.parse_bitwise_or();
        while self.at(SyntaxKind::AMP_AMP) {
            self.bump();
            self.parse_bitwise_or();
        }
    }

    fn parse_bitwise_or(&mut self) {
        self.parse_bitwise_xor();
        while self.at(SyntaxKind::PIPE) {
            self.bump();
            self.parse_bitwise_xor();
        }
    }

    fn parse_bitwise_xor(&mut self) {
        self.parse_bitwise_and();
        while self.at(SyntaxKind::CARET) {
            self.bump();
            self.parse_bitwise_and();
        }
    }

    fn parse_bitwise_and(&mut self) {
        self.parse_cmp();
        while self.at(SyntaxKind::AMP) {
            self.bump();
            self.parse_cmp();
        }
    }

    fn parse_cmp(&mut self) {
        self.parse_shift();
        while matches!(
            self.current(),
            SyntaxKind::EQ_EQ
            | SyntaxKind::BANG_EQ
            | SyntaxKind::LT
            | SyntaxKind::GT
            | SyntaxKind::LT_EQ
            | SyntaxKind::GT_EQ
            | SyntaxKind::GT_LT
            | SyntaxKind::GT_BANG_LT
            | SyntaxKind::EQ_TILDE
            | SyntaxKind::BANG_TILDE
        ) {
            self.bump();
            self.parse_shift();
        }
    }

    fn parse_shift(&mut self) {
        self.parse_add();
        while matches!(self.current(), SyntaxKind::GT_GT | SyntaxKind::LT_LT) {
            self.bump();
            self.parse_add();
        }
    }

    fn parse_add(&mut self) {
        self.parse_mul();
        while matches!(self.current(), SyntaxKind::PLUS | SyntaxKind::MINUS) {
            self.bump();
            self.parse_mul();
        }
    }

    fn parse_mul(&mut self) {
        self.parse_unary();
        while matches!(self.current(), SyntaxKind::STAR | SyntaxKind::SLASH | SyntaxKind::PERCENT) {
            self.bump();
            self.parse_unary();
        }
    }

    fn parse_unary(&mut self) {
        if matches!(
            self.current(),
            SyntaxKind::BANG | SyntaxKind::MINUS | SyntaxKind::TILDE
        ) {
            self.wrap(SyntaxKind::UNARY_EXPR, |p| {
                p.bump(); // operator
                p.parse_unary();
            });
        } else {
            self.parse_postfix();
        }
    }

    fn parse_postfix(&mut self) {
        self.parse_primary();
        loop {
            match self.current() {
                SyntaxKind::L_BRACKET => {
                    // arr[index]
                    self.wrap(SyntaxKind::INDEX_EXPR, |p| {
                        p.bump(); // [
                        p.parse_expr();
                        p.expect(SyntaxKind::R_BRACKET);
                    });
                }
                SyntaxKind::L_PAREN => {
                    // foo(args) — function call; the function name was already parsed
                    // as a primary so we wrap around it. We use builder checkpoints
                    // via a simpler inline approach: emit ARG_LIST and let the caller
                    // flatten if needed. This is an approximation; a full Pratt parser
                    // with explicit checkpoints would wrap more cleanly.
                    self.wrap(SyntaxKind::ARG_LIST, |p| {
                        p.bump(); // (
                        while !p.at(SyntaxKind::R_PAREN) && !p.at_eof() {
                            p.parse_arg();
                            if !p.eat(SyntaxKind::COMMA) {
                                break;
                            }
                        }
                        p.expect(SyntaxKind::R_PAREN);
                    });
                }
                _ => break,
            }
        }
    }

    /// One argument in a call: either `ident : expr` (named) or just `expr`.
    fn parse_arg(&mut self) {
        // Named arg: next non-trivia is IDENT, one after that is COLON
        let is_named = self.at(SyntaxKind::IDENT) && self.at_nth(1, SyntaxKind::COLON);
        if is_named {
            self.wrap(SyntaxKind::NAMED_ARG, |p| {
                p.bump(); // ident (arg name)
                p.bump(); // :
                p.parse_expr(); // value
            });
        } else {
            self.wrap(SyntaxKind::ARG, |p| {
                p.parse_expr();
            });
        }
    }

    fn parse_primary(&mut self) {
        match self.current() {
            // Literals
            SyntaxKind::INT_LIT
            | SyntaxKind::HEX_LIT
            | SyntaxKind::STRING_DOUBLE
            | SyntaxKind::STRING_SINGLE
            | SyntaxKind::KW_TRUE
            | SyntaxKind::KW_FALSE
            | SyntaxKind::KW_NULL => {
                self.wrap(SyntaxKind::LITERAL, |p| { p.bump(); });
            }

            // Identifier or function call
            SyntaxKind::IDENT => {
                self.wrap(SyntaxKind::IDENT_EXPR, |p| { p.bump(); });
            }

            // Grouped expression
            SyntaxKind::L_PAREN => {
                self.wrap(SyntaxKind::PAREN_EXPR, |p| {
                    p.bump(); // (
                    p.parse_expr();
                    p.expect(SyntaxKind::R_PAREN);
                });
            }

            // `exit` and `include` can appear as call-like expressions too
            SyntaxKind::KW_EXIT => {
                self.wrap(SyntaxKind::IDENT_EXPR, |p| { p.bump(); });
            }

            // Anything else is an error primary
            _ => {
                let k = self.current();
                self.errors.push(format!(
                    "unexpected token {:?} in expression at pos {}",
                    k, self.pos
                ));
                self.eat_trivia();
                if let Some((_, text)) = self.tokens.get(self.pos) {
                    self.builder.token(SyntaxKind::ERROR.into(), text);
                    self.pos += 1;
                }
            }
        }
    }

    // ------------------------------------------------------------------ //
    // Utility
    // ------------------------------------------------------------------ //

    fn at_eof(&self) -> bool {
        self.tokens[self.pos..].iter().all(|(k, _)| k.is_trivia())
            || self.pos >= self.tokens.len()
    }
}

// ============================================================================
// Public parse function
// ============================================================================

/// Parse `source` into a lossless CST.
///
/// The returned `SyntaxNode` is the root. `root.to_string()` always equals
/// `source` — every byte is preserved.
pub fn parse(source: &str) -> ParseResult {
    let tokens = crate::lexer::tokenize(source);
    let parser = Parser::new(tokens);
    let (node, errors) = parser.parse_source_file();
    ParseResult { root: node, errors }
}

pub struct ParseResult {
    pub root: SyntaxNode,
    pub errors: Vec<String>,
}

impl ParseResult {
    /// Verify round-trip fidelity.
    pub fn round_trips(&self, original: &str) -> bool {
        self.root.to_string() == original
    }
}
