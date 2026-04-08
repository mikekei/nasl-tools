use crate::syntax_kind::SyntaxKind;

/// Full-fidelity lexer: every byte in the input becomes part of exactly one
/// token. Whitespace, newlines, and comments are emitted as trivia tokens
/// rather than discarded. This is the foundation of lossless round-trip.
pub struct Lexer<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> Lexer<'a> {
    /// Tokenize the entire input. The returned slices are sub-slices of
    /// `input`, so no allocation of string data occurs.
    pub fn tokenize(input: &'a str) -> Vec<(SyntaxKind, &'a str)> {
        let mut lexer = Lexer { input, pos: 0 };
        let mut tokens = Vec::with_capacity(input.len() / 4);
        while lexer.pos < lexer.input.len() {
            let start = lexer.pos;
            let kind = lexer.next_token();
            tokens.push((kind, &input[start..lexer.pos]));
        }
        tokens
    }

    // ------------------------------------------------------------------ //
    // Core helpers
    // ------------------------------------------------------------------ //

    fn current(&self) -> Option<u8> {
        self.input.as_bytes().get(self.pos).copied()
    }

    fn peek_at(&self, offset: usize) -> Option<u8> {
        self.input.as_bytes().get(self.pos + offset).copied()
    }

    fn advance(&mut self) {
        // Step one UTF-8 character. For ASCII-dominant NASL source this is
        // almost always 1 byte, but we handle multi-byte correctly.
        if self.pos < self.input.len() {
            // Get the number of bytes for the current char.
            let b = self.input.as_bytes()[self.pos];
            let char_len = match b {
                0x00..=0x7F => 1,
                0xC0..=0xDF => 2,
                0xE0..=0xEF => 3,
                0xF0..=0xF7 => 4,
                _ => 1, // continuation byte or invalid — step 1 to avoid infinite loop
            };
            self.pos += char_len.min(self.input.len() - self.pos);
        }
    }

    fn advance_bytes(&mut self, n: usize) {
        self.pos = (self.pos + n).min(self.input.len());
    }

    // ------------------------------------------------------------------ //
    // Token dispatch
    // ------------------------------------------------------------------ //

    fn next_token(&mut self) -> SyntaxKind {
        match self.current() {
            Some(b'#') => self.lex_comment(),
            Some(b'\n') | Some(b'\r') => self.lex_newline(),
            Some(b' ') | Some(b'\t') => self.lex_whitespace(),
            Some(b'"') => self.lex_string_double(),
            Some(b'\'') => self.lex_string_single(),
            Some(b'0'..=b'9') => self.lex_number(),
            Some(b'a'..=b'z') | Some(b'A'..=b'Z') | Some(b'_') => self.lex_word(),
            Some(b'>') => self.lex_gt(),
            Some(b'<') => self.lex_lt(),
            Some(b'=') => self.lex_eq(),
            Some(b'!') => self.lex_bang(),
            Some(b'&') => self.lex_amp(),
            Some(b'|') => self.lex_pipe(),
            Some(b'+') => self.lex_plus(),
            Some(b'-') => self.lex_minus(),
            Some(b'*') => self.lex_star(),
            Some(b'/') => self.lex_slash(),
            Some(b'%') => self.lex_percent(),
            Some(b'(') => { self.advance(); SyntaxKind::L_PAREN }
            Some(b')') => { self.advance(); SyntaxKind::R_PAREN }
            Some(b'{') => { self.advance(); SyntaxKind::L_BRACE }
            Some(b'}') => { self.advance(); SyntaxKind::R_BRACE }
            Some(b'[') => { self.advance(); SyntaxKind::L_BRACKET }
            Some(b']') => { self.advance(); SyntaxKind::R_BRACKET }
            Some(b';') => { self.advance(); SyntaxKind::SEMICOLON }
            Some(b',') => { self.advance(); SyntaxKind::COMMA }
            Some(b':') => { self.advance(); SyntaxKind::COLON }
            Some(b'.') => { self.advance(); SyntaxKind::DOT }
            Some(b'^') => { self.advance(); SyntaxKind::CARET }
            Some(b'~') => { self.advance(); SyntaxKind::TILDE }
            // Multi-byte UTF-8 or truly unknown byte → emit as ERROR (1 byte)
            _ => { self.advance_bytes(1); SyntaxKind::ERROR }
        }
    }

    // ------------------------------------------------------------------ //
    // Trivia
    // ------------------------------------------------------------------ //

    /// `# ...` — consume everything up to (but not including) the newline.
    fn lex_comment(&mut self) -> SyntaxKind {
        while let Some(b) = self.current() {
            if b == b'\n' || b == b'\r' {
                break;
            }
            self.advance();
        }
        SyntaxKind::COMMENT
    }

    /// One logical newline: `\r\n` or bare `\n` or bare `\r`.
    fn lex_newline(&mut self) -> SyntaxKind {
        if self.current() == Some(b'\r') {
            self.advance();
            if self.current() == Some(b'\n') {
                self.advance();
            }
        } else {
            self.advance(); // \n
        }
        SyntaxKind::NEWLINE
    }

    /// One run of spaces and/or tabs (not newlines).
    fn lex_whitespace(&mut self) -> SyntaxKind {
        while matches!(self.current(), Some(b' ') | Some(b'\t')) {
            self.advance();
        }
        SyntaxKind::WHITESPACE
    }

    // ------------------------------------------------------------------ //
    // String literals
    // ------------------------------------------------------------------ //

    /// `"..."` — supports `\"` and `\\` escape sequences.
    fn lex_string_double(&mut self) -> SyntaxKind {
        self.advance(); // opening "
        loop {
            match self.current() {
                None => break, // unterminated → best-effort
                Some(b'\\') => {
                    self.advance(); // backslash
                    self.advance(); // escaped char
                }
                Some(b'"') => {
                    self.advance(); // closing "
                    break;
                }
                _ => self.advance(),
            }
        }
        SyntaxKind::STRING_DOUBLE
    }

    /// `'...'` — supports `\'` and `\\` escape sequences.
    fn lex_string_single(&mut self) -> SyntaxKind {
        self.advance(); // opening '
        loop {
            match self.current() {
                None => break,
                Some(b'\\') => {
                    self.advance();
                    self.advance();
                }
                Some(b'\'') => {
                    self.advance(); // closing '
                    break;
                }
                _ => self.advance(),
            }
        }
        SyntaxKind::STRING_SINGLE
    }

    // ------------------------------------------------------------------ //
    // Numbers
    // ------------------------------------------------------------------ //

    fn lex_number(&mut self) -> SyntaxKind {
        // Check for 0x hex prefix
        if self.current() == Some(b'0')
            && matches!(self.peek_at(1), Some(b'x') | Some(b'X'))
        {
            self.advance_bytes(2); // 0x
            while matches!(self.current(), Some(b'0'..=b'9') | Some(b'a'..=b'f') | Some(b'A'..=b'F')) {
                self.advance();
            }
            return SyntaxKind::HEX_LIT;
        }
        while matches!(self.current(), Some(b'0'..=b'9')) {
            self.advance();
        }
        SyntaxKind::INT_LIT
    }

    // ------------------------------------------------------------------ //
    // Identifiers and keywords
    // ------------------------------------------------------------------ //

    fn lex_word(&mut self) -> SyntaxKind {
        while matches!(self.current(), Some(b'a'..=b'z') | Some(b'A'..=b'Z') | Some(b'0'..=b'9') | Some(b'_')) {
            self.advance();
        }
        // We need the slice we just consumed to check for keywords.
        // The caller will reconstruct it from the start..pos range.
        // Here we use a different approach: track start manually.
        // Actually we don't have start here — we'll classify in tokenize()
        // by looking at the produced slice. But we produce the kind now.
        // Solution: peek at the bytes we already advanced past.
        // We call a separate classify step on the slice in tokenize().
        // For now return a sentinel that tokenize() will reclassify.
        SyntaxKind::IDENT // reclassified below by classify_word()
    }

    // ------------------------------------------------------------------ //
    // Operators starting with >
    // ------------------------------------------------------------------ //

    fn lex_gt(&mut self) -> SyntaxKind {
        self.advance(); // >
        match self.current() {
            Some(b'!') if self.peek_at(1) == Some(b'<') => {
                // >!<  contains-not
                self.advance_bytes(2);
                SyntaxKind::GT_BANG_LT
            }
            Some(b'<') => {
                // ><  contains
                self.advance();
                SyntaxKind::GT_LT
            }
            Some(b'=') => {
                self.advance();
                SyntaxKind::GT_EQ
            }
            Some(b'>') => {
                self.advance();
                SyntaxKind::GT_GT
            }
            _ => SyntaxKind::GT,
        }
    }

    fn lex_lt(&mut self) -> SyntaxKind {
        self.advance(); // <
        match self.current() {
            Some(b'=') => { self.advance(); SyntaxKind::LT_EQ }
            Some(b'<') => { self.advance(); SyntaxKind::LT_LT }
            _ => SyntaxKind::LT,
        }
    }

    fn lex_eq(&mut self) -> SyntaxKind {
        self.advance(); // =
        match self.current() {
            Some(b'=') => { self.advance(); SyntaxKind::EQ_EQ }
            Some(b'~') => { self.advance(); SyntaxKind::EQ_TILDE }
            _ => SyntaxKind::EQ,
        }
    }

    fn lex_bang(&mut self) -> SyntaxKind {
        self.advance(); // !
        match self.current() {
            Some(b'=') => { self.advance(); SyntaxKind::BANG_EQ }
            Some(b'~') => { self.advance(); SyntaxKind::BANG_TILDE }
            _ => SyntaxKind::BANG,
        }
    }

    fn lex_amp(&mut self) -> SyntaxKind {
        self.advance(); // &
        if self.current() == Some(b'&') {
            self.advance();
            SyntaxKind::AMP_AMP
        } else {
            SyntaxKind::AMP
        }
    }

    fn lex_pipe(&mut self) -> SyntaxKind {
        self.advance(); // |
        if self.current() == Some(b'|') {
            self.advance();
            SyntaxKind::PIPE_PIPE
        } else {
            SyntaxKind::PIPE
        }
    }

    fn lex_plus(&mut self) -> SyntaxKind {
        self.advance(); // +
        match self.current() {
            Some(b'=') => { self.advance(); SyntaxKind::PLUS_EQ }
            Some(b'+') => { self.advance(); SyntaxKind::PLUS_PLUS }
            _ => SyntaxKind::PLUS,
        }
    }

    fn lex_minus(&mut self) -> SyntaxKind {
        self.advance(); // -
        match self.current() {
            Some(b'=') => { self.advance(); SyntaxKind::MINUS_EQ }
            Some(b'-') => { self.advance(); SyntaxKind::MINUS_MINUS }
            _ => SyntaxKind::MINUS,
        }
    }

    fn lex_star(&mut self) -> SyntaxKind {
        self.advance(); // *
        if self.current() == Some(b'=') {
            self.advance();
            SyntaxKind::STAR_EQ
        } else {
            SyntaxKind::STAR
        }
    }

    fn lex_slash(&mut self) -> SyntaxKind {
        self.advance(); // /
        if self.current() == Some(b'=') {
            self.advance();
            SyntaxKind::SLASH_EQ
        } else {
            SyntaxKind::SLASH
        }
    }

    fn lex_percent(&mut self) -> SyntaxKind {
        self.advance(); // %
        if self.current() == Some(b'=') {
            self.advance();
            SyntaxKind::PERCENT_EQ
        } else {
            SyntaxKind::PERCENT
        }
    }
}

/// Classify an identifier slice as a keyword or plain IDENT.
pub fn classify_word(s: &str) -> SyntaxKind {
    match s {
        "if"         => SyntaxKind::KW_IF,
        "else"       => SyntaxKind::KW_ELSE,
        "for"        => SyntaxKind::KW_FOR,
        "foreach"    => SyntaxKind::KW_FOREACH,
        "while"      => SyntaxKind::KW_WHILE,
        "repeat"     => SyntaxKind::KW_REPEAT,
        "until"      => SyntaxKind::KW_UNTIL,
        "return"     => SyntaxKind::KW_RETURN,
        "break"      => SyntaxKind::KW_BREAK,
        "continue"   => SyntaxKind::KW_CONTINUE,
        "exit"       => SyntaxKind::KW_EXIT,
        "include"    => SyntaxKind::KW_INCLUDE,
        "function"   => SyntaxKind::KW_FUNCTION,
        "local_var"  => SyntaxKind::KW_LOCAL_VAR,
        "global_var" => SyntaxKind::KW_GLOBAL_VAR,
        "TRUE"       => SyntaxKind::KW_TRUE,
        "FALSE"      => SyntaxKind::KW_FALSE,
        "NULL"       => SyntaxKind::KW_NULL,
        _            => SyntaxKind::IDENT,
    }
}

/// Public entry point: lex `input` and reclassify word tokens as keywords.
pub fn tokenize(input: &str) -> Vec<(SyntaxKind, &str)> {
    let mut tokens = Lexer::tokenize(input);
    for (kind, text) in tokens.iter_mut() {
        if *kind == SyntaxKind::IDENT {
            *kind = classify_word(text);
        }
    }
    tokens
}
