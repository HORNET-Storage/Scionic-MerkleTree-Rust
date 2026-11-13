//! A small JSON tree for forging wire input in tests: parse, edit, write.
//!
//! Numbers keep their source text and objects keep their member order, so a
//! value that is parsed and written back differs from its source only in
//! whitespace and in how strings are escaped. Malformed input panics: this
//! reads what the crate itself wrote.

#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Number(String),
    Text(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

impl Json {
    pub fn parse(input: &[u8]) -> Json {
        let mut parser = Parser {
            bytes: input,
            at: 0,
        };
        let value = parser.value();
        parser.skip_space();
        assert_eq!(parser.at, input.len(), "JSON: bytes after the value");
        value
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = String::new();
        self.write(&mut out);
        out.into_bytes()
    }

    /// An object's members, in their order.
    pub fn members(&self) -> &[(String, Json)] {
        match self {
            Json::Object(members) => members,
            other => panic!("JSON: not an object: {other:?}"),
        }
    }

    /// An array's items.
    pub fn items(&self) -> &[Json] {
        match self {
            Json::Array(items) => items,
            other => panic!("JSON: not an array: {other:?}"),
        }
    }

    pub fn items_mut(&mut self) -> &mut Vec<Json> {
        match self {
            Json::Array(items) => items,
            other => panic!("JSON: not an array: {other:?}"),
        }
    }

    pub fn text(&self) -> &str {
        match self {
            Json::Text(text) => text,
            other => panic!("JSON: not a string: {other:?}"),
        }
    }

    pub fn has(&self, key: &str) -> bool {
        self.members().iter().any(|(name, _)| name == key)
    }

    pub fn get(&self, key: &str) -> &Json {
        self.members()
            .iter()
            .find_map(|(name, value)| (name == key).then_some(value))
            .unwrap_or_else(|| panic!("JSON: no member {key}"))
    }

    pub fn get_mut(&mut self, key: &str) -> &mut Json {
        match self {
            Json::Object(members) => members
                .iter_mut()
                .find_map(|(name, value)| (name == key).then_some(value))
                .unwrap_or_else(|| panic!("JSON: no member {key}")),
            other => panic!("JSON: not an object: {other:?}"),
        }
    }

    /// Replace a member, or add it after the others.
    pub fn set(&mut self, key: &str, value: Json) {
        let Json::Object(members) = self else {
            panic!("JSON: not an object: {self:?}");
        };
        match members.iter_mut().find(|(name, _)| name == key) {
            Some((_, existing)) => *existing = value,
            None => members.push((key.to_owned(), value)),
        }
    }

    pub fn remove(&mut self, key: &str) -> Json {
        let Json::Object(members) = self else {
            panic!("JSON: not an object: {self:?}");
        };
        let at = members
            .iter()
            .position(|(name, _)| name == key)
            .unwrap_or_else(|| panic!("JSON: no member {key}"));
        members.remove(at).1
    }

    /// Add an item to the end of an array.
    pub fn push(&mut self, value: Json) {
        self.items_mut().push(value);
    }

    fn write(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(true) => out.push_str("true"),
            Json::Bool(false) => out.push_str("false"),
            Json::Number(text) => out.push_str(text),
            Json::Text(text) => write_text(text, out),
            Json::Array(items) => {
                out.push('[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    item.write(out);
                }
                out.push(']');
            }
            Json::Object(members) => {
                out.push('{');
                for (index, (name, value)) in members.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    write_text(name, out);
                    out.push(':');
                    value.write(out);
                }
                out.push('}');
            }
        }
    }
}

fn write_text(text: &str, out: &mut String) {
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            control if (control as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", control as u32));
            }
            other => out.push(other),
        }
    }
    out.push('"');
}

struct Parser<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Parser<'_> {
    fn peek(&self) -> u8 {
        *self
            .bytes
            .get(self.at)
            .unwrap_or_else(|| panic!("JSON: input ends at byte {}", self.at))
    }

    fn take(&mut self) -> u8 {
        let byte = self.peek();
        self.at += 1;
        byte
    }

    fn expect(&mut self, byte: u8) {
        let found = self.take();
        assert_eq!(
            found as char, byte as char,
            "JSON: unexpected byte before byte {}",
            self.at
        );
    }

    fn skip_space(&mut self) {
        while matches!(self.bytes.get(self.at), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    fn literal(&mut self, word: &str) {
        for byte in word.bytes() {
            self.expect(byte);
        }
    }

    fn value(&mut self) -> Json {
        self.skip_space();
        match self.peek() {
            b'n' => {
                self.literal("null");
                Json::Null
            }
            b't' => {
                self.literal("true");
                Json::Bool(true)
            }
            b'f' => {
                self.literal("false");
                Json::Bool(false)
            }
            b'"' => Json::Text(self.string()),
            b'[' => {
                self.at += 1;
                let mut items = Vec::new();
                self.skip_space();
                if self.peek() == b']' {
                    self.at += 1;
                    return Json::Array(items);
                }
                loop {
                    items.push(self.value());
                    self.skip_space();
                    match self.take() {
                        b',' => {}
                        b']' => return Json::Array(items),
                        other => panic!("JSON: {:?} inside an array", other as char),
                    }
                }
            }
            b'{' => {
                self.at += 1;
                let mut members = Vec::new();
                self.skip_space();
                if self.peek() == b'}' {
                    self.at += 1;
                    return Json::Object(members);
                }
                loop {
                    self.skip_space();
                    let name = self.string();
                    self.skip_space();
                    self.expect(b':');
                    members.push((name, self.value()));
                    self.skip_space();
                    match self.take() {
                        b',' => {}
                        b'}' => return Json::Object(members),
                        other => panic!("JSON: {:?} inside an object", other as char),
                    }
                }
            }
            _ => {
                let start = self.at;
                while matches!(
                    self.bytes.get(self.at),
                    Some(b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
                ) {
                    self.at += 1;
                }
                assert!(self.at > start, "JSON: unexpected byte at {start}");
                Json::Number(
                    std::str::from_utf8(&self.bytes[start..self.at])
                        .expect("digits are ASCII")
                        .to_owned(),
                )
            }
        }
    }

    fn string(&mut self) -> String {
        self.expect(b'"');
        let mut out = String::new();
        loop {
            // A quote and a backslash are ASCII, and no byte of a longer UTF-8
            // sequence is, so a run ends on a character boundary.
            let start = self.at;
            while !matches!(self.peek(), b'"' | b'\\') {
                self.at += 1;
            }
            out.push_str(
                std::str::from_utf8(&self.bytes[start..self.at]).expect("JSON strings are UTF-8"),
            );
            if self.take() == b'"' {
                return out;
            }
            match self.take() {
                b'"' => out.push('"'),
                b'\\' => out.push('\\'),
                b'/' => out.push('/'),
                b'b' => out.push('\u{8}'),
                b'f' => out.push('\u{c}'),
                b'n' => out.push('\n'),
                b'r' => out.push('\r'),
                b't' => out.push('\t'),
                b'u' => {
                    let first = self.hex4();
                    let code = if (0xD800..0xDC00).contains(&first) {
                        self.expect(b'\\');
                        self.expect(b'u');
                        0x10000 + ((first - 0xD800) << 10) + (self.hex4() - 0xDC00)
                    } else {
                        first
                    };
                    out.push(char::from_u32(code).expect("JSON: a valid \\u escape"));
                }
                other => panic!("JSON: unknown escape {:?}", other as char),
            }
        }
    }

    fn hex4(&mut self) -> u32 {
        let digits = std::str::from_utf8(&self.bytes[self.at..self.at + 4]).expect("hex is ASCII");
        self.at += 4;
        u32::from_str_radix(digits, 16).expect("JSON: four hex digits")
    }
}
