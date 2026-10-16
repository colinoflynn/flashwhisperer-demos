// Minimal JSON reader - enough for the constraint files in req/.
// No external crates: the whole tool builds with a bare `rustc`.

#[derive(Debug, Clone)]
#[allow(dead_code)] // Bool is parsed for completeness; these files do not use it
pub enum J {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<J>),
    Obj(Vec<(String, J)>),
}

impl J {
    pub fn get(&self, k: &str) -> Option<&J> {
        match self {
            J::Obj(m) => m.iter().find(|(n, _)| n == k).map(|(_, v)| v),
            _ => None,
        }
    }
    pub fn arr(&self) -> Option<&Vec<J>> {
        match self { J::Arr(a) => Some(a), _ => None }
    }
    pub fn str(&self) -> Option<&str> {
        match self { J::Str(s) => Some(s), _ => None }
    }
    pub fn num(&self) -> Option<f64> {
        match self { J::Num(n) => Some(*n), _ => None }
    }
    pub fn usize(&self) -> Option<usize> {
        self.num().map(|n| n as usize)
    }
    pub fn is_null(&self) -> bool { matches!(self, J::Null) }
}

pub fn parse(s: &str) -> Result<J, String> {
    let b = s.as_bytes();
    let mut i = 0usize;
    let v = val(b, &mut i)?;
    ws(b, &mut i);
    if i != b.len() { return Err(format!("trailing junk at byte {}", i)); }
    Ok(v)
}

fn ws(b: &[u8], i: &mut usize) {
    while *i < b.len() && matches!(b[*i], b' ' | b'\t' | b'\n' | b'\r') { *i += 1; }
}

fn val(b: &[u8], i: &mut usize) -> Result<J, String> {
    ws(b, i);
    if *i >= b.len() { return Err("unexpected end of input".into()); }
    match b[*i] {
        b'{' => {
            *i += 1;
            let mut m = Vec::new();
            ws(b, i);
            if b.get(*i) == Some(&b'}') { *i += 1; return Ok(J::Obj(m)); }
            loop {
                ws(b, i);
                let k = match val(b, i)? { J::Str(s) => s, _ => return Err("object key must be a string".into()) };
                ws(b, i);
                if b.get(*i) != Some(&b':') { return Err(format!("expected ':' at byte {}", i)); }
                *i += 1;
                m.push((k, val(b, i)?));
                ws(b, i);
                match b.get(*i) {
                    Some(&b',') => { *i += 1; }
                    Some(&b'}') => { *i += 1; return Ok(J::Obj(m)); }
                    _ => return Err(format!("expected ',' or '}}' at byte {}", i)),
                }
            }
        }
        b'[' => {
            *i += 1;
            let mut a = Vec::new();
            ws(b, i);
            if b.get(*i) == Some(&b']') { *i += 1; return Ok(J::Arr(a)); }
            loop {
                a.push(val(b, i)?);
                ws(b, i);
                match b.get(*i) {
                    Some(&b',') => { *i += 1; }
                    Some(&b']') => { *i += 1; return Ok(J::Arr(a)); }
                    _ => return Err(format!("expected ',' or ']' at byte {}", i)),
                }
            }
        }
        b'"' => {
            *i += 1;
            let mut s = String::new();
            loop {
                let c = *b.get(*i).ok_or("unterminated string")?;
                *i += 1;
                match c {
                    b'"' => return Ok(J::Str(s)),
                    b'\\' => {
                        let e = *b.get(*i).ok_or("unterminated escape")?;
                        *i += 1;
                        match e {
                            b'"' => s.push('"'),
                            b'\\' => s.push('\\'),
                            b'/' => s.push('/'),
                            b'b' => s.push('\u{8}'),
                            b'f' => s.push('\u{c}'),
                            b'n' => s.push('\n'),
                            b'r' => s.push('\r'),
                            b't' => s.push('\t'),
                            b'u' => {
                                let h = std::str::from_utf8(&b[*i..*i + 4]).map_err(|_| "bad u-escape")?;
                                let cp = u32::from_str_radix(h, 16).map_err(|_| "bad u-escape")?;
                                *i += 4;
                                s.push(char::from_u32(cp).unwrap_or('\u{fffd}'));
                            }
                            _ => return Err("bad escape".into()),
                        }
                    }
                    _ => s.push(c as char),
                }
            }
        }
        b't' => { expect(b, i, "true")?; Ok(J::Bool(true)) }
        b'f' => { expect(b, i, "false")?; Ok(J::Bool(false)) }
        b'n' => { expect(b, i, "null")?; Ok(J::Null) }
        _ => {
            let st = *i;
            if b[*i] == b'-' || b[*i] == b'+' { *i += 1; }
            while *i < b.len() && matches!(b[*i], b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-') { *i += 1; }
            std::str::from_utf8(&b[st..*i])
                .ok()
                .and_then(|t| t.parse::<f64>().ok())
                .map(J::Num)
                .ok_or_else(|| format!("bad number at byte {}", st))
        }
    }
}

fn expect(b: &[u8], i: &mut usize, lit: &str) -> Result<(), String> {
    if b.len() >= *i + lit.len() && &b[*i..*i + lit.len()] == lit.as_bytes() {
        *i += lit.len();
        Ok(())
    } else {
        Err(format!("expected `{}` at byte {}", lit, i))
    }
}
