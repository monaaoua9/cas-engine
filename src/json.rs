use std::fmt::Write;

/// Just enough JSON to print command results; there is no parser.
#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Int(i64),
    Uint(u64),
    Float(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl From<bool> for Json {
    fn from(v: bool) -> Self {
        Json::Bool(v)
    }
}
impl From<u64> for Json {
    fn from(v: u64) -> Self {
        Json::Uint(v)
    }
}
impl From<u32> for Json {
    fn from(v: u32) -> Self {
        Json::Uint(v as u64)
    }
}
impl From<usize> for Json {
    fn from(v: usize) -> Self {
        Json::Uint(v as u64)
    }
}
impl From<i64> for Json {
    fn from(v: i64) -> Self {
        Json::Int(v)
    }
}
impl From<f64> for Json {
    fn from(v: f64) -> Self {
        Json::Float(v)
    }
}
impl From<&str> for Json {
    fn from(v: &str) -> Self {
        Json::Str(v.to_string())
    }
}
impl From<String> for Json {
    fn from(v: String) -> Self {
        Json::Str(v)
    }
}
impl<T: Into<Json>> From<Vec<T>> for Json {
    fn from(v: Vec<T>) -> Self {
        Json::Arr(v.into_iter().map(Into::into).collect())
    }
}

/// `obj([("a", 1u64.into()), ...])`
pub fn obj<const N: usize>(pairs: [(&str, Json); N]) -> Json {
    Json::Obj(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

fn escape(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

impl Json {
    pub fn render(&self) -> String {
        let mut s = String::new();
        self.write(&mut s);
        s
    }

    fn write(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Json::Int(n) => {
                let _ = write!(out, "{n}");
            }
            Json::Uint(n) => {
                let _ = write!(out, "{n}");
            }
            // JSON has no NaN or infinity
            Json::Float(f) if !f.is_finite() => out.push_str("null"),
            Json::Float(f) => {
                let _ = write!(out, "{f}");
            }
            Json::Str(s) => escape(s, out),
            Json::Arr(a) => {
                out.push('[');
                for (i, v) in a.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    v.write(out);
                }
                out.push(']');
            }
            Json::Obj(o) => {
                out.push('{');
                for (i, (k, v)) in o.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    escape(k, out);
                    out.push(':');
                    v.write(out);
                }
                out.push('}');
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalars() {
        assert_eq!(Json::Null.render(), "null");
        assert_eq!(Json::from(true).render(), "true");
        assert_eq!(Json::from(-5i64).render(), "-5");
        assert_eq!(Json::from(u64::MAX).render(), "18446744073709551615");
        assert_eq!(Json::from(1.5f64).render(), "1.5");
        assert_eq!(Json::from(f64::NAN).render(), "null");
        assert_eq!(Json::from(f64::INFINITY).render(), "null");
    }

    #[test]
    fn strings_are_escaped() {
        let s = Json::from("a\"b\\c\nd\te\u{1}f/é").render();
        assert_eq!(s, "\"a\\\"b\\\\c\\nd\\te\\u0001f/é\"");
    }

    #[test]
    fn nested() {
        let j = obj([
            ("name", "x".into()),
            ("sizes", vec![1u64, 2, 3].into()),
            ("inner", obj([("ok", true.into()), ("none", Json::Null)])),
            ("empty", Json::Arr(vec![])),
        ]);
        assert_eq!(j.render(), r#"{"name":"x","sizes":[1,2,3],"inner":{"ok":true,"none":null},"empty":[]}"#);
    }

    #[test]
    fn keys_are_escaped_too() {
        assert_eq!(obj([("a\"b", 1u64.into())]).render(), r#"{"a\"b":1}"#);
    }
}
