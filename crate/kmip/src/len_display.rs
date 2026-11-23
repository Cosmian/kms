use std::fmt;

/// Length of a byte string for logs/`Display`; `None` when absent. Never shows content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ByteLen(Option<usize>);

impl fmt::Display for ByteLen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(n) => write!(f, "<{n} bytes>"),
            None => f.write_str("None"),
        }
    }
}

/// `Display` text of a byte string: its length, never its content (it may be a plaintext, a
/// key or a PIN).
pub trait LenDisplay {
    /// `<N bytes>`, or `None` for an absent optional value.
    fn len_display(&self) -> ByteLen;
}

impl LenDisplay for [u8] {
    fn len_display(&self) -> ByteLen {
        ByteLen(Some(self.len()))
    }
}

impl LenDisplay for Vec<u8> {
    fn len_display(&self) -> ByteLen {
        self.as_slice().len_display()
    }
}

impl<T: LenDisplay + ?Sized> LenDisplay for &T {
    fn len_display(&self) -> ByteLen {
        (**self).len_display()
    }
}

impl<T: LenDisplay> LenDisplay for Option<T> {
    fn len_display(&self) -> ByteLen {
        self.as_ref().map_or(ByteLen(None), LenDisplay::len_display)
    }
}

#[cfg(test)]
mod tests {
    use super::LenDisplay;

    #[test]
    fn len_display_formats_length_or_none() {
        assert_eq!(b"abc"[..].len_display().to_string(), "<3 bytes>");
        assert_eq!(vec![0_u8; 32].len_display().to_string(), "<32 bytes>");
        assert_eq!(Some(&b"ab"[..]).len_display().to_string(), "<2 bytes>");
        assert_eq!(None::<&[u8]>.len_display().to_string(), "None");
        assert_eq!(Some(vec![1_u8]).len_display().to_string(), "<1 bytes>");
    }
}
