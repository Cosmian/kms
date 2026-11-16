/// `Display` text of a byte string: its length, never its content (it may be a plaintext, a
/// key or a PIN).
pub(crate) trait LenDisplay {
    /// `<N bytes>`, or `None` for an absent optional value.
    fn len_display(&self) -> String;
}

impl LenDisplay for [u8] {
    fn len_display(&self) -> String {
        format!("<{} bytes>", self.len())
    }
}

impl LenDisplay for Vec<u8> {
    fn len_display(&self) -> String {
        self.as_slice().len_display()
    }
}

impl<T: LenDisplay> LenDisplay for Option<T> {
    fn len_display(&self) -> String {
        self.as_ref()
            .map_or_else(|| "None".to_owned(), LenDisplay::len_display)
    }
}
