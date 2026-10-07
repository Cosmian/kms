// Embeds a Windows VERSIONINFO resource (`FileDescription`, `ProductName`, `FileVersion`,
// `ProductVersion`, `CompanyName`, `LegalCopyright`, `Language`) into ckms.exe so that
// Windows Explorer's Properties > Details tab is populated. Without this, the fields
// stay empty because plain `cargo build` never emits a Windows resource section.
#[cfg_attr(not(windows), allow(clippy::unnecessary_wraps))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(windows)]
    {
        let mut res = winresource::WindowsResource::new();
        // FileVersion, ProductVersion, ProductName and FileDescription are pre-filled by
        // winresource from `package.version`, `package.name` and `package.description`.
        res.set_language(0x0409) // English (United States) — leaving this unset shows as "Language Neutral"
            .set("CompanyName", "Cosmian Tech SAS")
            .set("LegalCopyright", "Copyright © 2026 Cosmian Tech SAS")
            .set("InternalName", "ckms")
            .set("OriginalFilename", "ckms.exe");
        res.compile()?;
    }
    Ok(())
}
