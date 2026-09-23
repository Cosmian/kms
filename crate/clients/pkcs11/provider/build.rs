// Embeds a Windows VERSIONINFO resource in cosmian_pkcs11.dll (Explorer Properties > Details tab).
#[cfg_attr(not(windows), allow(clippy::unnecessary_wraps))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(windows)]
    {
        let mut res = winresource::WindowsResource::new();
        // FileVersion, ProductVersion and FileDescription are pre-filled by winresource
        // from `package.version` and `package.description`.
        res.set_version_info(winresource::VersionInfo::FILETYPE, 2) // VFT_DLL
            .set_language(0x0409) // English (United States) — leaving this unset shows as "Language Neutral"
            .set("ProductName", "Cosmian KMS PKCS#11 Provider")
            .set("CompanyName", "Cosmian Tech SAS")
            .set("LegalCopyright", "Copyright © 2026 Cosmian Tech SAS")
            .set("InternalName", "cosmian_pkcs11")
            .set("OriginalFilename", "cosmian_pkcs11.dll");
        res.compile()?;
    }
    Ok(())
}
