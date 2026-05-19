## Features

### Web UI

- Increase Eviden logo height in header from `h-7` to `h-16` so the "Eviden" brand text is visually larger than "Key Management System"
- Use orange Eviden logo in dark mode (for contrast) instead of the white variant
- Replace favicon with an SVG cropped to just the "E" letter from the Eviden logo (`eviden-favicon.svg`), replacing the previous unreadable full-width logo compressed to 32×32; also regenerate `eviden-favicon-32x32.png` from the new SVG

### Documentation

- Add rebranding note in `documentation/docs/index.md`: Cosmian is now Eviden
- Replace "Cosmian VM" / "Cosmian VM KMS" product references with "Eviden VM" / "Eviden VM KMS" across all documentation pages
- Fix `documentation/mkdocs.yml`: reduce nav indentation from 6-space to 4-space per nesting level (markdown_extensions and nav sections)
- Update nav labels: "Why use the Cosmian KMS" → "Why use the Eviden KMS"; "Deploying in a Cosmian Confidential VM" → "Deploying in an Eviden Confidential VM"
