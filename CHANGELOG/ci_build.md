## CI

- fix(nix): replace `builtins.fetchTarball` with `pkgs.fetchurl` for `.crate` sources — Nix doesn't recognize the `.crate` extension for unpacking; use `.tar.gz` name alias instead
- fix(ci): reduce `http-connections` to 8 in Nix config to mitigate macOS "Invalid multi handle" curl daemon bug
- fix(ci): skip Docker cleanup step on macOS runners in packaging workflow
