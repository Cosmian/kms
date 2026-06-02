# Changelog (develop)

## Bug Fixes

- Fix server panic on Windows when rolling log directory is not writable by standard users — gracefully disable file logging with a warning instead of panicking
- Fix Windows service not starting: installer now passes `-c kms.toml` in the service `binPath` and creates required ProgramData directories
- Change default Windows rolling log directory from `C:\ProgramData\Cosmian KMS Server\logs` to `%LOCALAPPDATA%\Cosmian KMS Server` (guaranteed writable)

## Features

- Server and ckms wizards now create directories recursively when paths are entered by the user (covers macOS, Windows, and Linux)
- Windows NSIS installer creates `C:\ProgramData\Cosmian KMS Server\{logs,data}` for service use and cleans them on uninstall

## Documentation

- Update logging documentation to reflect the new Windows default log directory and document the graceful fallback behavior
