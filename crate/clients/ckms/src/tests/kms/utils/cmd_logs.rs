use std::{
    io::Write,
    process::{Command, Output, Stdio},
};

/// Recover output logs from a command call `cmd` and re-inject it into stdio
pub(crate) fn recover_cmd_logs(cmd: &mut Command) -> Output {
    let output = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    std::io::stdout()
        .write_all(format!("\r\x1b[K{}", String::from_utf8_lossy(&output.stdout)).as_bytes())
        .unwrap();
    std::io::stderr()
        .write_all(format!("\r\x1b[K{}", String::from_utf8_lossy(&output.stderr)).as_bytes())
        .unwrap();
    output
}
