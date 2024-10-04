use std::{fmt::Write, fs::File, io::Write as io_Write, path::PathBuf};

use clap::{builder::StyledStr, Command, Parser};

use crate::error::result::CliResult;

/// Generate the CLI documentation as markdown
#[derive(Parser, Debug)]
pub struct MarkdownAction {
    /// The file to export the markdown to
    #[clap(required = true)]
    markdown_file: PathBuf,
}

impl MarkdownAction {
    /// Process the given command and generate the markdown documentation.
    ///
    /// # Errors
    ///
    /// Returns an error if there is an issue creating or writing to the markdown file.
    #[allow(clippy::print_stdout)]
    pub fn process(&self, cmd: &Command) -> CliResult<()> {
        let mut output = String::new();
        writeln!(
            output,
            "*-- This file is auto-generated using the `ckms markdown` command. --*"
        )?;
        writeln!(output)?;
        write_command(&mut output, "", "", cmd)?;
        let mut f = File::create(&self.markdown_file)?;
        f.write_all(output.as_bytes())?;
        println!("Markdown generated to {:?}", &self.markdown_file);
        Ok(())
    }
}

fn write_command(out: &mut dyn Write, index: &str, parent: &str, cmd: &Command) -> CliResult<()> {
    if !parent.is_empty() {
        writeln!(out, "---")?;
        writeln!(out)?;
    }
    let full_command = if parent.is_empty() {
        "ckms".to_owned()
    } else {
        format!("{} {}", parent, cmd.get_name())
    };
    writeln!(out, "## {index} {full_command}")?;

    if let Some(about) = cmd.get_about() {
        writeln!(out)?;
        to_md(out, about)?;
        writeln!(out)?;
    }

    writeln!(out, "### Usage")?;
    write!(out, "`{full_command}")?;
    if cmd.has_subcommands() {
        write!(out, " <subcommand>")?;
    }
    if cmd.get_arguments().next().is_some() {
        write!(out, " [options]")?;
    }
    for pos in cmd.get_positionals() {
        writeln!(out, " {pos}")?;
    }
    writeln!(out, "`")?;

    for (i, arg) in cmd.get_arguments().enumerate() {
        if i == 0 {
            writeln!(out, "### Arguments")?;
        }
        write!(out, "`")?;
        if let Some(long) = arg.get_long() {
            write!(out, "--{long}")?;
        }
        if let Some(short) = arg.get_short() {
            write!(out, " [-{short}]")?;
        }
        if let Some(n) = arg.get_value_names() {
            if let Some(n) = n.first() {
                write!(out, " <{n}>")?;
            }
        }
        write!(out, "`")?;
        if let Some(help) = arg.get_help() {
            write!(out, " ")?;
            to_md(out, help)?;
        }
        if !arg.get_possible_values().is_empty() {
            writeln!(out)?;
            write!(out, "Possible values:  `")?;
            for (i, pv) in arg.get_possible_values().iter().enumerate() {
                if i > 0 {
                    write!(out, ", ")?;
                }
                write!(out, "{:?}", pv.get_name())?;
            }
            write!(out, "`")?;
            let default_values = arg.get_default_values();
            if !default_values.is_empty() {
                write!(out, " [default: `")?;
                for (i, default_value) in default_values.iter().enumerate() {
                    if i > 0 {
                        write!(out, ", ")?;
                    }
                    write!(out, "{default_value:?}")?;
                }
                write!(out, "`]")?;
            }
            writeln!(out)?;
        }
        writeln!(out)?;
    }

    writeln!(out)?;
    let sub_commands = write_subcommands(out, index, &full_command, cmd)?;
    for (i, sub_command) in sub_commands.into_iter().enumerate() {
        let index = if index.is_empty() {
            format!("{}", i + 1)
        } else {
            format!("{}.{}", index, i + 1)
        };
        write_command(out, &index, &full_command, sub_command)?;
    }
    writeln!(out)?;
    Ok(())
}

fn write_subcommands<'a>(
    write: &mut dyn Write,
    parent_index: &str,
    parent_command: &str,
    cmd: &'a Command,
) -> CliResult<Vec<&'a Command>> {
    let mut sc = Vec::new();
    for (i, sub_command) in cmd.get_subcommands().enumerate() {
        if i == 0 {
            writeln!(write, "### Subcommands")?;
            writeln!(write)?;
        }
        let index = if parent_index.is_empty() {
            format!("{}", i + 1)
        } else {
            format!("{}.{}", parent_index, i + 1)
        };
        let full_command = if parent_command.is_empty() {
            sub_command.get_name().to_string()
        } else {
            format!("{} {}", parent_command, sub_command.get_name())
        };
        let sub_command_anchor = format!("{index} {full_command}")
            .to_lowercase()
            .replace(' ', "-")
            .replace('.', "");
        write!(write, "**`{}`**", sub_command.get_name())?;
        write!(write, " [[{index}]](#{sub_command_anchor}) ")?;
        if let Some(about) = sub_command.get_about() {
            write!(write, " ")?;
            to_md(write, about)?;
        }
        writeln!(write)?;
        sc.push(sub_command);
    }
    Ok(sc)
}

fn to_md(out: &mut dyn Write, ss: &StyledStr) -> CliResult<()> {
    let s = ss.to_string();
    let split = s.split('\n');
    let mut in_list = false;
    for line in split {
        if in_list {
            if line.trim().starts_with('-') {
                // still in list
                writeln!(out, "{line}")?;
            } else {
                // no more in list
                in_list = false;
                writeln!(out)?;
                writeln!(out, "{line}")?;
            }
        } else if line.trim().starts_with('-') {
            // first line of list
            in_list = true;
            writeln!(out)?;
            writeln!(out, "{line}")?;
        } else {
            // still not in list
            writeln!(out, "{line}")?;
        }
    }
    Ok(())
}
