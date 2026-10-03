//! Compiles protobuf definitions, tolerating what dumped protocols get wrong.
//!
//! Dumps of the game's protocol (e.g. `dump.proto`) also carry the client's
//! non-protocol enums, which can be `uint`/`ulong` backed and so hold values
//! a protobuf enum cannot. The definitions are cleaned up in memory before
//! compiling; the file on disk is never changed.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use anyhow::Result;
use prost_reflect::DescriptorPool;
use protox::Compiler;
use protox::file::{ChainFileResolver, File, FileResolver, GoogleFileResolver, IncludeFileResolver};

/// Compiles the definitions at `path`, with `include` as the import path.
pub fn compile(path: &Path, include: &Path) -> Result<DescriptorPool> {
    let name = path.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("all.proto")
        .to_string();

    let source = std::fs::read_to_string(path)?;
    let (source, fixes) = sanitize(&source);
    if fixes > 0 {
        info!("Adjusted {} enum value(s) that protobuf cannot represent.", fixes);
    }

    let mut resolver = ChainFileResolver::new();
    resolver.add(SourceResolver { name: name.clone(), source });
    resolver.add(IncludeFileResolver::new(PathBuf::from(include)));
    resolver.add(GoogleFileResolver::new());

    let mut compiler = Compiler::with_file_resolver(resolver);
    compiler.include_source_info(false);
    compiler.open_file(&name)?;

    Ok(compiler.descriptor_pool())
}

/// Serves the cleaned-up main file from memory.
struct SourceResolver {
    name: String,
    source: String,
}

impl FileResolver for SourceResolver {
    fn open_file(&self, name: &str) -> Result<File, protox::Error> {
        if name == self.name {
            File::from_source(name, &self.source)
        } else {
            Err(protox::Error::file_not_found(name))
        }
    }
}

/// Makes every enum valid proto3:
///
/// - values in `(i32::MAX, u32::MAX]` wrap to the `int32` they are on the wire,
/// - values that do not fit 32 bits, or repeat a value, are commented out,
/// - the zero value comes first, and is added when missing.
///
/// Returns the new source and how many values were changed.
fn sanitize(source: &str) -> (String, usize) {
    let mut output = String::with_capacity(source.len());
    let mut fixes = 0;

    // The enum being read: its name and its member lines.
    let mut current: Option<(String, Vec<String>)> = None;

    for line in source.lines() {
        let trimmed = line.trim();

        match &mut current {
            None => {
                output.push_str(line);
                output.push('\n');

                // `enum Name {`, possibly followed by a comment.
                let code = trimmed.split("//").next().unwrap_or_default().trim();
                if let Some(rest) = code.strip_prefix("enum ") {
                    if let Some(name) = rest.strip_suffix('{') {
                        current = Some((name.trim().to_string(), Vec::new()));
                    }
                }
            },
            Some((name, members)) => {
                if trimmed != "}" {
                    members.push(line.to_string());
                    continue;
                }

                fixes += write_enum(&mut output, name, members);
                output.push_str(line);
                output.push('\n');
                current = None;
            }
        }
    }

    (output, fixes)
}

/// Writes the members of one enum. Returns how many values were changed.
fn write_enum(output: &mut String, name: &str, members: &[String]) -> usize {
    let mut fixes = 0;
    let mut seen = HashSet::new();
    let mut kept = Vec::new();

    for line in members {
        let Some((value, rewrite)) = parse_value(line) else {
            // Options, comments and blank lines stay as they are.
            kept.push((None, line.clone()));
            continue;
        };

        let wrapped = match i32::try_from(value) {
            Ok(value) => Some(value),
            Err(_) => u32::try_from(value).ok().map(|value| value as i32),
        };

        match wrapped {
            Some(wrapped) if seen.insert(wrapped) => {
                if wrapped as i128 != value {
                    fixes += 1;
                }
                kept.push((Some(wrapped), rewrite(wrapped)));
            },
            _ => {
                fixes += 1;
                kept.push((None, format!("  // {}", line.trim())));
            }
        }
    }

    // proto3 wants the zero value first.
    match kept.iter().position(|(value, _)| *value == Some(0)) {
        Some(index) => {
            let zero = kept.remove(index);
            kept.insert(0, zero);
        },
        None => {
            fixes += 1;
            kept.insert(0, (Some(0), format!("  {name}__ZERO = 0;")));
        }
    }

    for (_, line) in kept {
        output.push_str(&line);
        output.push('\n');
    }

    fixes
}

/// Parses an enum member line (`NAME = VALUE;`, maybe with options).
///
/// Returns its value and a function that rewrites the line with another value.
fn parse_value(line: &str) -> Option<(i128, impl Fn(i32) -> String + '_)> {
    let (left, right) = line.split_once('=')?;
    let end = right.find(|c: char| c == ';' || c == '[')?;
    let value = right[..end].trim().parse::<i128>().ok()?;

    let rest = &right[end..];
    let gap = if rest.starts_with('[') { " " } else { "" };

    Some((value, move |value: i32| format!("{left}= {value}{gap}{rest}")))
}
