//! Offline static TLS geometry inspection; does not admit TLS-bearing artifacts.

use troe_application::static_tls::StaticTlsLayout;

use crate::{Arguments, ToolError, ToolResult, parse_target, target_name};

pub(crate) fn execute(arguments: &mut Arguments) -> ToolResult<()> {
    let mut target = None;
    let mut file_bytes = None;
    let mut memory_bytes = None;
    let mut alignment = None;
    let mut max_pages = None;
    while let Some(option) = arguments.next() {
        let Some(option) = option.to_str() else {
            return Err(ToolError::new("TLS layout option must be valid UTF-8"));
        };
        let field = match option {
            "--target" if target.is_none() => {
                target = Some(parse_target(&arguments.string(option)?)?);
                continue;
            }
            "--file-bytes" => &mut file_bytes,
            "--memory-bytes" => &mut memory_bytes,
            "--alignment" => &mut alignment,
            "--max-pages" => &mut max_pages,
            _ => {
                return Err(ToolError::new(format!(
                    "unknown or repeated TLS option {option}"
                )));
            }
        };
        if field.replace(arguments.number(option)?).is_some() {
            return Err(ToolError::new(format!("repeated TLS option {option}")));
        }
    }
    let target = target.ok_or_else(|| ToolError::new("missing --target"))?;
    let required =
        |value: Option<u64>, name| value.ok_or_else(|| ToolError::new(format!("missing {name}")));
    let alignment = required(alignment, "--alignment")?;
    let layout = StaticTlsLayout::new(
        target,
        required(file_bytes, "--file-bytes")?,
        required(memory_bytes, "--memory-bytes")?,
        alignment,
        required(max_pages, "--max-pages")?,
    )
    .map_err(|error| ToolError::new(error.to_string()))?;
    println!(
        "{{\"target\":\"{}\",\"file_bytes\":{},\"memory_bytes\":{},\"alignment\":{},\"mapping_alignment\":{},\"template_offset\":{},\"thread_pointer_offset\":{},\"mapped_bytes\":{},\"pages\":{}}}",
        target_name(target),
        layout.file_bytes(),
        layout.memory_bytes(),
        alignment,
        layout.mapping_alignment(),
        layout.template_offset(),
        layout.thread_pointer_offset(),
        layout.mapped_bytes(),
        layout.pages(),
    );
    Ok(())
}
