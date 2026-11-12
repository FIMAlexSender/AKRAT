use pulldown_cmark::{Alignment, CodeBlockKind, Event, Options, Parser, Tag, TagEnd};

pub const MAX_MARKDOWN_BYTES: usize = 256 * 1024;
pub const MAX_MARKDOWN_EVENTS: usize = 20_000;
pub const MAX_MARKDOWN_DEPTH: usize = 64;
pub const MAX_LINK_BYTES: usize = 2_048;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MarkdownNode {
    pub kind: MarkdownNodeKind,
    pub children: Vec<MarkdownNode>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MarkdownNodeKind {
    Document,
    Paragraph,
    Heading(u8),
    Quote,
    CodeBlock(Option<String>),
    List(Option<u64>),
    Item,
    Table(Vec<TableAlignment>),
    TableHead,
    TableRow,
    TableCell,
    Emphasis,
    Strong,
    Underline,
    Strike,
    Spoiler,
    Link(Option<String>),
    Text(String),
    InlineCode(String),
    SoftBreak,
    HardBreak,
    Rule,
    Task(bool),
    Unsupported,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TableAlignment {
    None,
    Left,
    Center,
    Right,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MarkdownError {
    TooLarge,
    TooComplex,
}

impl std::fmt::Display for MarkdownError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge => f.write_str("Markdown exceeds the size limit"),
            Self::TooComplex => f.write_str("Markdown exceeds parsing limits"),
        }
    }
}

impl std::error::Error for MarkdownError {}

pub fn parse_markdown(source: &str) -> Result<MarkdownNode, MarkdownError> {
    if source.len() > MAX_MARKDOWN_BYTES {
        return Err(MarkdownError::TooLarge);
    }
    let mut options = Options::empty();
    options.insert(Options::ENABLE_TABLES);
    options.insert(Options::ENABLE_STRIKETHROUGH);
    options.insert(Options::ENABLE_TASKLISTS);
    options.insert(Options::ENABLE_GFM);

    let mut root = MarkdownNode {
        kind: MarkdownNodeKind::Document,
        children: Vec::new(),
    };
    let mut stack: Vec<MarkdownNode> = Vec::new();
    let mut events = 0usize;
    let prepared = protect_custom_markers(source);
    for event in Parser::new_ext(&prepared, options) {
        events = events.saturating_add(1);
        if events > MAX_MARKDOWN_EVENTS {
            return Err(MarkdownError::TooComplex);
        }
        match event {
            Event::Start(tag) => {
                if stack.len() >= MAX_MARKDOWN_DEPTH {
                    return Err(MarkdownError::TooComplex);
                }
                stack.push(MarkdownNode {
                    kind: map_tag(tag),
                    children: Vec::new(),
                });
            }
            Event::End(tag_end) => {
                let Some(node) = stack.pop() else {
                    return Err(MarkdownError::TooComplex);
                };
                if !tag_matches(&node.kind, tag_end) {
                    return Err(MarkdownError::TooComplex);
                }
                append_node(&mut root, &mut stack, node);
            }
            Event::Text(text) => append_leaf(
                &mut root,
                &mut stack,
                MarkdownNodeKind::Text(text.into_string()),
            ),
            Event::Code(text) => append_leaf(
                &mut root,
                &mut stack,
                MarkdownNodeKind::InlineCode(text.into_string()),
            ),
            Event::Html(text) | Event::InlineHtml(text) => {
                append_leaf(
                    &mut root,
                    &mut stack,
                    MarkdownNodeKind::Text(text.into_string()),
                );
            }
            Event::FootnoteReference(text) => {
                append_leaf(
                    &mut root,
                    &mut stack,
                    MarkdownNodeKind::Text(text.into_string()),
                );
            }
            Event::SoftBreak => append_leaf(&mut root, &mut stack, MarkdownNodeKind::SoftBreak),
            Event::HardBreak => append_leaf(&mut root, &mut stack, MarkdownNodeKind::HardBreak),
            Event::Rule => append_leaf(&mut root, &mut stack, MarkdownNodeKind::Rule),
            Event::TaskListMarker(checked) => {
                append_leaf(&mut root, &mut stack, MarkdownNodeKind::Task(checked));
            }
            _ => append_leaf(&mut root, &mut stack, MarkdownNodeKind::Unsupported),
        }
    }
    if !stack.is_empty() {
        return Err(MarkdownError::TooComplex);
    }
    apply_custom_markers(&mut root.children, 0, &mut events)?;
    Ok(root)
}

fn protect_custom_markers(source: &str) -> String {
    let mut output = String::with_capacity(source.len());
    let mut fence: Option<(u8, usize)> = None;
    for line in source.split_inclusive('\n') {
        if let Some((marker, length)) = fence {
            output.push_str(line);
            if fence_marker(line).is_some_and(|(candidate, count, closing)| {
                closing && candidate == marker && count >= length
            }) {
                fence = None;
            }
            continue;
        }
        if let Some((marker, length, closing)) = fence_marker(line) {
            output.push_str(line);
            if !closing {
                fence = Some((marker, length));
            }
            continue;
        }
        output.push_str(&protect_inline_markers(line));
    }
    output
}

fn fence_marker(line: &str) -> Option<(u8, usize, bool)> {
    let bytes = line.as_bytes();
    let mut index = 0;
    while index < bytes.len() && bytes[index] == b' ' && index < 4 {
        index += 1;
    }
    if index > 3 || index >= bytes.len() || !matches!(bytes[index], b'`' | b'~') {
        return None;
    }
    let marker = bytes[index];
    let start = index;
    while index < bytes.len() && bytes[index] == marker {
        index += 1;
    }
    let length = index - start;
    if length < 3 {
        return None;
    }
    let closing = bytes[index..].iter().all(|byte| byte.is_ascii_whitespace());
    Some((marker, length, closing))
}

fn protect_inline_markers(line: &str) -> String {
    let bytes = line.as_bytes();
    let mut output = String::with_capacity(line.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'`' {
            let start = index;
            while index < bytes.len() && bytes[index] == b'`' {
                index += 1;
            }
            let ticks = index - start;
            if let Some(end) = find_backtick_close(bytes, index, ticks) {
                output.push_str(&line[start..end]);
                index = end;
            } else {
                output.push_str(&line[start..index]);
            }
            continue;
        }
        let delimiter = if bytes[index..].starts_with(b"__")
            && (index == 0 || bytes[index - 1] != b'_')
            && (index + 2 == bytes.len() || bytes[index + 2] != b'_')
        {
            Some((b"__".as_slice(), '\u{e000}', '\u{e001}'))
        } else if bytes[index..].starts_with(b"||") {
            Some((b"||".as_slice(), '\u{e002}', '\u{e003}'))
        } else {
            None
        };
        if let Some((delimiter, opening, closing)) = delimiter
            && let Some(end) = find_unescaped_delimiter(bytes, index + delimiter.len(), delimiter)
        {
            output.push(opening);
            output.push_str(&line[index + delimiter.len()..end]);
            output.push(closing);
            index = end + delimiter.len();
        } else {
            let character = line[index..]
                .chars()
                .next()
                .expect("valid character boundary");
            output.push(character);
            index += character.len_utf8();
        }
    }
    output
}

fn find_backtick_close(bytes: &[u8], mut index: usize, ticks: usize) -> Option<usize> {
    while index < bytes.len() {
        if bytes[index] != b'`' {
            index += 1;
            continue;
        }
        let start = index;
        while index < bytes.len() && bytes[index] == b'`' {
            index += 1;
        }
        if index - start == ticks {
            return Some(index);
        }
    }
    None
}

fn find_unescaped_delimiter(bytes: &[u8], mut index: usize, delimiter: &[u8]) -> Option<usize> {
    while index < bytes.len() {
        if bytes[index] == b'`' {
            let start = index;
            while index < bytes.len() && bytes[index] == b'`' {
                index += 1;
            }
            if let Some(end) = find_backtick_close(bytes, index, index - start) {
                index = end;
            }
            continue;
        }
        if bytes[index..].starts_with(delimiter) {
            let preceding_slashes = bytes[..index]
                .iter()
                .rev()
                .take_while(|byte| **byte == b'\\')
                .count();
            if preceding_slashes % 2 == 0 {
                return Some(index);
            }
            index += delimiter.len();
        } else {
            index += 1;
        }
    }
    None
}

fn apply_custom_markers(
    nodes: &mut Vec<MarkdownNode>,
    depth: usize,
    events: &mut usize,
) -> Result<(), MarkdownError> {
    if depth > MAX_MARKDOWN_DEPTH {
        return Err(MarkdownError::TooComplex);
    }
    for node in nodes.iter_mut() {
        if !matches!(
            node.kind,
            MarkdownNodeKind::InlineCode(_) | MarkdownNodeKind::CodeBlock(_)
        ) {
            apply_custom_markers(&mut node.children, depth + 1, events)?;
        }
    }
    let mut output = Vec::new();
    let mut groups: Vec<(MarkdownNodeKind, Vec<MarkdownNode>, char)> = Vec::new();
    for node in std::mem::take(nodes) {
        if let MarkdownNodeKind::Text(text) = &node.kind {
            let mut plain = String::new();
            for character in text.chars() {
                let token = match character {
                    '\u{e000}' => Some((true, MarkdownNodeKind::Underline, '\u{e001}')),
                    '\u{e001}' => Some((false, MarkdownNodeKind::Underline, character)),
                    '\u{e002}' => Some((true, MarkdownNodeKind::Spoiler, '\u{e003}')),
                    '\u{e003}' => Some((false, MarkdownNodeKind::Spoiler, character)),
                    _ => None,
                };
                if let Some((opening, kind, closing)) = token {
                    *events = events.saturating_add(1);
                    if *events > MAX_MARKDOWN_EVENTS {
                        return Err(MarkdownError::TooComplex);
                    }
                    if !plain.is_empty() {
                        append_markdown_node(
                            &mut output,
                            &mut groups,
                            text_node(std::mem::take(&mut plain)),
                        );
                    }
                    if opening {
                        if depth + groups.len() >= MAX_MARKDOWN_DEPTH {
                            return Err(MarkdownError::TooComplex);
                        }
                        groups.push((kind, Vec::new(), closing));
                    } else if groups.last().is_some_and(|group| group.0 == kind) {
                        let (kind, children, _) = groups.pop().expect("matching marker group");
                        append_markdown_node(
                            &mut output,
                            &mut groups,
                            MarkdownNode { kind, children },
                        );
                    } else {
                        append_markdown_node(&mut output, &mut groups, text_node("||".into()));
                    }
                } else {
                    plain.push(character);
                }
            }
            if !plain.is_empty() {
                append_markdown_node(&mut output, &mut groups, text_node(plain));
            }
        } else {
            append_markdown_node(&mut output, &mut groups, node);
        }
    }
    while let Some((kind, mut children, _)) = groups.pop() {
        let marker = if kind == MarkdownNodeKind::Underline {
            "__"
        } else {
            "||"
        };
        let mut flattened = vec![text_node(marker.into())];
        flattened.append(&mut children);
        for node in flattened {
            append_markdown_node(&mut output, &mut groups, node);
        }
    }
    *nodes = output;
    Ok(())
}

fn append_markdown_node(
    output: &mut Vec<MarkdownNode>,
    groups: &mut [(MarkdownNodeKind, Vec<MarkdownNode>, char)],
    node: MarkdownNode,
) {
    if let Some((_, children, _)) = groups.last_mut() {
        children.push(node);
    } else {
        output.push(node);
    }
}

fn text_node(text: String) -> MarkdownNode {
    MarkdownNode {
        kind: MarkdownNodeKind::Text(text),
        children: Vec::new(),
    }
}

fn append_leaf(root: &mut MarkdownNode, stack: &mut [MarkdownNode], kind: MarkdownNodeKind) {
    let node = MarkdownNode {
        kind,
        children: Vec::new(),
    };
    if let Some(parent) = stack.last_mut() {
        parent.children.push(node);
    } else {
        root.children.push(node);
    }
}

fn append_node(root: &mut MarkdownNode, stack: &mut [MarkdownNode], node: MarkdownNode) {
    if let Some(parent) = stack.last_mut() {
        parent.children.push(node);
    } else {
        root.children.push(node);
    }
}

fn map_tag(tag: Tag<'_>) -> MarkdownNodeKind {
    match tag {
        Tag::Paragraph => MarkdownNodeKind::Paragraph,
        Tag::Heading { level, .. } => MarkdownNodeKind::Heading(level as u8),
        Tag::BlockQuote(_) => MarkdownNodeKind::Quote,
        Tag::CodeBlock(kind) => MarkdownNodeKind::CodeBlock(match kind {
            CodeBlockKind::Fenced(language) if !language.is_empty() => Some(language.into_string()),
            _ => None,
        }),
        Tag::List(start) => MarkdownNodeKind::List(start),
        Tag::Item => MarkdownNodeKind::Item,
        Tag::Table(alignments) => MarkdownNodeKind::Table(
            alignments
                .into_iter()
                .map(|alignment| match alignment {
                    Alignment::None => TableAlignment::None,
                    Alignment::Left => TableAlignment::Left,
                    Alignment::Center => TableAlignment::Center,
                    Alignment::Right => TableAlignment::Right,
                })
                .collect(),
        ),
        Tag::TableHead => MarkdownNodeKind::TableHead,
        Tag::TableRow => MarkdownNodeKind::TableRow,
        Tag::TableCell => MarkdownNodeKind::TableCell,
        Tag::Emphasis => MarkdownNodeKind::Emphasis,
        Tag::Strong => MarkdownNodeKind::Strong,
        Tag::Strikethrough => MarkdownNodeKind::Strike,
        Tag::Link { dest_url, .. } => MarkdownNodeKind::Link(safe_link(dest_url.as_ref())),
        _ => MarkdownNodeKind::Unsupported,
    }
}

fn tag_matches(kind: &MarkdownNodeKind, end: TagEnd) -> bool {
    matches!(
        (kind, end),
        (MarkdownNodeKind::Paragraph, TagEnd::Paragraph)
            | (MarkdownNodeKind::Heading(_), TagEnd::Heading(_))
            | (MarkdownNodeKind::Quote, TagEnd::BlockQuote(_))
            | (MarkdownNodeKind::CodeBlock(_), TagEnd::CodeBlock)
            | (MarkdownNodeKind::List(_), TagEnd::List(_))
            | (MarkdownNodeKind::Item, TagEnd::Item)
            | (MarkdownNodeKind::Table(_), TagEnd::Table)
            | (MarkdownNodeKind::TableHead, TagEnd::TableHead)
            | (MarkdownNodeKind::TableRow, TagEnd::TableRow)
            | (MarkdownNodeKind::TableCell, TagEnd::TableCell)
            | (MarkdownNodeKind::Emphasis, TagEnd::Emphasis)
            | (MarkdownNodeKind::Strong, TagEnd::Strong)
            | (MarkdownNodeKind::Strike, TagEnd::Strikethrough)
            | (MarkdownNodeKind::Link(_), TagEnd::Link)
            | (MarkdownNodeKind::Unsupported, _)
    )
}

fn safe_link(destination: &str) -> Option<String> {
    if destination.len() > MAX_LINK_BYTES || destination.chars().any(char::is_control) {
        return None;
    }
    let (scheme, _) = destination.split_once(':')?;
    if scheme.eq_ignore_ascii_case("https")
        || scheme.eq_ignore_ascii_case("http")
        || scheme.eq_ignore_ascii_case("mailto")
    {
        Some(destination.to_owned())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_common_formatting_tables_and_tasks() {
        let parsed =
            parse_markdown("**bold** *italic* ~~gone~~\n\n|A|B|\n|-|-|\n|1|2|\n\n- [x] done")
                .unwrap();
        assert!(contains_kind(&parsed, |kind| matches!(
            kind,
            MarkdownNodeKind::Strong
        )));
        assert!(contains_kind(&parsed, |kind| matches!(
            kind,
            MarkdownNodeKind::Emphasis
        )));
        assert!(contains_kind(&parsed, |kind| matches!(
            kind,
            MarkdownNodeKind::Strike
        )));
        assert!(contains_kind(&parsed, |kind| matches!(
            kind,
            MarkdownNodeKind::Table(_)
        )));
        assert!(contains_kind(&parsed, |kind| matches!(
            kind,
            MarkdownNodeKind::Task(true)
        )));
    }

    #[test]
    fn raw_html_is_literal_text_and_unsafe_links_are_not_activatable() {
        let parsed =
            parse_markdown("<script>alert(1)</script> [run](javascript:alert(1))").unwrap();
        assert!(contains_kind(
            &parsed,
            |kind| matches!(kind, MarkdownNodeKind::Text(text) if text.contains("<script>"))
        ));
        assert!(!contains_kind(&parsed, |kind| matches!(
            kind,
            MarkdownNodeKind::Link(Some(_))
        )));
    }

    #[test]
    fn accepts_only_explicit_safe_schemes() {
        let parsed = parse_markdown(
            "[web](https://example.org) [mail](mailto:a@example.org) [bad](data:text/html,x)",
        )
        .unwrap();
        assert!(contains_kind(
            &parsed,
            |kind| matches!(kind, MarkdownNodeKind::Link(Some(url)) if url.starts_with("https:"))
        ));
        assert!(contains_kind(
            &parsed,
            |kind| matches!(kind, MarkdownNodeKind::Link(Some(url)) if url.starts_with("mailto:"))
        ));
        assert!(contains_kind(&parsed, |kind| matches!(
            kind,
            MarkdownNodeKind::Link(None)
        )));
    }

    #[test]
    fn parses_underline_spoilers_and_mixed_formatting_without_touching_code() {
        let parsed = parse_markdown(
            "__souligné__ **gras** ||secret|| `__code__ ||code||`\n\n```text\n__bloc__ ||bloc||\n```",
        )
        .unwrap();
        assert!(contains_kind(&parsed, |kind| matches!(
            kind,
            MarkdownNodeKind::Underline
        )));
        assert!(contains_kind(&parsed, |kind| matches!(
            kind,
            MarkdownNodeKind::Spoiler
        )));
        assert!(contains_kind(&parsed, |kind| matches!(
            kind,
            MarkdownNodeKind::Strong
        )));
        assert!(contains_kind(&parsed, |kind| matches!(
            kind,
            MarkdownNodeKind::InlineCode(text) if text.contains("__code__") && text.contains("||code||")
        )));
        assert!(contains_kind(&parsed, |kind| matches!(
            kind,
            MarkdownNodeKind::Text(text) if text.contains("__bloc__ ||bloc||")
        )));
    }

    #[test]
    fn input_and_parse_complexity_are_bounded() {
        assert_eq!(
            parse_markdown(&"x".repeat(MAX_MARKDOWN_BYTES + 1)),
            Err(MarkdownError::TooLarge)
        );
        let dense = "**x** ".repeat(MAX_MARKDOWN_EVENTS / 2 + 1);
        assert_eq!(parse_markdown(&dense), Err(MarkdownError::TooComplex));
        let custom_dense = "||x||".repeat(MAX_MARKDOWN_EVENTS / 2 + 1);
        assert_eq!(
            parse_markdown(&custom_dense),
            Err(MarkdownError::TooComplex)
        );
    }

    fn contains_kind(
        node: &MarkdownNode,
        predicate: impl Fn(&MarkdownNodeKind) -> bool + Copy,
    ) -> bool {
        predicate(&node.kind)
            || node
                .children
                .iter()
                .any(|child| contains_kind(child, predicate))
    }
}
