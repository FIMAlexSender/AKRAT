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
    Strike,
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
    for event in Parser::new_ext(source, options) {
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
    Ok(root)
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
    fn input_and_parse_complexity_are_bounded() {
        assert_eq!(
            parse_markdown(&"x".repeat(MAX_MARKDOWN_BYTES + 1)),
            Err(MarkdownError::TooLarge)
        );
        let dense = "**x** ".repeat(MAX_MARKDOWN_EVENTS / 2 + 1);
        assert_eq!(parse_markdown(&dense), Err(MarkdownError::TooComplex));
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
