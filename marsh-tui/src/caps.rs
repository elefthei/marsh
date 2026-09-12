//! The `caps` tab: the authority's active granted capabilities as a directory tree.
//!
//! Everything here is a projection of [`shellmux::ShellMux::active_capabilities`] and nothing here
//! touches a filesystem. A resource is a vector of segments, and that vector is its identity: a
//! deleted file keeps its row while a claim on it stands, and `["a/b"]` is not `["a", "b"]` even
//! though both print as `a/b`.
//!
//! This is a read-only browser. Nothing in it opens, edits or releases anything.

use std::collections::{BTreeMap, HashSet};

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::widgets::StatefulWidget as _;
use shellmux::{Action, Event};
use tui_tree_widget::{Tree, TreeItem, TreeState};

use crate::terminal::escape_controls;

/// The identifier of the virtual root every resource hangs below: the only top-level item, so it
/// collides with nothing, and also what its row shows.
const ROOT: &str = "/";

/// One active claim on a resource.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claim {
    /// The action as the authority spells it.
    pub action: String,
    /// The job name that holds it — still the holder after that job closes.
    pub principal: String,
    /// What the claim asserts: `unstaged`, `staged` or `read claim`.
    pub kind: &'static str,
}

impl Claim {
    /// The claim an event asserts, or `None` for an action that asserts none.
    fn of(event: &Event) -> Option<Self> {
        let kind = match event.action {
            Action::Edit | Action::Unstage => "unstaged",
            Action::Stage | Action::Delete => "staged",
            Action::Read => "read claim",
            Action::Commit { .. }
            | Action::Checkout
            | Action::Stash
            | Action::Clean
            | Action::Diff
            | Action::History => return None,
        };
        Some(Self {
            action: event.action.to_string(),
            principal: event.principal.as_str().to_string(),
            kind,
        })
    }

    /// How a claim reads on its row.
    fn describe(&self) -> String {
        format!(
            "{} {} ({})",
            escape_controls(&self.action),
            escape_controls(&self.principal),
            self.kind
        )
    }
}

/// One node of the virtual tree: a segment, whatever hangs below it, and whatever claims it holds.
#[derive(Debug, Default)]
struct Node {
    /// Children by raw segment, so the order is lexicographic over identity rather than display.
    children: BTreeMap<String, Self>,
    /// The claims active on this exact segment vector.
    claims: Vec<Claim>,
}

impl Node {
    /// The node at `segments` below this one.
    fn get(&self, segments: &[String]) -> Option<&Self> {
        segments
            .iter()
            .try_fold(self, |node, segment| node.children.get(segment))
    }

    /// `name` and every claim on this node, as a row and the footer read it.
    fn text(&self, name: &str) -> String {
        let mut text = escape_controls(name);
        if !self.claims.is_empty() {
            text.push_str("  —  ");
            text.push_str(
                &self
                    .claims
                    .iter()
                    .map(Claim::describe)
                    .collect::<Vec<_>>()
                    .join(", "),
            );
        }
        text
    }

    /// The widget's item for this node, named `segment`.
    ///
    /// Directories before leaves, each group lexicographic by raw segment: `BTreeMap` already
    /// orders the segments, so one stable partition is all the ordering that is left.
    fn item(&self, segment: &str) -> TreeItem<'static, String> {
        let children = [false, true]
            .into_iter()
            .flat_map(|leaves| {
                self.children
                    .iter()
                    .filter(move |(_, child)| child.children.is_empty() == leaves)
            })
            .map(|(segment, child)| child.item(segment))
            .collect();
        // `BTreeMap` keys are unique, so the duplicate-identifier error cannot happen; the leaf is
        // the total fallback that keeps this projection free of panics.
        TreeItem::new(segment.to_string(), self.text(segment), children)
            .unwrap_or_else(|_| TreeItem::new_leaf(segment.to_string(), self.text(segment)))
    }
}

/// The browsable state of the `caps` tab.
#[derive(Debug)]
pub struct CapsView {
    /// The virtual root every resource hangs below.
    root: Node,
    /// Every identifier path this view has already rendered, so a newly seen directory can start
    /// expanded without re-expanding one the user collapsed.
    seen_paths: HashSet<Vec<String>>,
    /// The widget's items, rebuilt on every refresh: the root, and every resource below it.
    items: Vec<TreeItem<'static, String>>,
    /// The widget's selection, expansion and scroll state, keyed by identifier path.
    state: TreeState<String>,
}

impl Default for CapsView {
    fn default() -> Self {
        Self::new()
    }
}

impl CapsView {
    /// An empty browser: the root, expanded and selected.
    #[must_use]
    pub fn new() -> Self {
        let root = vec![ROOT.to_string()];
        let mut state = TreeState::default();
        state.open(root.clone());
        state.select(root.clone());
        Self {
            root: Node::default(),
            seen_paths: HashSet::from([root]),
            items: vec![Node::default().item(ROOT)],
            state,
        }
    }

    /// Replaces the tree with `events`, preserving expansion and selection by identifier path.
    ///
    /// Directories that were never seen before start expanded, which is what makes a first read
    /// show the whole tree; a directory the user collapsed stays collapsed across refreshes. A
    /// selection whose resource is gone moves to its nearest surviving ancestor; the root survives
    /// everything, so a refresh always leaves something selected.
    pub fn refresh(&mut self, events: &[Event]) {
        let mut root = Node::default();
        let mut known: HashSet<Vec<String>> = HashSet::new();
        let mut path = vec![ROOT.to_string()];
        known.insert(path.clone());
        for event in events {
            let Some(claim) = Claim::of(event) else {
                continue;
            };
            let mut node = &mut root;
            path.truncate(1);
            for segment in event.resource.segments() {
                path.push(segment.clone());
                known.insert(path.clone());
                node = node.children.entry(segment.clone()).or_default();
            }
            if !node.claims.contains(&claim) {
                node.claims.push(claim);
            }
        }
        for fresh in known.difference(&self.seen_paths) {
            self.state.open(fresh.clone());
        }
        let mut selected = self.state.selected().to_vec();
        while !known.contains(&selected) {
            if selected.pop().is_none() {
                selected.push(ROOT.to_string());
            }
        }
        if selected != self.state.selected() {
            self.state.select(selected);
        }
        self.items = vec![root.item(ROOT)];
        self.seen_paths = known;
        self.root = root;
    }

    /// Whether there is no claim at all, so the tree is only the root.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.root.children.is_empty() && self.root.claims.is_empty()
    }

    /// The widget's state, for key handling.
    pub const fn state_mut(&mut self) -> &mut TreeState<String> {
        &mut self.state
    }

    /// The selected resource's full escaped path and every claim on it — the footer's text — or
    /// `None` while nothing is selected.
    #[must_use]
    pub fn detail(&self) -> Option<String> {
        let (_, segments) = self.state.selected().split_first()?;
        let node = self.root.get(segments)?;
        let path = if segments.is_empty() {
            "<root>".to_string()
        } else {
            segments.join("/")
        };
        Some(node.text(&path))
    }

    /// Draws the tree into `area`.
    pub fn render(&mut self, area: Rect, buf: &mut Buffer) {
        // One top-level item, so the duplicate-identifier error cannot happen.
        if let Ok(tree) = Tree::new(&self.items) {
            tree.highlight_style(Style::default().fg(Color::Black).bg(Color::White))
                .render(area, buf, &mut self.state);
        }
    }
}

#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use super::*;

    use shellmux::Resource;

    fn event(principal: &str, action: Action, resource: Resource) -> Event {
        Event::new(principal, action, resource)
    }

    /// Every cell of the tab as drawn, rows concatenated.
    fn screen(view: &mut CapsView, width: u16, height: u16) -> String {
        let mut buffer = Buffer::empty(Rect::new(0, 0, width, height));
        view.render(*buffer.area(), &mut buffer);
        buffer.content().iter().map(|cell| cell.symbol()).collect()
    }

    /// The identifier path of a resource: the root, then its raw segments.
    fn path(segments: &[&str]) -> Vec<String> {
        std::iter::once(ROOT)
            .chain(segments.iter().copied())
            .map(str::to_string)
            .collect()
    }

    /// Identity is the segment vector: two resources that print the same are two rows, and a
    /// resource no longer on disk keeps its claim.
    #[test]
    fn resources_that_share_a_display_text_stay_distinct_rows() {
        let mut view = CapsView::new();
        view.refresh(&[
            event("one", Action::Edit, Resource::from(["a/b"])),
            event("two", Action::Edit, Resource::from(["a", "b"])),
            event("three", Action::Read, Resource::from(["gone.txt"])),
        ]);

        let drawn = screen(&mut view, 60, 8);
        assert!(drawn.contains("a/b  —  edit one (unstaged)"), "{drawn}");
        assert!(drawn.contains("b  —  edit two (unstaged)"), "{drawn}");
        assert!(
            drawn.contains("gone.txt  —  read three (read claim)"),
            "{drawn}"
        );

        view.state_mut().select(path(&["a/b"]));
        assert_eq!(
            view.detail(),
            Some("a/b  —  edit one (unstaged)".to_string())
        );
        view.state_mut().select(path(&["a", "b"]));
        assert_eq!(
            view.detail(),
            Some("a/b  —  edit two (unstaged)".to_string())
        );
    }

    /// Selection survives a refresh by identity, and falls back to an ancestor when its resource
    /// disappears.
    #[test]
    fn selection_survives_refreshes_and_falls_back_to_an_ancestor() {
        let mut view = CapsView::new();
        view.refresh(&[
            event("one", Action::Edit, Resource::from(["src", "a.rs"])),
            event("two", Action::Edit, Resource::from(["src", "b.rs"])),
        ]);
        // Movement reads what the last render flattened, so the tab has to be drawn first.
        let _drawn = screen(&mut view, 40, 8);
        view.state_mut().select_last();
        assert_eq!(view.state_mut().selected(), path(&["src", "b.rs"]));

        view.refresh(&[event("one", Action::Edit, Resource::from(["src", "a.rs"]))]);
        assert_eq!(
            view.state_mut().selected(),
            path(&["src"]),
            "the nearest surviving ancestor takes the selection"
        );
    }

    /// A control character in a segment is displayed, never executed.
    #[test]
    fn control_characters_in_a_segment_are_escaped_for_display() {
        let mut view = CapsView::new();
        view.refresh(&[event(
            "one",
            Action::Edit,
            Resource::from(vec!["e\x1b[2Jvil".to_string()]),
        )]);
        let drawn = screen(&mut view, 40, 4);
        assert!(drawn.contains("e\\x1b[2Jvil"), "{drawn}");
        assert!(
            view.seen_paths.contains(&path(&["e\x1b[2Jvil"])),
            "escaping is display only"
        );
    }

    /// An empty snapshot is a stated absence, not an invented filesystem.
    #[test]
    fn an_empty_projection_has_only_the_root() {
        let mut view = CapsView::new();
        view.refresh(&[]);
        assert!(view.is_empty());
        assert_eq!(view.detail(), Some("<root>".to_string()));
        // A root with nothing below it is a leaf, so it carries no expand marker.
        assert_eq!(screen(&mut view, 6, 1), "  /   ");
    }
}
