//! The 23-rule git legality table: one `Forbid` rule per deny cell.

use super::diagnostics::{GitContext, opf, rcf};
use super::languages::{
    clean_lang, read_claimed_other_lang, staged_lang, unstaged_other_lang, unstaged_self_lang,
};
use crate::Action;
use crate::policy::rule::{PolicyRule, forbid};

/// The 23-rule git legality table. Within one action the row-languages are mutually exclusive, but
/// the claim language is independent of them, so the row cells are ordered before the claim cells
/// and the row diagnostic wins when both hold. Across actions heads pin distinct action constants.
/// Read/Diff/History and every staged-row commit have no rule and thus grant.
pub(super) fn git_rules() -> Vec<PolicyRule<GitContext>> {
    vec![
        // 1. edit on a resource unstaged by another principal.
        forbid(
            Action::Edit,
            unstaged_other_lang(),
            Box::new(|context| {
                let GitContext {
                    principal: p,
                    resource: r,
                    owner: q,
                    ..
                } = context;
                (
                    format!(
                        "{r} is unstaged by {q}; {p} may read, diff, or history it but may not edit it"
                    ),
                    opf(p, r, q),
                )
            }),
        ),
        // 2. checkout of a resource unstaged by another principal.
        forbid(
            Action::Checkout,
            unstaged_other_lang(),
            Box::new(|context| {
                let GitContext {
                    principal: p,
                    resource: r,
                    owner: q,
                    ..
                } = context;
                (
                    format!(
                        "{r} is unstaged by {q}; checkout would discard or replace {q}'s dirty resource"
                    ),
                    opf(p, r, q),
                )
            }),
        ),
        // 3. stage of a clean resource.
        forbid(
            Action::Stage,
            clean_lang(),
            Box::new(|context| {
                let GitContext {
                    principal: p,
                    resource: r,
                    ..
                } = context;
                (
                    "stage requires an unstaged resource owned by the acting principal".to_string(),
                    vec![format!("{p} edit {r} before staging")],
                )
            }),
        ),
        // 4. stage of an already-staged resource.
        forbid(
            Action::Stage,
            staged_lang(),
            Box::new(|context| {
                let GitContext {
                    principal: p,
                    resource: r,
                    ..
                } = context;
                (
                    "stage requires an unstaged resource owned by the acting principal".to_string(),
                    vec![format!("{p} unstage {r} before staging again")],
                )
            }),
        ),
        // 5. stage of a resource unstaged by another principal.
        forbid(
            Action::Stage,
            unstaged_other_lang(),
            Box::new(|context| {
                let GitContext {
                    principal: p,
                    resource: r,
                    owner: q,
                    ..
                } = context;
                (
                    format!("{r} is unstaged by {q}; only {q} may stage it"),
                    opf(p, r, q),
                )
            }),
        ),
        // 6. stash of a clean resource.
        forbid(
            Action::Stash,
            clean_lang(),
            Box::new(|context| {
                let GitContext {
                    principal: p,
                    resource: r,
                    ..
                } = context;
                (
                    "stash requires an unstaged resource owned by the acting principal".to_string(),
                    vec![format!("{p} edit {r} before stashing")],
                )
            }),
        ),
        // 7. stash of an already-staged resource.
        forbid(
            Action::Stash,
            staged_lang(),
            Box::new(|context| {
                let GitContext {
                    principal: p,
                    resource: r,
                    ..
                } = context;
                (
                    "stash requires an unstaged resource owned by the acting principal".to_string(),
                    vec![format!("{p} unstage {r} before stashing")],
                )
            }),
        ),
        // 8. stash of a resource unstaged by another principal.
        forbid(
            Action::Stash,
            unstaged_other_lang(),
            Box::new(|context| {
                let GitContext {
                    principal: p,
                    resource: r,
                    owner: q,
                    ..
                } = context;
                (
                    format!("{r} is unstaged by {q}; only {q} may stash it"),
                    opf(p, r, q),
                )
            }),
        ),
        // 9. unstage of a resource unstaged by another principal.
        forbid(
            Action::Unstage,
            unstaged_other_lang(),
            Box::new(|context| {
                let GitContext {
                    principal: p,
                    resource: r,
                    owner: q,
                    ..
                } = context;
                (
                    "unstage requires a staged resource".to_string(),
                    opf(p, r, q),
                )
            }),
        ),
        // 10. unstage of a clean resource.
        forbid(
            Action::Unstage,
            clean_lang(),
            Box::new(|context| {
                let GitContext {
                    principal: p,
                    resource: r,
                    ..
                } = context;
                (
                    "unstage requires a staged resource".to_string(),
                    vec![format!("{p} stage {r} before unstaging")],
                )
            }),
        ),
        // 11. unstage of a resource unstaged by the acting principal.
        forbid(
            Action::Unstage,
            unstaged_self_lang(),
            Box::new(|context| {
                let GitContext {
                    principal: p,
                    resource: r,
                    ..
                } = context;
                (
                    "unstage requires a staged resource".to_string(),
                    vec![format!("{p} stage {r} before unstaging")],
                )
            }),
        ),
        // 12. commit of a clean resource.
        forbid(
            Action::commit_without_message(),
            clean_lang(),
            Box::new(|context| {
                let GitContext {
                    principal: p,
                    resource: r,
                    ..
                } = context;
                (
                    "commit requires a staged resource".to_string(),
                    vec![
                        format!("{p} edit {r}"),
                        format!("{p} stage {r} before committing"),
                    ],
                )
            }),
        ),
        // 13. commit of a resource unstaged by the acting principal.
        forbid(
            Action::commit_without_message(),
            unstaged_self_lang(),
            Box::new(|context| {
                let GitContext {
                    principal: p,
                    resource: r,
                    ..
                } = context;
                (
                    "commit requires a staged resource".to_string(),
                    vec![format!("{p} stage {r} before committing")],
                )
            }),
        ),
        // 14. commit of a resource unstaged by another principal.
        forbid(
            Action::commit_without_message(),
            unstaged_other_lang(),
            Box::new(|context| {
                let GitContext {
                    principal: p,
                    resource: r,
                    owner: q,
                    ..
                } = context;
                (
                    "commit requires a staged resource".to_string(),
                    opf(p, r, q),
                )
            }),
        ),
        // 15. delete of a staged resource.
        forbid(
            Action::Delete,
            staged_lang(),
            Box::new(|context| {
                let GitContext {
                    principal: p,
                    resource: r,
                    ..
                } = context;
                (
                    "delete requires a resource with no staged or unstaged changes".to_string(),
                    vec![
                        format!("{p} commit {r} before deleting"),
                        format!("{p} checkout {r} before deleting"),
                    ],
                )
            }),
        ),
        // 16. delete of a resource unstaged by the acting principal.
        forbid(
            Action::Delete,
            unstaged_self_lang(),
            Box::new(|context| {
                let GitContext {
                    principal: p,
                    resource: r,
                    ..
                } = context;
                (
                    "delete requires a resource with no staged or unstaged changes".to_string(),
                    vec![
                        format!("{p} checkout {r} before deleting"),
                        format!("{p} stash {r} before deleting"),
                    ],
                )
            }),
        ),
        // 17. delete of a resource unstaged by another principal.
        forbid(
            Action::Delete,
            unstaged_other_lang(),
            Box::new(|context| {
                let GitContext {
                    principal: p,
                    resource: r,
                    owner: q,
                    ..
                } = context;
                (
                    format!("{r} is unstaged by {q}; delete would discard {q}'s dirty resource"),
                    opf(p, r, q),
                )
            }),
        ),
        // 18. clean of a resource unstaged by another principal.
        forbid(
            Action::Clean,
            unstaged_other_lang(),
            Box::new(|context| {
                let GitContext {
                    principal: p,
                    resource: r,
                    owner: q,
                    ..
                } = context;
                (
                    format!("{r} is unstaged by {q}; clean would discard {q}'s dirty resource"),
                    opf(p, r, q),
                )
            }),
        ),
        // 19. edit of a resource another principal holds a read claim on.
        forbid(
            Action::Edit,
            read_claimed_other_lang(),
            Box::new(|context| {
                let GitContext {
                    principal: p,
                    resource: r,
                    reader: s,
                    ..
                } = context;
                (
                    format!("{r} was last read by {s}; {p} must read it before editing it"),
                    rcf(p, r),
                )
            }),
        ),
        // 20. delete of a resource another principal holds a read claim on.
        forbid(
            Action::Delete,
            read_claimed_other_lang(),
            Box::new(|context| {
                let GitContext {
                    principal: p,
                    resource: r,
                    reader: s,
                    ..
                } = context;
                (
                    format!("{r} was last read by {s}; {p} must read it before deleting it"),
                    rcf(p, r),
                )
            }),
        ),
        // 21. clean of a resource another principal holds a read claim on.
        forbid(
            Action::Clean,
            read_claimed_other_lang(),
            Box::new(|context| {
                let GitContext {
                    principal: p,
                    resource: r,
                    reader: s,
                    ..
                } = context;
                (
                    format!("{r} was last read by {s}; {p} must read it before cleaning it"),
                    rcf(p, r),
                )
            }),
        ),
        // 22. checkout of a resource another principal holds a read claim on.
        forbid(
            Action::Checkout,
            read_claimed_other_lang(),
            Box::new(|context| {
                let GitContext {
                    principal: p,
                    resource: r,
                    reader: s,
                    ..
                } = context;
                (
                    format!("{r} was last read by {s}; {p} must read it before checking it out"),
                    rcf(p, r),
                )
            }),
        ),
        // 23. stash of a resource another principal holds a read claim on.
        forbid(
            Action::Stash,
            read_claimed_other_lang(),
            Box::new(|context| {
                let GitContext {
                    principal: p,
                    resource: r,
                    reader: s,
                    ..
                } = context;
                (
                    format!("{r} was last read by {s}; {p} must read it before stashing it"),
                    rcf(p, r),
                )
            }),
        ),
    ]
}
