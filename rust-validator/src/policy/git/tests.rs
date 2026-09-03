//! The table this module encodes, checked against an independent literal oracle.

use super::git_decision;
use super::languages::{clean_lang, staged_lang, unstaged_other_lang, unstaged_self_lang};
use crate::policy::PolicyDecision;
use crate::syntax::{CanonicalStore, compile_rule};
use crate::{Action, Bump, ComponentPattern, Event, Head, RegexExpr, Rule, RuleMode};

fn resource() -> [&'static str; 2] {
    ["src", "x"]
}

/// History whose fold lands the resource in the named row (candidate principal is "self").
fn history_for(row: &str) -> Vec<Event> {
    let r = resource();
    match row {
        "clean" => vec![],
        "staged" => vec![
            Event::new("self", Action::Edit, r),
            Event::new("self", Action::Stage, r),
        ],
        "unstaged-self" => vec![Event::new("self", Action::Edit, r)],
        "unstaged-other" => vec![Event::new("other", Action::Edit, r)],
        other => panic!("unknown row {other}"),
    }
}

fn grant() -> PolicyDecision {
    PolicyDecision::Grant
}

fn denial(precondition: &str, fixes: &[&str]) -> PolicyDecision {
    PolicyDecision::Deny {
        failed_precondition: precondition.to_string(),
        allowed_fixes: fixes.iter().map(|f| f.to_string()).collect(),
    }
}

fn opf() -> Vec<String> {
    vec![
        "other stage src/x".to_string(),
        "other checkout src/x".to_string(),
        "other stash src/x".to_string(),
        "self only reads, diffs, or histories src/x".to_string(),
    ]
}

/// Independent oracle: the reduced default table for candidate principal "self", resource
/// "src/x", foreign owner "other". Strings are literal to pin the Rust translation. The commit
/// branch is message-agnostic: `commit("m")` and `commit_without_message()` yield the same
/// per-row result.
fn oracle(row: &str, action: &Action) -> PolicyDecision {
    match action {
        Action::Read | Action::Diff | Action::History => grant(),
        Action::Delete => match row {
            "clean" => grant(),
            "staged" => denial(
                "delete requires a resource with no staged or unstaged changes",
                &["self commit src/x before deleting", "self checkout src/x before deleting"],
            ),
            "unstaged-self" => denial(
                "delete requires a resource with no staged or unstaged changes",
                &["self checkout src/x before deleting", "self stash src/x before deleting"],
            ),
            _ => PolicyDecision::Deny {
                failed_precondition:
                    "src/x is unstaged by other; delete would discard other's dirty resource"
                        .to_string(),
                allowed_fixes: opf(),
            },
        },
        Action::Clean => match row {
            "unstaged-other" => PolicyDecision::Deny {
                failed_precondition:
                    "src/x is unstaged by other; clean would discard other's dirty resource"
                        .to_string(),
                allowed_fixes: opf(),
            },
            _ => grant(),
        },
        Action::Edit => match row {
            "unstaged-other" => PolicyDecision::Deny {
                failed_precondition:
                    "src/x is unstaged by other; self may read, diff, or history it but may not edit it"
                        .to_string(),
                allowed_fixes: opf(),
            },
            _ => grant(),
        },
        Action::Checkout => match row {
            "unstaged-other" => PolicyDecision::Deny {
                failed_precondition:
                    "src/x is unstaged by other; checkout would discard or replace other's dirty resource"
                        .to_string(),
                allowed_fixes: opf(),
            },
            _ => grant(),
        },
        Action::Stage => match row {
            "unstaged-self" => grant(),
            "clean" => denial(
                "stage requires an unstaged resource owned by the acting principal",
                &["self edit src/x before staging"],
            ),
            "staged" => denial(
                "stage requires an unstaged resource owned by the acting principal",
                &["self unstage src/x before staging again"],
            ),
            _ => PolicyDecision::Deny {
                failed_precondition: "src/x is unstaged by other; only other may stage it"
                    .to_string(),
                allowed_fixes: opf(),
            },
        },
        Action::Stash => match row {
            "unstaged-self" => grant(),
            "clean" => denial(
                "stash requires an unstaged resource owned by the acting principal",
                &["self edit src/x before stashing"],
            ),
            "staged" => denial(
                "stash requires an unstaged resource owned by the acting principal",
                &["self unstage src/x before stashing"],
            ),
            _ => PolicyDecision::Deny {
                failed_precondition: "src/x is unstaged by other; only other may stash it"
                    .to_string(),
                allowed_fixes: opf(),
            },
        },
        Action::Unstage => match row {
            "staged" => grant(),
            "unstaged-other" => PolicyDecision::Deny {
                failed_precondition: "unstage requires a staged resource".to_string(),
                allowed_fixes: opf(),
            },
            _ => denial(
                "unstage requires a staged resource",
                &["self stage src/x before unstaging"],
            ),
        },
        Action::Commit { .. } => match row {
            "staged" => grant(),
            "clean" => denial(
                "commit requires a staged resource",
                &["self edit src/x", "self stage src/x before committing"],
            ),
            "unstaged-self" => denial(
                "commit requires a staged resource",
                &["self stage src/x before committing"],
            ),
            _ => PolicyDecision::Deny {
                failed_precondition: "commit requires a staged resource".to_string(),
                allowed_fixes: opf(),
            },
        },
    }
}

#[test]
fn git_decision_matches_the_reduced_table_exhaustively() {
    let rows = ["clean", "staged", "unstaged-self", "unstaged-other"];
    let actions = [
        Action::Read,
        Action::Edit,
        Action::Stage,
        Action::Unstage,
        Action::commit("m"),
        Action::commit_without_message(),
        Action::Checkout,
        Action::Stash,
        Action::Delete,
        Action::Clean,
        Action::Diff,
        Action::History,
    ];
    for row in rows {
        let history = history_for(row);
        for action in &actions {
            let candidate = Event::new("self", action.clone(), resource());
            let got = git_decision(&history, &candidate);
            let expected = oracle(row, action);
            assert_eq!(got, expected, "row={row} action={action:?}");
        }
    }
}

/// A canonical row language paired with the name the failure message reports.
type RowLanguage = (&'static str, fn() -> RegexExpr);

#[test]
fn row_languages_match_the_four_canonical_states() {
    let languages: [RowLanguage; 4] = [
        ("clean", clean_lang),
        ("staged", staged_lang),
        ("unstaged-self", unstaged_self_lang),
        ("unstaged-other", unstaged_other_lang),
    ];
    let histories = [
        ("clean", history_for("clean")),
        ("staged", history_for("staged")),
        ("unstaged-self", history_for("unstaged-self")),
        ("unstaged-other", history_for("unstaged-other")),
    ];
    let candidate = Event::new("self", Action::Read, resource());

    for (lang_name, lang) in languages {
        for (history_name, history) in &histories {
            let arena = Bump::new();
            let mut store = CanonicalStore::new(&arena);
            // Bind-all classifier head: matches any candidate, binds `p`/`r`; the unused `a`
            // binding is legal — only tail variables absent from the head would error.
            let rule = Rule::new(
                RuleMode::Forbid,
                Head::new(
                    ComponentPattern::variable("p"),
                    ComponentPattern::variable("a"),
                    ComponentPattern::variable("r"),
                ),
                lang(),
            );
            let mut rt = compile_rule(&mut store, &rule).expect("row language compiles");
            let inside = rt
                .accepts_history(&mut store, history.iter(), &candidate)
                .expect("bind-all head matches candidate");
            assert_eq!(
                inside,
                lang_name == *history_name,
                "lang={lang_name} history={history_name}",
            );
        }
    }
}

#[test]
fn a_read_claim_moves_only_when_another_principal_reads() {
    let r = resource();
    let candidate = Event::new("self", Action::Edit, r);

    // A foreign read claims the resource.
    let history = vec![Event::new("other", Action::Read, r)];
    assert_eq!(
        git_decision(&history, &candidate),
        denial(
            "src/x was last read by other; self must read it before editing it",
            &["self read src/x"],
        ),
    );

    // Reading it takes the claim over: last reader wins.
    let history = vec![
        Event::new("other", Action::Read, r),
        Event::new("self", Action::Read, r),
    ];
    assert_eq!(git_decision(&history, &candidate), PolicyDecision::Grant);

    // Settling does not move the claim. `other` has relinquished, but `self` still has to look
    // before it writes -- otherwise it would clobber content it has never seen.
    let mut history = vec![
        Event::new("other", Action::Read, r),
        Event::new("other", Action::Edit, r),
        Event::new("other", Action::Stage, r),
    ];
    assert_eq!(
        git_decision(&history, &candidate),
        denial(
            "src/x was last read by other; self must read it before editing it",
            &["self read src/x"],
        ),
    );

    // Taking it over is always available: `read` has no cell in any row or claim state.
    history.push(Event::new("self", Action::Read, r));
    assert_eq!(git_decision(&history, &candidate), PolicyDecision::Grant);
}

#[test]
fn a_read_claim_also_blocks_foreign_checkout_and_stash() {
    let r = resource();

    // Staged row: cell 2 covers only unstaged-other, so the claim is all that stands in the way.
    let staged = vec![
        Event::new("other", Action::Edit, r),
        Event::new("other", Action::Stage, r),
        Event::new("self", Action::Read, r),
    ];
    assert_eq!(
        git_decision(&staged, &Event::new("other", Action::Checkout, r)),
        denial(
            "src/x was last read by self; other must read it before checking it out",
            &["other read src/x"],
        ),
    );

    // Unstaged-self row for `other`: cells 6-8 cover the other three rows.
    let unstaged = vec![
        Event::new("other", Action::Edit, r),
        Event::new("self", Action::Read, r),
    ];
    assert_eq!(
        git_decision(&unstaged, &Event::new("other", Action::Stash, r)),
        denial(
            "src/x was last read by self; other must read it before stashing it",
            &["other read src/x"],
        ),
    );
}

#[test]
fn delete_settles_the_resource_into_the_staged_row() {
    let r = resource();
    let history = vec![Event::new("self", Action::Delete, r)];
    assert_eq!(
        git_decision(&history, &Event::new("self", Action::Stage, r)),
        denial(
            "stage requires an unstaged resource owned by the acting principal",
            &["self unstage src/x before staging again"],
        ),
    );
    assert_eq!(
        git_decision(&history, &Event::new("self", Action::commit("m"), r)),
        PolicyDecision::Grant,
    );
}

#[test]
fn retained_policy_matches_one_shot_decisions_across_history_updates() {
    let arena = Bump::new();
    let mut policy = super::GitPolicy::new(&arena);
    let r = resource();
    let mut history = Vec::new();
    let candidates = [
        Event::new("self", Action::Edit, r),
        Event::new("self", Action::Stage, r),
        Event::new("self", Action::commit("ship"), r),
        Event::new("other", Action::Edit, r),
        Event::new("other", Action::Read, r),
    ];

    for candidate in candidates {
        let expected = git_decision(&history, &candidate);
        let actual = policy.decide(&history, &candidate);
        assert_eq!(actual, expected);
        if actual == PolicyDecision::Grant {
            history.push(candidate);
        }
    }
}
