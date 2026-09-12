//! Releasing capability claims the seed no longer justifies.
//!
//! [`crate::history::load`] replays every event ever granted, and the policy decides a resource's
//! row from the last state-changing event on it. One `edit` therefore owns its resource for its
//! principal forever: nothing in the log ever settles it, so a restart days later still refuses
//! another principal's write to a file that was deleted in between.
//!
//! Reconciliation runs once, at [`crate::ShellMux::new`], between the load and the authority. It
//! reduces the replayed history to at most one event per resource — the one that decides the row —
//! and retains it only while the seed's own git state still corroborates it. A worktree-dirty
//! resource keeps its unstaged claim and an index-only resource keeps its staged claim; a resource
//! that is clean, ignored, deleted, or in no repository at all keeps nothing. Read claims never
//! survive a restart: no state in the seed corroborates a read.
//!
//! Within a session nothing changes — claims accumulate and contend exactly as they did before —
//! and the durable log is never rewritten. This filters what the policy is told, in memory, so
//! [`crate::commit::recover`] and the log's sequence numbers still see the complete record.

use std::collections::HashMap;
use std::path::PathBuf;

use git2::{Repository, Status};
use marsh_exec::{PersistenceLayer, gitshell, isolate_from_host_config};
use rust_validator::{Action, Event, active_git_capability_indices};

/// The row a retained claim asserts about its resource.
enum Row {
    /// Uncommitted worktree content.
    Unstaged,
    /// Index content and nothing further in the worktree.
    Staged,
}

/// Drops from `history` every event that is not a claim the seed still corroborates.
///
/// Infallible by construction: a repository that cannot be opened or queried leaves its claims
/// standing, and every other failure to resolve a resource drops one claim, never a session.
pub(crate) fn reconcile(persistence: &PersistenceLayer, history: Vec<Event>) -> Vec<Event> {
    // Process-global, `Once`-guarded: a host `core.excludesfile` must not decide what looks
    // ignored here, exactly as it must not decide how a git builtin hashes a blob.
    isolate_from_host_config();

    // The active-capability projection is the policy's own view of the log: per resource, the last
    // event that decides its row plus the last read claim. Reads never survive a restart — no seed
    // state corroborates one — so `corroborated` drops them along with the rows the seed no longer
    // shows, which is what releases the read claims of rules 19-23.
    let mut repositories: HashMap<PathBuf, Option<Repository>> = HashMap::new();
    let retained: Vec<usize> = active_git_capability_indices(&history)
        .into_iter()
        .filter(|index| corroborated(persistence, &history[*index], &mut repositories))
        .collect();

    // The projection is already in the log's own order, so retaining events is one ordered walk of
    // the owned history that moves each survivor out rather than cloning it.
    let mut retained = retained.into_iter().peekable();
    history
        .into_iter()
        .enumerate()
        .filter_map(|(index, event)| retained.next_if_eq(&index).map(|_| event))
        .collect()
}

/// The row `action` leaves its resource in, or `None` when that row is `clean`.
///
/// A clean resource is what an empty history already means, so a commit, checkout or stash has
/// nothing left to assert and is never retained.
const fn row_of(action: &Action) -> Option<Row> {
    match action {
        Action::Edit | Action::Unstage => Some(Row::Unstaged),
        Action::Stage | Action::Delete => Some(Row::Staged),
        Action::Commit { .. } | Action::Checkout | Action::Stash => None,
        Action::Read | Action::Diff | Action::History | Action::Clean => None,
    }
}

/// Whether the seed still shows the state `event` claims for its resource.
///
/// `repositories` caches one open per repository root, because a history naming many resources of
/// one repository must not reopen it once per resource.
fn corroborated(
    persistence: &PersistenceLayer,
    event: &Event,
    repositories: &mut HashMap<PathBuf, Option<Repository>>,
) -> bool {
    let Some(row) = row_of(&event.action) else {
        return false;
    };
    let absolute = persistence
        .seed
        .join(event.resource.segments().iter().collect::<PathBuf>());
    let Some(parent) = absolute.parent() else {
        return false;
    };
    // A resource in no repository is dropped: it has no git state to be dirty in, and marsh's git
    // builtins refuse to run without a repository, so no command could ever settle a claim there.
    let Some(root) = gitshell::repo_root(parent, &persistence.seed) else {
        return false;
    };
    let repository = repositories
        .entry(root.clone())
        .or_insert_with(|| Repository::open(&root).ok());
    // An unreadable repository is an anomaly, and the safe side of an anomaly is a claim left
    // standing rather than a job free to clobber work.
    let Some(repository) = repository.as_ref() else {
        return true;
    };
    // Infallible: `repo_root` returned an ancestor of `absolute`.
    let Ok(relative) = absolute.strip_prefix(&root) else {
        return true;
    };
    match repository.status_file(relative) {
        // libgit2 reports this for a path in neither HEAD, the index, nor the worktree: the file
        // is gone and untracked, so nothing is left to protect.
        Err(error) if error.code() == git2::ErrorCode::NotFound => false,
        Err(_) => true,
        Ok(status) => match row {
            Row::Unstaged => worktree_dirty(status),
            Row::Staged => staged(status) && !worktree_dirty(status),
        },
    }
}

/// Whether `status` shows worktree content git has not been told about.
///
/// `IGNORED` alone intersects nothing here, which is the point: git holds no uncommitted work at an
/// ignored path, so a claim on it is released.
fn worktree_dirty(status: Status) -> bool {
    status.intersects(
        Status::WT_NEW
            | Status::WT_MODIFIED
            | Status::WT_DELETED
            | Status::WT_TYPECHANGE
            | Status::WT_RENAMED
            | Status::WT_UNREADABLE
            | Status::CONFLICTED,
    )
}

/// Whether `status` shows content in the index that HEAD does not have.
fn staged(status: Status) -> bool {
    status.intersects(
        Status::INDEX_NEW
            | Status::INDEX_MODIFIED
            | Status::INDEX_DELETED
            | Status::INDEX_RENAMED
            | Status::INDEX_TYPECHANGE,
    )
}

#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use super::*;

    use std::path::Path;

    use rust_validator::Resource;

    use git2::Signature;

    /// A scratch seed carrying one repository at `repo/` and a plain directory beside it, the way a
    /// real seed holds none, one, or many repositories at any depth.
    ///
    /// Inside the repository: `tracked.txt` committed and clean, `dirty.txt` untracked and present,
    /// `staged.txt` in the index and matching the worktree, `ignored.txt` excluded by
    /// `.gitignore`, and `gone.txt` absent from all three of HEAD, index and worktree.
    fn scratch(root: &Path) -> PersistenceLayer {
        let seed = root.join("seed");
        let repo_dir = seed.join("repo");
        std::fs::create_dir_all(&repo_dir).expect("repository directory");
        std::fs::create_dir_all(seed.join("plain")).expect("plain directory");
        std::fs::write(seed.join("plain/outside.txt"), b"x\n").expect("outside file");

        // The helper builds its seed commit with libgit2 directly, so it needs the isolation
        // `reconcile` installs; a host `core.autocrlf` would otherwise change what looks modified.
        isolate_from_host_config();
        let repository = Repository::init_opts(
            &repo_dir,
            git2::RepositoryInitOptions::new().initial_head("main"),
        )
        .expect("init");

        std::fs::write(repo_dir.join("tracked.txt"), b"seed\n").expect("tracked file");
        std::fs::write(repo_dir.join(".gitignore"), b"ignored.txt\n").expect("ignore rules");
        {
            let mut index = repository.index().expect("index");
            index
                .add_path(Path::new("tracked.txt"))
                .expect("add tracked");
            index
                .add_path(Path::new(".gitignore"))
                .expect("add ignore rules");
            index.write().expect("write index");
            let tree = repository
                .find_tree(index.write_tree().expect("write tree"))
                .expect("tree");
            let signature =
                Signature::new("t", "t@marsh.local", &git2::Time::new(0, 0)).expect("signature");
            repository
                .commit(Some("HEAD"), &signature, &signature, "seed\n", &tree, &[])
                .expect("seed commit");
        }

        std::fs::write(repo_dir.join("dirty.txt"), b"dirty\n").expect("dirty file");
        std::fs::write(repo_dir.join("ignored.txt"), b"ignored\n").expect("ignored file");
        std::fs::write(repo_dir.join("staged.txt"), b"staged\n").expect("staged file");
        {
            let mut index = repository.index().expect("index");
            index.add_path(Path::new("staged.txt")).expect("add staged");
            index.write().expect("write index");
        }

        PersistenceLayer::new(seed, root.join("state"))
    }

    /// One event, spelled the way the log replays it.
    fn event(principal: &str, action: Action, path: &[&str]) -> Event {
        Event::new(principal, action, Resource::from(path.to_vec()))
    }

    /// The row is decided by the last state-changing event on a resource, so that is the only one
    /// worth replaying — and reads, which nothing in the seed can corroborate, are not claims.
    #[test]
    fn a_dirty_resource_keeps_only_the_last_claim_on_it() {
        let scratch_dir = tempfile::tempdir().expect("scratch directory");
        let persistence = scratch(scratch_dir.path());
        let dirty = ["repo", "dirty.txt"];
        let history = vec![
            event("main", Action::Edit, &dirty),
            event("agent", Action::Read, &dirty),
            event("agent", Action::Edit, &dirty),
            event("main", Action::Read, &dirty),
        ];

        assert_eq!(
            reconcile(&persistence, history),
            vec![event("agent", Action::Edit, &dirty)],
            "the last edit owns the row, and it is still dirty in the seed"
        );
    }

    /// A resource whose content sits in the index and nowhere else is exactly what a `stage` claim
    /// asserts, so the recorded event is replayed unchanged.
    #[test]
    fn an_index_only_resource_keeps_its_staged_claim() {
        let scratch_dir = tempfile::tempdir().expect("scratch directory");
        let persistence = scratch(scratch_dir.path());
        let history = vec![event("main", Action::Stage, &["repo", "staged.txt"])];

        assert_eq!(
            reconcile(&persistence, history.clone()),
            history,
            "a staged resource is still owned by the principal that staged it"
        );
    }

    /// Commit, checkout and stash settle a resource into the clean row, which an empty history
    /// already means: replaying them can only refuse a later command for no reason.
    #[test]
    fn a_settled_resource_loses_its_claim() {
        let scratch_dir = tempfile::tempdir().expect("scratch directory");
        let persistence = scratch(scratch_dir.path());
        let dirty = ["repo", "dirty.txt"];
        for action in [Action::commit("m"), Action::Checkout, Action::Stash] {
            let history = vec![
                event("main", Action::Edit, &dirty),
                event("main", action.clone(), &dirty),
            ];
            assert!(
                reconcile(&persistence, history).is_empty(),
                "{action} leaves nothing to claim"
            );
        }
    }

    /// Clean, ignored and absent all mean git holds no uncommitted work at the resource. The last
    /// is the reported bug: a file deleted behind marsh's back kept its edit claim forever.
    #[test]
    fn a_resource_the_seed_shows_no_dirt_for_loses_its_claim() {
        let scratch_dir = tempfile::tempdir().expect("scratch directory");
        let persistence = scratch(scratch_dir.path());
        for name in ["tracked.txt", "ignored.txt", "gone.txt"] {
            let history = vec![event("main", Action::Edit, &["repo", name])];
            assert!(
                reconcile(&persistence, history).is_empty(),
                "{name} carries no dirt to justify a claim"
            );
        }
    }

    /// No repository, no state that could ever settle the claim: marsh's git builtins refuse to run
    /// outside one, so such a claim would stand until the log was deleted.
    #[test]
    fn a_resource_in_no_repository_loses_its_claim() {
        let scratch_dir = tempfile::tempdir().expect("scratch directory");
        let persistence = scratch(scratch_dir.path());
        let history = vec![event("main", Action::Edit, &["plain", "outside.txt"])];

        assert!(reconcile(&persistence, history).is_empty());
    }
}
