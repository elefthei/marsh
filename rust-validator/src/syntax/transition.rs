//! Normalized symbolic-transition smart constructors from `symbolic-matcher.tex`.
//!
//! Transition union and intersection intentionally remain separate. Union is an ACI collector;
//! intersection additionally performs deterministic conditional merging and distributive DNF
//! expansion, so a shared connective skeleton would obscure the normalization algorithm.

use smallvec::SmallVec;

use super::node::{RegexId, RegexKind, TestId, TransitionId, TransitionNode};
use super::store::CanonicalStore;

/// The destructured arms of a `TransitionNode::If`, passed between the intersection helpers.
#[derive(Clone, Copy)]
struct IfArms<'arena> {
    test: TestId<'arena>,
    then_transition: TransitionId<'arena>,
    else_transition: TransitionId<'arena>,
}

impl<'arena> CanonicalStore<'arena> {
    /// Lifts one normalized regex state into a constant transition.
    ///
    /// The three distinguished regex constants reuse preallocated transition constants. Every other
    /// regex is hashconsed as a `Const` leaf, preserving canonical transition identity.
    ///
    /// # Preconditions
    /// `regex` must be a canonical normalized regex from `self`.
    pub(super) fn transition_const(&mut self, regex: RegexId<'arena>) -> TransitionId<'arena> {
        if regex == self.empty {
            self.transition_empty
        } else if regex == self.all {
            self.transition_all
        } else if regex == self.epsilon {
            self.transition_epsilon
        } else {
            self.transitions.mk(TransitionNode::Const(regex))
        }
    }

    /// Interns an already path-cleaned conditional with local reductions.
    ///
    /// Constant guards select their reachable branch, and equal branches erase the conditional.
    /// Unlike [`CanonicalStore::transition_if`], this helper does not descend into either branch or
    /// strengthen the current path condition.
    ///
    /// # Preconditions
    /// `test` and both transition IDs must be canonical values from `self`. Both branches must
    /// already be normalized under the caller's current path condition.
    fn intern_transition_if(
        &mut self,
        test: super::node::TestId<'arena>,
        then_transition: TransitionId<'arena>,
        else_transition: TransitionId<'arena>,
    ) -> TransitionId<'arena> {
        if test == self.test_true {
            then_transition
        } else if test == self.test_false {
            else_transition
        } else if then_transition == else_transition {
            then_transition
        } else {
            self.transitions.mk(TransitionNode::If {
                test,
                then_transition,
                else_transition,
            })
        }
    }

    /// Rewrites a transition DAG under one accumulated path condition.
    ///
    /// Conditional nodes delegate to [`CanonicalStore::clean_conditional_path`]. Every other
    /// constructor is rebuilt through its smart constructor so path cleaning cannot leave flattened,
    /// ordering, complement, or append invariants stale after a child changes.
    ///
    /// # Preconditions
    /// `transition` and `path` must be canonical values from `self`; `path` must be normalized.
    fn clean_transition_path(
        &mut self,
        transition: TransitionId<'arena>,
        path: super::node::TestId<'arena>,
    ) -> TransitionId<'arena> {
        match *transition.get() {
            TransitionNode::Const(_) => transition,
            TransitionNode::If {
                test,
                then_transition,
                else_transition,
            } => self.clean_conditional_path(test, then_transition, else_transition, path),
            TransitionNode::Union(children) => {
                let children = children
                    .iter()
                    .map(|child| self.clean_transition_path(*child, path))
                    .collect::<SmallVec<[TransitionId<'arena>; 4]>>();
                self.transition_union(children)
            }
            TransitionNode::Intersect(children) => {
                let children = children
                    .iter()
                    .map(|child| self.clean_transition_path(*child, path))
                    .collect::<SmallVec<[TransitionId<'arena>; 4]>>();
                self.transition_intersect(children)
            }
            TransitionNode::Not(inner) => {
                let inner = self.clean_transition_path(inner, path);
                self.transition_not(inner)
            }
            TransitionNode::Append { transition, suffix } => {
                let transition = self.clean_transition_path(transition, path);
                self.transition_append(transition, suffix)
            }
        }
    }

    /// Cleans one conditional and its descendants under an accumulated path condition.
    ///
    /// The true branch is analyzed under `path ∧ test`; the false branch under `path ∧ ¬test`.
    /// Contradictory branch paths are discarded before descent. Reachable descendants are then
    /// recursively cleaned with their strengthened path, after which local guard/branch identities
    /// are applied by [`CanonicalStore::intern_transition_if`].
    ///
    /// # Preconditions
    /// The test, path, and branches must be canonical values from `self`. `path` and `test` must be
    /// normalized; each branch must already satisfy the transition smart-constructor invariants.
    fn clean_conditional_path(
        &mut self,
        test: super::node::TestId<'arena>,
        then_transition: TransitionId<'arena>,
        else_transition: TransitionId<'arena>,
        path: super::node::TestId<'arena>,
    ) -> TransitionId<'arena> {
        if test == self.test_true {
            return self.clean_transition_path(then_transition, path);
        }
        if test == self.test_false {
            return self.clean_transition_path(else_transition, path);
        }
        if then_transition == else_transition {
            return self.clean_transition_path(then_transition, path);
        }

        let true_path = self.test_and([path, test]);
        let complement = self.test_not(test);
        let false_path = self.test_and([path, complement]);
        if true_path == self.test_false {
            return self.clean_transition_path(else_transition, false_path);
        }
        if false_path == self.test_false {
            return self.clean_transition_path(then_transition, true_path);
        }

        let then_transition = self.clean_transition_path(then_transition, true_path);
        let else_transition = self.clean_transition_path(else_transition, false_path);
        self.intern_transition_if(test, then_transition, else_transition)
    }

    /// Constructs a normalized conditional and removes path-infeasible nested branches.
    ///
    /// Cleaning starts from the true path, so this is the public smart-constructor boundary for
    /// conditionals whose descendants may not yet reflect their enclosing guard.
    ///
    /// # Preconditions
    /// `test` and both branches must be canonical values from `self`. Input branches may contain
    /// path-infeasible descendants; this constructor removes them.
    pub(super) fn transition_if(
        &mut self,
        test: super::node::TestId<'arena>,
        then_transition: TransitionId<'arena>,
        else_transition: TransitionId<'arena>,
    ) -> TransitionId<'arena> {
        self.clean_conditional_path(test, then_transition, else_transition, self.test_true)
    }

    /// Constructs flattened, ordered, deduplicated transition union.
    ///
    /// Universal leaves absorb the union, empty leaves are identities, and nested unions flatten.
    /// All remaining constant-regex leaves are combined once through `regex_union`; this ensures
    /// regex-level complement, test grouping, epsilon, and absorption laws run before the transition
    /// operands are sorted and deduplicated. Zero and one operands collapse to their canonical forms.
    ///
    /// # Preconditions
    /// Every child must be a canonical normalized transition from `self`. Input order,
    /// same-connective nesting, and duplicates are unrestricted.
    pub(super) fn transition_union(
        &mut self,
        children: impl IntoIterator<Item = TransitionId<'arena>>,
    ) -> TransitionId<'arena> {
        let mut flat = SmallVec::<[TransitionId<'arena>; 4]>::new();
        for child in children {
            match *child.get() {
                TransitionNode::Const(regex) if regex == self.all => return self.transition_all,
                TransitionNode::Const(regex) if regex == self.empty => {}
                TransitionNode::Union(nested) => flat.extend_from_slice(nested),
                _ => flat.push(child),
            }
        }

        let mut constants = SmallVec::<[RegexId<'arena>; 4]>::new();
        flat.retain(|child| match *child.get() {
            TransitionNode::Const(regex) => {
                constants.push(regex);
                false
            }
            _ => true,
        });
        if !constants.is_empty() {
            let regex = self.regex_union(constants);
            if regex == self.all {
                return self.transition_all;
            }
            if regex != self.empty {
                let transition = self.transition_const(regex);
                flat.push(transition);
            }
        }

        flat.sort_unstable();
        flat.dedup();
        match flat.as_slice() {
            [] => self.transition_empty,
            [only] => *only,
            _ => {
                let values = self.transitions.arena().alloc_slice_copy(&flat);
                self.transitions.mk(TransitionNode::Union(values))
            }
        }
    }

    /// Intersects two normalized transitions and performs one deterministic DNF expansion step.
    ///
    /// The method first handles idempotence, constant identities/absorbers, and constant-regex
    /// intersection. It then merges equal conditional guards, combines one-sided guards, or expands
    /// the lower ordered guard first. Union operands distribute into intersections, and a remaining
    /// conditional is pushed above the intersection. Only a pair requiring none of those rewrites is
    /// interned as an ordered `Intersect` node.
    ///
    /// # Preconditions
    /// Both transitions must be canonical normalized values from `self`. Conditional guards and all
    /// commutative child slices reachable from them must be sorted and deduplicated.
    fn transition_intersect_pair(
        &mut self,
        left: TransitionId<'arena>,
        right: TransitionId<'arena>,
    ) -> TransitionId<'arena> {
        if left == right {
            return left;
        }
        match (*left.get(), *right.get()) {
            (TransitionNode::Const(regex), _) if regex == self.empty => {
                return self.transition_empty;
            }
            (_, TransitionNode::Const(regex)) if regex == self.empty => {
                return self.transition_empty;
            }
            (TransitionNode::Const(regex), _) if regex == self.all => return right,
            (_, TransitionNode::Const(regex)) if regex == self.all => return left,
            (TransitionNode::Const(left), TransitionNode::Const(right)) => {
                let regex = self.regex_intersect([left, right]);
                return self.transition_const(regex);
            }
            (
                TransitionNode::If {
                    test: left_test,
                    then_transition: left_then,
                    else_transition: left_else,
                },
                TransitionNode::If {
                    test: right_test,
                    then_transition: right_then,
                    else_transition: right_else,
                },
            ) => {
                return self.transition_intersect_conditionals(
                    IfArms {
                        test: left_test,
                        then_transition: left_then,
                        else_transition: left_else,
                    },
                    IfArms {
                        test: right_test,
                        then_transition: right_then,
                        else_transition: right_else,
                    },
                    left,
                    right,
                );
            }
            (TransitionNode::Union(children), _) => {
                let intersections = children
                    .iter()
                    .map(|child| self.transition_intersect([*child, right]))
                    .collect::<SmallVec<[TransitionId<'arena>; 4]>>();
                return self.transition_union(intersections);
            }
            (_, TransitionNode::Union(children)) => {
                let intersections = children
                    .iter()
                    .map(|child| self.transition_intersect([left, *child]))
                    .collect::<SmallVec<[TransitionId<'arena>; 4]>>();
                return self.transition_union(intersections);
            }
            (
                TransitionNode::If {
                    test,
                    then_transition,
                    else_transition,
                },
                _,
            ) => {
                let then_transition = self.transition_intersect([then_transition, right]);
                let else_transition = self.transition_intersect([else_transition, right]);
                return self.transition_if(test, then_transition, else_transition);
            }
            (
                _,
                TransitionNode::If {
                    test,
                    then_transition,
                    else_transition,
                },
            ) => {
                let then_transition = self.transition_intersect([left, then_transition]);
                let else_transition = self.transition_intersect([left, else_transition]);
                return self.transition_if(test, then_transition, else_transition);
            }
            _ => {}
        }

        let mut children = SmallVec::<[TransitionId<'arena>; 4]>::from_slice(&[left, right]);
        children.sort_unstable();
        let values = self.transitions.arena().alloc_slice_copy(&children);
        self.transitions.mk(TransitionNode::Intersect(values))
    }

    /// Intersects two conditional transitions, preserving the deterministic guard ordering.
    ///
    /// Two guarded conditionals (both `else` branches empty) conjoin their guards. Otherwise equal
    /// tests recurse branchwise, and unequal tests expand one operand over the other: a guarded
    /// operand always expands first, so a guard never sinks below an unguarded conditional; when
    /// neither is guarded the lower ordered test expands, which is what makes the result canonical.
    ///
    /// # Preconditions
    /// `left`/`right` must be the destructured arms of the canonical conditionals `left_id` and
    /// `right_id` respectively.
    fn transition_intersect_conditionals(
        &mut self,
        left: IfArms<'arena>,
        right: IfArms<'arena>,
        left_id: TransitionId<'arena>,
        right_id: TransitionId<'arena>,
    ) -> TransitionId<'arena> {
        if left.else_transition == self.transition_empty
            && right.else_transition == self.transition_empty
        {
            let guard = self.test_and([left.test, right.test]);
            if guard == self.test_false {
                return self.transition_empty;
            }
            let then_transition =
                self.transition_intersect([left.then_transition, right.then_transition]);
            return self.transition_if(guard, then_transition, self.transition_empty);
        }

        if left.test == right.test {
            let then_transition =
                self.transition_intersect([left.then_transition, right.then_transition]);
            let else_transition =
                self.transition_intersect([left.else_transition, right.else_transition]);
            return self.transition_if(left.test, then_transition, else_transition);
        }

        let expand_left = if left.else_transition == self.transition_empty {
            true
        } else if right.else_transition == self.transition_empty {
            false
        } else {
            left.test < right.test
        };
        if expand_left {
            let then_transition = self.transition_intersect([left.then_transition, right_id]);
            let else_transition = self.transition_intersect([left.else_transition, right_id]);
            return self.transition_if(left.test, then_transition, else_transition);
        }
        let then_transition = self.transition_intersect([left_id, right.then_transition]);
        let else_transition = self.transition_intersect([left_id, right.else_transition]);
        self.transition_if(right.test, then_transition, else_transition)
    }

    /// Constructs transition intersection in deterministic disjunctive normal form.
    ///
    /// Empty leaves absorb, universal leaves are identities, and nested intersections flatten.
    /// Constant-regex leaves are combined through `regex_intersect`. Remaining operands are sorted,
    /// deduplicated, then folded through [`CanonicalStore::transition_intersect_pair`], whose ordered
    /// expansion rules produce the canonical DNF. This differs materially from `transition_union`,
    /// which never needs a pairwise distributive fold.
    ///
    /// # Preconditions
    /// Every child must be a canonical normalized transition from `self`. Input order,
    /// same-connective nesting, and duplicates are unrestricted.
    pub(super) fn transition_intersect(
        &mut self,
        children: impl IntoIterator<Item = TransitionId<'arena>>,
    ) -> TransitionId<'arena> {
        let mut flat = SmallVec::<[TransitionId<'arena>; 4]>::new();
        for child in children {
            match *child.get() {
                TransitionNode::Const(regex) if regex == self.empty => {
                    return self.transition_empty;
                }
                TransitionNode::Const(regex) if regex == self.all => {}
                TransitionNode::Intersect(nested) => flat.extend_from_slice(nested),
                _ => flat.push(child),
            }
        }

        let mut constants = SmallVec::<[RegexId<'arena>; 4]>::new();
        flat.retain(|child| match *child.get() {
            TransitionNode::Const(regex) => {
                constants.push(regex);
                false
            }
            _ => true,
        });
        if !constants.is_empty() {
            let regex = self.regex_intersect(constants);
            if regex == self.empty {
                return self.transition_empty;
            }
            if regex != self.all {
                let transition = self.transition_const(regex);
                flat.push(transition);
            }
        }

        flat.sort_unstable();
        flat.dedup();
        let mut children = flat.into_iter();
        let Some(first) = children.next() else {
            return self.transition_all;
        };
        children.fold(first, |result, child| {
            self.transition_intersect_pair(result, child)
        })
    }

    /// Pushes transition complement through Boolean structure and conditionals to regex leaves.
    ///
    /// Constant leaves delegate to `regex_not`; conditionals complement both branches; union and
    /// intersection use De Morgan duality. A Boolean-marker conditional is optimized by complementing
    /// its guard. `Append` remains beneath an explicit `Not` because complement does not distribute
    /// through regex concatenation.
    ///
    /// # Preconditions
    /// `transition` must be a canonical normalized transition from `self`.
    pub(super) fn transition_not(
        &mut self,
        transition: TransitionId<'arena>,
    ) -> TransitionId<'arena> {
        match *transition.get() {
            TransitionNode::Const(regex) => {
                let regex = self.regex_not(regex);
                self.transition_const(regex)
            }
            TransitionNode::If {
                test,
                then_transition,
                else_transition,
            } if then_transition == self.transition_all
                && else_transition == self.transition_empty =>
            {
                let test = self.test_not(test);
                self.transition_if(test, self.transition_all, self.transition_empty)
            }
            TransitionNode::If {
                test,
                then_transition,
                else_transition,
            } => {
                let then_transition = self.transition_not(then_transition);
                let else_transition = self.transition_not(else_transition);
                self.transition_if(test, then_transition, else_transition)
            }
            TransitionNode::Union(children) => {
                let complements = children
                    .iter()
                    .map(|child| self.transition_not(*child))
                    .collect::<SmallVec<[TransitionId<'arena>; 4]>>();
                self.transition_intersect(complements)
            }
            TransitionNode::Intersect(children) => {
                let complements = children
                    .iter()
                    .map(|child| self.transition_not(*child))
                    .collect::<SmallVec<[TransitionId<'arena>; 4]>>();
                self.transition_union(complements)
            }
            TransitionNode::Not(inner) => inner,
            TransitionNode::Append { .. } => self.transitions.mk(TransitionNode::Not(transition)),
        }
    }

    /// Appends a fixed normalized regex suffix to every reachable transition result.
    ///
    /// The suffix is normalized once. Empty and epsilon results short-circuit; constants concatenate
    /// immediately; unions and conditionals distribute the append; nested appends combine suffixes.
    /// Intersection and complement retain an explicit `Append` node because concatenation does not
    /// distribute through those operators.
    ///
    /// # Preconditions
    /// `transition` and every regex in `suffix` must be canonical normalized values from `self`.
    /// Suffix order is semantic; duplicates are permitted.
    pub(super) fn transition_append(
        &mut self,
        transition: TransitionId<'arena>,
        suffix: &[RegexId<'arena>],
    ) -> TransitionId<'arena> {
        if suffix.is_empty() {
            return transition;
        }
        let normalized = self.regex_concat(suffix.to_vec());
        if normalized == self.epsilon {
            return transition;
        }
        if normalized == self.empty {
            return self.transition_empty;
        }
        let suffix: SmallVec<[RegexId<'arena>; 4]> = match normalized.get().kind {
            RegexKind::Concat(factors) => SmallVec::from_slice(factors),
            _ => SmallVec::from_slice(&[normalized]),
        };

        match *transition.get() {
            TransitionNode::Const(regex) => {
                let mut factors = SmallVec::<[RegexId<'arena>; 4]>::new();
                factors.push(regex);
                factors.extend_from_slice(&suffix);
                let regex = self.regex_concat(factors);
                self.transition_const(regex)
            }
            TransitionNode::Union(children) => {
                let appended = children
                    .iter()
                    .map(|child| self.transition_append(*child, &suffix))
                    .collect::<SmallVec<[TransitionId<'arena>; 4]>>();
                self.transition_union(appended)
            }
            TransitionNode::If {
                test,
                then_transition,
                else_transition,
            } => {
                let then_transition = self.transition_append(then_transition, &suffix);
                let else_transition = self.transition_append(else_transition, &suffix);
                self.transition_if(test, then_transition, else_transition)
            }
            TransitionNode::Append {
                transition,
                suffix: existing,
            } => {
                let mut combined = SmallVec::<[RegexId<'arena>; 4]>::new();
                combined.extend_from_slice(existing);
                combined.extend_from_slice(&suffix);
                self.transition_append(transition, &combined)
            }
            TransitionNode::Intersect(_) | TransitionNode::Not(_) => {
                let values = self.transitions.arena().alloc_slice_copy(&suffix);
                self.transitions.mk(TransitionNode::Append {
                    transition,
                    suffix: values,
                })
            }
        }
    }
}
