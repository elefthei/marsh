//! Smart constructors for canonical test and regex DAGs.
//!
//! The constructors implement `Norm_B` and `Norm` from `symbolic-matcher.tex`: flattened ACI
//! Boolean operators, absorption and contradiction reductions, flattened regex set operators,
//! ordered concatenation, cross-layer test reductions, and cached nullability. Test conjunction and
//! disjunction share one typed dual algorithm. Regex union and intersection remain explicit because
//! their epsilon, nullability, and lifted-test reductions are materially different.

use smallvec::SmallVec;

use super::component::CompiledAtomPattern;
use super::node::{RegexId, RegexKind, RegexNode, TestId, TestNode};
use super::source::{Comparison, ComponentPattern};
use super::store::CanonicalStore;

/// Returns whether any unordered pair satisfies `predicate`.
///
/// Each distinct pair is tested exactly once, no value is paired with itself, and evaluation stops
/// on the first match. The worst case is quadratic in `values.len()`; callers use this only for
/// small normalized sibling sets.
///
/// Example traversal: for `[a, b, c]`, the predicate sees `(a, b)`, `(a, c)`, then `(b, c)` until
/// one pair matches.
///
/// # Preconditions
/// `predicate` must be symmetric because `(left, right)` is presented in only one orientation.
fn pair_satisfies<T: Copy>(values: &[T], mut predicate: impl FnMut(T, T) -> bool) -> bool {
    values.iter().enumerate().any(|(index, left)| {
        values[index + 1..]
            .iter()
            .any(|right| predicate(*left, *right))
    })
}

/// Recognizes direct complementation between two atomic tests.
///
/// The pair is complementary exactly when it tests the same compiled component pattern with
/// opposite comparisons, for example `action == Read` and `action != Read`. Compound De Morgan
/// complements are handled separately by [`CanonicalStore::tests_have_complements`].
///
/// Example reductions enabled by a match:
///
/// ```text
/// Eq(action, Read) ∧ Neq(action, Read) → false
/// Eq(action, Read) ∨ Neq(action, Read) → true
/// ```
///
/// # Preconditions
/// Both IDs must be canonical tests from the same [`CanonicalStore`].
fn complementary_test<'arena>(left: TestId<'arena>, right: TestId<'arena>) -> bool {
    matches!(
        (*left.get(), *right.get()),
        (
            TestNode::Atom {
                comparison: left_comparison,
                pattern: left_pattern,
            },
            TestNode::Atom {
                comparison: right_comparison,
                pattern: right_pattern,
            },
        ) if left_comparison != right_comparison && left_pattern == right_pattern
    )
}

/// Recognizes unequal constants selected from the same product coordinate.
///
/// Constants from different coordinates are incomparable: `principal == alice` and
/// `action == Read` are not a distinct-constant pair. Variables are also excluded because their
/// values are not known during normalization.
///
/// Examples:
///
/// ```text
/// distinct(Principal("alice"), Principal("bob")) = true
/// distinct(Principal("alice"), Action(Read)) = false
/// distinct(Principal($p), Principal("alice")) = false
/// ```
///
/// # Preconditions
/// Both patterns must have been compiled by the same [`CanonicalStore`].
fn distinct_constant_patterns(
    left: CompiledAtomPattern<'_>,
    right: CompiledAtomPattern<'_>,
) -> bool {
    match (left, right) {
        (
            CompiledAtomPattern::Principal(ComponentPattern::Constant(left)),
            CompiledAtomPattern::Principal(ComponentPattern::Constant(right)),
        ) => left != right,
        (
            CompiledAtomPattern::Action(ComponentPattern::Constant(left)),
            CompiledAtomPattern::Action(ComponentPattern::Constant(right)),
        ) => left != right,
        (
            CompiledAtomPattern::Resource(ComponentPattern::Constant(left)),
            CompiledAtomPattern::Resource(ComponentPattern::Constant(right)),
        ) => left != right,
        _ => false,
    }
}

/// Recognizes two atoms that use `comparison` on distinct constants of one coordinate.
///
/// With [`Comparison::Eq`], the pair is contradictory in conjunction. With [`Comparison::Neq`],
/// the pair is exhaustive in disjunction because one finite-product coordinate cannot equal both
/// distinct constants.
///
/// Example reductions for distinct constants `alice != bob`:
///
/// ```text
/// Eq(principal, alice) ∧ Eq(principal, bob) → false
/// Neq(principal, alice) ∨ Neq(principal, bob) → true
/// ```
///
/// # Preconditions
/// Both IDs must be canonical tests from the same [`CanonicalStore`].
fn distinct_constant_atoms(left: TestId<'_>, right: TestId<'_>, comparison: Comparison) -> bool {
    matches!(
        (*left.get(), *right.get()),
        (
            TestNode::Atom {
                comparison: left_comparison,
                pattern: left_pattern,
            },
            TestNode::Atom {
                comparison: right_comparison,
                pattern: right_pattern,
            },
        ) if left_comparison == comparison
            && right_comparison == comparison
            && distinct_constant_patterns(left_pattern, right_pattern)
    )
}

/// Returns whether a constant atom can be removed because a sibling implies it.
///
/// `candidate_comparison` identifies the atom being considered for removal. The sibling must use
/// its opposite comparison and select a distinct constant in the same component domain. Thus the
/// two call sites implement the dual implications:
///
/// - conjunction: `Eq(c) ∧ Neq(d) = Eq(c)` for `c != d`, so the `Neq(d)` candidate is removed;
/// - disjunction: `Neq(d) ∨ Eq(c) = Neq(d)` for `c != d`, so the `Eq(c)` candidate is removed.
///
/// Example reductions for `c != d`:
///
/// ```text
/// Eq(component, c) ∧ Neq(component, d) → Eq(component, c)
/// Neq(component, d) ∨ Eq(component, c) → Neq(component, d)
/// ```
///
/// # Preconditions
/// `candidate` and every ID in `siblings` must be canonical tests from the same store. The sibling
/// slice need not be sorted.
fn redundant_constant_atom(
    candidate: TestId<'_>,
    siblings: &[TestId<'_>],
    candidate_comparison: Comparison,
) -> bool {
    let TestNode::Atom {
        comparison,
        pattern: candidate_pattern,
    } = *candidate.get()
    else {
        return false;
    };
    let sibling_comparison = !candidate_comparison;
    comparison == candidate_comparison
        && siblings.iter().copied().any(|sibling| {
            let TestNode::Atom {
                comparison,
                pattern,
            } = *sibling.get()
            else {
                return false;
            };
            comparison == sibling_comparison
                && distinct_constant_patterns(candidate_pattern, pattern)
        })
}

/// Recognizes a compound operand absorbed by another operand of the outer connective.
///
/// For an outer conjunction, `candidate` must be a disjunction. A plain sibling implements direct
/// absorption, `x ∧ (x ∨ y) = x`; a disjunctive sibling whose children are a subset of the
/// candidate's children implements generalized absorption,
/// `(x ∨ y) ∧ (x ∨ y ∨ z) = x ∨ y`. Outer disjunction uses the dual laws
/// `x ∨ (x ∧ y) = x` and `(x ∧ y) ∨ (x ∧ y ∧ z) = x ∧ y`.
///
/// An operand is never compared with itself. The outer smart constructors sort and deduplicate
/// their operands before calling this helper, so idempotence (`x ∧ x = x`, `x ∨ x = x`) has
/// already retained exactly one representative.
///
/// Example reductions:
///
/// ```text
/// x ∧ (x ∨ y) → x
/// (x ∨ y) ∧ (x ∨ y ∨ z) → x ∨ y
/// x ∨ (x ∧ y) → x
/// (x ∧ y) ∨ (x ∧ y ∧ z) → x ∧ y
/// ```
///
/// # Preconditions
/// `siblings` must be sorted and deduplicated. Every opposite-connective child slice must also be
/// sorted and deduplicated. All IDs must belong to the same [`CanonicalStore`].
fn absorbed_by_sibling<'arena>(candidate: TestId<'arena>, siblings: &[TestId<'arena>]) -> bool {
    siblings.iter().copied().any(|sibling| {
        // Do not remove the sole representative left by the caller's idempotence reduction.
        if sibling == candidate {
            return false;
        }
        match (*candidate.get(), *sibling.get()) {
            // Generalized absorption: the sibling's child set is a subset of the candidate's.
            (TestNode::Or(nested), TestNode::Or(children))
            | (TestNode::And(nested), TestNode::And(children)) => children
                .iter()
                .all(|child| nested.binary_search(child).is_ok()),
            // Direct absorption: the sibling is one of the candidate's nested operands.
            (TestNode::Or(nested), _) | (TestNode::And(nested), _) => {
                nested.binary_search(&sibling).is_ok()
            }
            _ => false,
        }
    })
}

/// Recognizes direct whole-language complementation between two regex nodes.
///
/// Exactly one operand must be the canonical `Not` node whose child is the other operand. Test-level
/// complements are grouped and normalized before this regex-level check.
///
/// Example reductions enabled by a match:
///
/// ```text
/// R ∪ Not(R) → All
/// R ∩ Not(R) → Empty
/// ```
///
/// # Preconditions
/// Both IDs must be canonical regexes from the same [`CanonicalStore`].
fn complementary_regex<'arena>(left: RegexId<'arena>, right: RegexId<'arena>) -> bool {
    matches!(left.get().kind, RegexKind::Not(inner) if inner == right)
        || matches!(right.get().kind, RegexKind::Not(inner) if inner == left)
}

/// Recognizes the canonical language complement of epsilon.
///
/// This predicate supports the intersection law that `Not(Epsilon)` is redundant beside any
/// non-nullable language. It intentionally matches only the direct canonical `Not(Epsilon)` form.
///
/// Example reduction for a non-nullable language `R`:
///
/// ```text
/// R ∩ Not(Epsilon) → R
/// ```
///
/// # Preconditions
/// `regex` must be a canonical regex from the current [`CanonicalStore`].
fn is_epsilon_complement(regex: RegexId<'_>) -> bool {
    matches!(regex.get().kind, RegexKind::Not(inner) if matches!(inner.get().kind, RegexKind::Epsilon))
}

/// Recognizes a compound regex operand absorbed by another operand of the outer set connective.
///
/// For outer union, `candidate` must be an intersection. A plain sibling implements
/// `R ∪ (R ∩ S) = R`; an intersecting sibling whose children are a subset of the candidate's
/// children implements `(R ∩ S) ∪ (R ∩ S ∩ T) = R ∩ S`. Outer intersection uses the dual laws
/// `R ∩ (R ∪ S) = R` and `(R ∪ S) ∩ (R ∪ S ∪ T) = R ∪ S`.
///
/// An operand is never compared with itself. The outer smart constructors sort and deduplicate
/// their operands first, so set-union/set-intersection idempotence has already retained exactly one
/// representative.
///
/// Example reductions:
///
/// ```text
/// R ∪ (R ∩ S) → R
/// (R ∩ S) ∪ (R ∩ S ∩ T) → R ∩ S
/// R ∩ (R ∪ S) → R
/// (R ∪ S) ∩ (R ∪ S ∪ T) → R ∪ S
/// ```
///
/// # Preconditions
/// `siblings` must be sorted and deduplicated. Every opposite-connective child slice must also be
/// sorted and deduplicated. All IDs must belong to the same [`CanonicalStore`].
fn regex_absorbed_by_sibling<'arena>(
    candidate: RegexId<'arena>,
    siblings: &[RegexId<'arena>],
) -> bool {
    siblings.iter().copied().any(|sibling| {
        // Do not remove the sole representative left by the caller's idempotence reduction.
        if sibling == candidate {
            return false;
        }
        match (candidate.get().kind, sibling.get().kind) {
            // Generalized absorption: the sibling's child set is a subset of the candidate's.
            (RegexKind::Intersect(nested), RegexKind::Intersect(children))
            | (RegexKind::Union(nested), RegexKind::Union(children)) => children
                .iter()
                .all(|child| nested.binary_search(child).is_ok()),
            // Direct absorption: the sibling is one of the candidate's nested operands.
            (RegexKind::Intersect(nested), _) | (RegexKind::Union(nested), _) => {
                nested.binary_search(&sibling).is_ok()
            }
            _ => false,
        }
    })
}

/// Outer connective whose siblings are being normalized.
///
/// The enum carries only the dual choices required by Boolean-test normalization. It deliberately
/// does not abstract regex or transition normalization, whose identities and rewrite systems differ.
#[derive(Clone, Copy)]
enum TestConnective {
    And,
    Or,
}

impl TestConnective {
    /// Returns the De Morgan dual connective.
    ///
    /// Example mapping: `And.dual() = Or`, `Or.dual() = And`; consequently
    /// `Not(x ∧ y) → Not(x) ∨ Not(y)` and `Not(x ∨ y) → Not(x) ∧ Not(y)`.
    fn dual(self) -> Self {
        match self {
            Self::And => Self::Or,
            Self::Or => Self::And,
        }
    }

    /// Identity element removed from this connective: `true` for `And`, `false` for `Or`.
    ///
    /// Example reductions: `x ∧ true → x`; `x ∨ false → x`.
    fn identity<'arena>(self, store: &CanonicalStore<'arena>) -> TestId<'arena> {
        match self {
            Self::And => store.test_true,
            Self::Or => store.test_false,
        }
    }

    /// Absorbing element that determines the whole result: `false` for `And`, `true` for `Or`.
    ///
    /// Example reductions: `x ∧ false → false`; `x ∨ true → true`.
    fn absorber<'arena>(self, store: &CanonicalStore<'arena>) -> TestId<'arena> {
        match self {
            Self::And => store.test_false,
            Self::Or => store.test_true,
        }
    }

    /// Returns children of a nested occurrence of this same connective for associative flattening.
    ///
    /// Example reductions: `(x ∧ y) ∧ z → x ∧ y ∧ z`; `(x ∨ y) ∨ z → x ∨ y ∨ z`.
    /// `And.children(Or([x, y]))` and its dual return `None`.
    fn children<'arena>(self, node: TestNode<'arena>) -> Option<&'arena [TestId<'arena>]> {
        match (self, node) {
            (Self::And, TestNode::And(children)) | (Self::Or, TestNode::Or(children)) => {
                Some(children)
            }
            _ => None,
        }
    }

    /// Comparison whose distinct constants make the connective constant.
    ///
    /// Example reductions for `c != d`: `Eq(c) ∧ Eq(d) → false` and
    /// `Neq(c) ∨ Neq(d) → true`.
    fn contradictory_comparison(self) -> Comparison {
        match self {
            Self::And => Comparison::Eq,
            Self::Or => Comparison::Neq,
        }
    }

    /// Comparison of a candidate atom removable when a distinct opposite atom implies it.
    ///
    /// Example reductions for `c != d`: `Eq(c) ∧ Neq(d) → Eq(c)` and
    /// `Neq(c) ∨ Eq(d) → Neq(c)`.
    fn redundant_comparison(self) -> Comparison {
        !self.contradictory_comparison()
    }

    /// Constructs the canonical node variant for two or more normalized children.
    ///
    /// Example mappings: `And.node([x, y]) = And([x, y])` and
    /// `Or.node([x, y]) = Or([x, y])`.
    fn node<'arena>(self, children: &'arena [TestId<'arena>]) -> TestNode<'arena> {
        match self {
            Self::And => TestNode::And(children),
            Self::Or => TestNode::Or(children),
        }
    }
}

impl<'arena> CanonicalStore<'arena> {
    /// Returns whether normalized siblings make their outer connective constant by complementation.
    ///
    /// `connective` identifies the outer operation:
    ///
    /// - [`TestConnective::And`] asks whether the siblings contain a contradiction, so their
    ///   conjunction is false;
    /// - [`TestConnective::Or`] asks whether the siblings contain a tautology, so their disjunction
    ///   is true.
    ///
    /// The first check recognizes a direct atomic pair `Eq(p)` and `Neq(p)`. The second recognizes
    /// the canonical form left after complement pushing and flattening. For an outer conjunction,
    /// an `Or(c₁, …, cₙ)` candidate is contradictory when every `Not(cᵢ)` is also an outer sibling:
    ///
    /// ```text
    /// (c₁ ∨ c₂) ∧ ¬c₁ ∧ ¬c₂ = false
    /// ```
    ///
    /// For an outer disjunction, the dual condition makes an `And(c₁, …, cₙ)` candidate a
    /// tautology when every `Not(cᵢ)` is an outer sibling:
    ///
    /// ```text
    /// (c₁ ∧ c₂) ∨ ¬c₁ ∨ ¬c₂ = true
    /// ```
    ///
    /// These are the flattened De Morgan forms of `x ∧ ¬x` and `x ∨ ¬x`; the compound complement
    /// is not necessarily present as one sibling node. This is a syntactic normalization rule, not
    /// a general satisfiability check. Calling [`CanonicalStore::test_not`] may intern normalized
    /// complements, which is why this query mutably borrows the store.
    ///
    /// # Preconditions
    /// `tests` must be the flattened outer operands, sorted and deduplicated. Every nested Boolean
    /// child slice must also be sorted and deduplicated. All IDs must belong to `self`; sortedness is
    /// required by the binary searches for the child complements.
    fn tests_have_complements(
        &mut self,
        tests: &[TestId<'arena>],
        connective: TestConnective,
    ) -> bool {
        // Direct atomic complementation: Eq(p) and Neq(p).
        if pair_satisfies(tests, complementary_test) {
            return true;
        }
        // Compound complementation after De Morgan normalization and outer-connective flattening.
        tests.iter().copied().any(|candidate| {
            let Some(dual_children) = connective.dual().children(*candidate.get()) else {
                return false;
            };
            // Every child must have its normalized complement as a separate outer sibling.
            dual_children.iter().all(|child| {
                let complement = self.test_not(*child);
                tests.binary_search(&complement).is_ok()
            })
        })
    }

    /// Normalizes one associative, commutative, idempotent Boolean connective.
    ///
    /// The algorithm performs the same ordered stages for conjunction and disjunction:
    ///
    /// 1. return immediately on the absorbing element, remove identities, and flatten nested uses
    ///    of the same connective;
    /// 2. sort and deduplicate children, establishing canonical order and idempotence;
    /// 3. collapse direct/compound complements and incompatible constant atoms to the absorber;
    /// 4. remove operands made redundant by absorption or finite-product constant implication;
    /// 5. return the identity, the sole child, or one hashconsed connective node.
    ///
    /// Representative reductions performed by this shared algorithm:
    ///
    /// ```text
    /// x ∧ true → x                    x ∨ false → x
    /// x ∧ false → false               x ∨ true → true
    /// x ∧ x → x                       x ∨ x → x
    /// x ∧ Not(x) → false              x ∨ Not(x) → true
    /// x ∧ (x ∨ y) → x                 x ∨ (x ∧ y) → x
    /// Eq(c) ∧ Eq(d) → false           Neq(c) ∨ Neq(d) → true    when c != d
    /// Eq(c) ∧ Neq(d) → Eq(c)          Neq(c) ∨ Eq(d) → Neq(c)  when c != d
    /// ```
    ///
    /// # Preconditions
    /// Every child must be a canonical test from `self`. Input order, nesting, and duplicates are
    /// unrestricted. Same-connective child slices already stored in canonical nodes are sorted and
    /// deduplicated.
    fn test_connective(
        &mut self,
        children: impl IntoIterator<Item = TestId<'arena>>,
        connective: TestConnective,
    ) -> TestId<'arena> {
        // Resolve the two constants once. For conjunction these are identity=true and
        // absorber=false; for disjunction they are identity=false and absorber=true.
        let identity = connective.identity(self);
        let absorber = connective.absorber(self);

        // Apply the local ACI laws while collecting operands. An absorber determines the complete
        // result immediately. Identities contribute nothing. Pulling children out of a nested node
        // with the same connective establishes associativity without rebuilding an intermediate
        // canonical node.
        let mut flat = SmallVec::<[TestId<'arena>; 4]>::new();
        for child in children {
            // x ∧ false = false; x ∨ true = true.
            if child == absorber {
                return absorber;
            }
            // x ∧ true = x; x ∨ false = x.
            if child == identity {
                continue;
            }
            // (x ◦ y) ◦ z = x ◦ y ◦ z for the selected connective ◦.
            if let Some(nested) = connective.children(*child.get()) {
                flat.extend_from_slice(nested);
            } else {
                flat.push(child);
            }
        }

        // Canonical order supplies commutativity; deduplication supplies idempotence. The sorted
        // representation is also required by the binary-search subset and complement checks below.
        flat.sort_unstable();
        flat.dedup();

        // Collapse combinations that make the complete connective constant. Complement detection
        // covers x ◦ ¬x and its flattened De Morgan forms. The finite-product rule covers two
        // distinct equalities in conjunction, or two distinct disequalities in disjunction.
        let contradictory_comparison = connective.contradictory_comparison();
        if self.tests_have_complements(&flat, connective)
            || pair_satisfies(&flat, |left, right| {
                distinct_constant_atoms(left, right, contradictory_comparison)
            })
        {
            // A contradiction collapses conjunction to false; a tautology collapses disjunction to
            // true. Both are the selected connective's absorber.
            return absorber;
        }

        // The remaining rewrites delete individual operands rather than collapsing the whole
        // expression. Only a dual compound or an atom with the removable comparison can qualify,
        // so avoid cloning and scanning the sibling list when neither shape occurs.
        let redundant_comparison = connective.redundant_comparison();
        if flat.iter().any(|candidate| {
            connective.dual().children(*candidate.get()).is_some()
                || matches!(
                    *candidate.get(),
                    TestNode::Atom { comparison, .. } if comparison == redundant_comparison
                )
        }) {
            // Retention needs the original complete sibling set: removing one candidate must not
            // change whether a later candidate was redundant in the original normalized expression.
            let siblings = flat.clone();
            flat.retain(|candidate| {
                // Remove x ◦ (x dual y), generalized subset absorption, and the finite-product
                // implication Eq(c) ∧ Neq(d) / Neq(d) ∨ Eq(c) for distinct constants c and d.
                !absorbed_by_sibling(*candidate, &siblings)
                    && !redundant_constant_atom(*candidate, &siblings, redundant_comparison)
            });
        }

        // Close the variadic connective after all rewrites. Zero children denote the identity; one
        // child needs no wrapper; only a genuine compound expression is arena-allocated and interned.
        match flat.as_slice() {
            [] => identity,
            [only] => *only,
            _ => {
                // Canonical children are immutable, so copy the finalized slice into the arena before
                // hashconsing the node.
                let values = self.tests.arena().alloc_slice_copy(&flat);
                self.tests.mk(connective.node(values))
            }
        }
    }

    /// Constructs canonical conjunction over one-event tests.
    ///
    /// This is the descriptive entry point for [`CanonicalStore::test_connective`]. It applies
    /// conjunction identities, contradictions, absorption, and constant implications before
    /// hashconsing the result.
    ///
    /// Example reductions:
    ///
    /// ```text
    /// And([]) → true
    /// x ∧ true ∧ x → x
    /// x ∧ Not(x) → false
    /// x ∧ (x ∨ y) → x
    /// ```
    ///
    /// # Preconditions
    /// Every child must be a canonical test from `self`. Input order, nesting, and duplicates are
    /// unrestricted.
    pub(super) fn test_and(
        &mut self,
        children: impl IntoIterator<Item = TestId<'arena>>,
    ) -> TestId<'arena> {
        self.test_connective(children, TestConnective::And)
    }

    /// Constructs canonical disjunction over one-event tests.
    ///
    /// This is the descriptive entry point for [`CanonicalStore::test_connective`]. It applies
    /// disjunction identities, tautologies, absorption, and constant implications before
    /// hashconsing the result.
    ///
    /// Example reductions:
    ///
    /// ```text
    /// Or([]) → false
    /// x ∨ false ∨ x → x
    /// x ∨ Not(x) → true
    /// x ∨ (x ∧ y) → x
    /// ```
    ///
    /// # Preconditions
    /// Every child must be a canonical test from `self`. Input order, nesting, and duplicates are
    /// unrestricted.
    pub(super) fn test_or(
        &mut self,
        children: impl IntoIterator<Item = TestId<'arena>>,
    ) -> TestId<'arena> {
        self.test_connective(children, TestConnective::Or)
    }

    /// Constructs the normalized Boolean complement of one event test.
    ///
    /// Constants swap, atomic equality/disequality comparisons invert, and compound connectives are
    /// complemented by De Morgan recursion through the corresponding smart constructor. Calling
    /// `test_and`/`test_or` after recursion preserves flattening, ordering, and all secondary
    /// reductions; the method never creates an unnormalized compound node directly.
    ///
    /// Example reductions:
    ///
    /// ```text
    /// Not(true) → false
    /// Not(Eq(p)) → Neq(p)
    /// Not(x ∧ y) → Not(x) ∨ Not(y)
    /// Not(x ∨ y) → Not(x) ∧ Not(y)
    /// ```
    ///
    /// # Preconditions
    /// `test` must be a canonical normalized test from `self`.
    pub(super) fn test_not(&mut self, test: TestId<'arena>) -> TestId<'arena> {
        match *test.get() {
            TestNode::True => self.test_false,
            TestNode::False => self.test_true,
            TestNode::Atom {
                comparison,
                pattern,
            } => self.tests.mk(TestNode::Atom {
                comparison: !comparison,
                pattern,
            }),
            TestNode::And(children) => {
                let complements = children
                    .iter()
                    .map(|child| self.test_not(*child))
                    .collect::<SmallVec<[TestId<'arena>; 4]>>();
                self.test_or(complements)
            }
            TestNode::Or(children) => {
                let complements = children
                    .iter()
                    .map(|child| self.test_not(*child))
                    .collect::<SmallVec<[TestId<'arena>; 4]>>();
                self.test_and(complements)
            }
        }
    }

    /// Interns one normalized regex kind with its deterministic nullability cache.
    ///
    /// Hashconsing may return an existing node. In that case, recomputed nullability must match the
    /// value stored with the canonical node; the assertion detects a constructor violating the
    /// invariant rather than allowing equal syntax to carry inconsistent semantic metadata.
    ///
    /// Example canonicalization:
    ///
    /// ```text
    /// intern(Union([R, S]), nullable) called twice → the same RegexId
    /// equal syntax with two different nullable values → invariant failure
    /// ```
    ///
    /// # Preconditions
    /// `kind` must already satisfy the flattened-normal-form invariants, all child IDs must belong
    /// to `self`, and `nullable` must equal the semantic nullability of `kind`.
    fn intern_regex(&mut self, kind: RegexKind<'arena>, nullable: bool) -> RegexId<'arena> {
        let (id, is_new) = self.regexes.mk_is_new(RegexNode::new(kind, nullable));
        if !is_new {
            assert_eq!(
                id.get().nullable(),
                nullable,
                "equal regex syntax computed inconsistent nullability"
            );
        }
        id
    }

    /// Lifts a one-event test into the regex language.
    ///
    /// A false test denotes no one-event words and therefore becomes the empty language. Every
    /// other test denotes words of length exactly one, so its nullability is always false.
    ///
    /// Example reductions:
    ///
    /// ```text
    /// Test(false) → Empty
    /// Test(φ) → a non-nullable one-event language, when φ != false
    /// ```
    ///
    /// # Preconditions
    /// `test` must be a canonical normalized test from `self`.
    pub(super) fn regex_test(&mut self, test: TestId<'arena>) -> RegexId<'arena> {
        if test == self.test_false {
            self.empty
        } else {
            self.intern_regex(RegexKind::Test(test), false)
        }
    }

    /// Constructs canonical language union.
    ///
    /// The constructor removes `Empty`, short-circuits on `All`, flattens nested unions, combines all
    /// one-event test operands through `test_or`, sorts and deduplicates operands, collapses explicit
    /// complements, removes epsilon when another nullable operand subsumes it, and applies direct and
    /// generalized absorption. The resulting node is nullable iff any retained child is nullable.
    ///
    /// This algorithm intentionally remains separate from `regex_intersect`: their treatment of
    /// epsilon and non-nullable operands is not a simple identity/absorber dual.
    ///
    /// Example reductions:
    ///
    /// ```text
    /// Empty ∪ R → R                    All ∪ R → All
    /// R ∪ R → R                        R ∪ Not(R) → All
    /// Test(φ) ∪ Test(ψ) → Test(φ ∨ ψ)
    /// Epsilon ∪ R → R                  when nullable(R)
    /// R ∪ (R ∩ S) → R
    /// ```
    ///
    /// # Preconditions
    /// Every child must be a canonical normalized regex from `self`. Input order, same-connective
    /// nesting, and duplicates are unrestricted.
    pub(super) fn regex_union(
        &mut self,
        children: impl IntoIterator<Item = RegexId<'arena>>,
    ) -> RegexId<'arena> {
        let mut flat = SmallVec::<[RegexId<'arena>; 4]>::new();
        for child in children {
            match child.get().kind {
                RegexKind::All => return self.all,
                RegexKind::Empty => {}
                RegexKind::Union(nested) => flat.extend_from_slice(nested),
                _ => flat.push(child),
            }
        }

        let mut tests = SmallVec::<[TestId<'arena>; 4]>::new();
        flat.retain(|child| match child.get().kind {
            RegexKind::Test(test) => {
                tests.push(test);
                false
            }
            _ => true,
        });
        if !tests.is_empty() {
            let test = self.test_or(tests);
            let regex = self.regex_test(test);
            if regex != self.empty {
                flat.push(regex);
            }
        }

        flat.sort_unstable();
        flat.dedup();
        if pair_satisfies(&flat, complementary_regex) {
            return self.all;
        }
        if flat.contains(&self.epsilon)
            && flat
                .iter()
                .any(|child| *child != self.epsilon && self.nullable(*child))
        {
            flat.retain(|child| *child != self.epsilon);
        }
        if flat
            .iter()
            .any(|candidate| matches!(candidate.get().kind, RegexKind::Intersect(_)))
        {
            let siblings = flat.clone();
            flat.retain(|candidate| !regex_absorbed_by_sibling(*candidate, &siblings));
        }
        match flat.as_slice() {
            [] => self.empty,
            [only] => *only,
            _ => {
                let nullable = flat.iter().any(|child| self.nullable(*child));
                let values = self.regexes.arena().alloc_slice_copy(&flat);
                self.intern_regex(RegexKind::Union(values), nullable)
            }
        }
    }

    /// Constructs canonical language intersection.
    ///
    /// The constructor removes `All`, short-circuits on `Empty`, flattens nested intersections,
    /// combines all one-event test operands through `test_and`, sorts and deduplicates operands,
    /// collapses explicit complements, applies epsilon-specific emptiness, removes `Not(Epsilon)`
    /// beside any non-nullable operand, and applies direct and generalized absorption. The resulting
    /// node is nullable iff every retained child is nullable.
    ///
    /// This algorithm intentionally remains separate from `regex_union`: intersection can collapse
    /// to exactly epsilon or empty based on all operands' nullability, a rule with no mirrored union
    /// implementation.
    ///
    /// Example reductions:
    ///
    /// ```text
    /// All ∩ R → R                      Empty ∩ R → Empty
    /// R ∩ R → R                        R ∩ Not(R) → Empty
    /// Test(φ) ∩ Test(ψ) → Test(φ ∧ ψ)
    /// Epsilon ∩ R → Epsilon            when nullable(R)
    /// Epsilon ∩ R → Empty              when not nullable(R)
    /// R ∩ Not(Epsilon) → R             when not nullable(R)
    /// R ∩ (R ∪ S) → R
    /// ```
    ///
    /// # Preconditions
    /// Every child must be a canonical normalized regex from `self`. Input order, same-connective
    /// nesting, and duplicates are unrestricted.
    pub(super) fn regex_intersect(
        &mut self,
        children: impl IntoIterator<Item = RegexId<'arena>>,
    ) -> RegexId<'arena> {
        let mut flat = SmallVec::<[RegexId<'arena>; 4]>::new();
        for child in children {
            match child.get().kind {
                RegexKind::Empty => return self.empty,
                RegexKind::All => {}
                RegexKind::Intersect(nested) => flat.extend_from_slice(nested),
                _ => flat.push(child),
            }
        }

        let mut tests = SmallVec::<[TestId<'arena>; 4]>::new();
        flat.retain(|child| match child.get().kind {
            RegexKind::Test(test) => {
                tests.push(test);
                false
            }
            _ => true,
        });
        if !tests.is_empty() {
            let test = self.test_and(tests);
            let regex = self.regex_test(test);
            if regex == self.empty {
                return self.empty;
            }
            flat.push(regex);
        }

        flat.sort_unstable();
        flat.dedup();
        if pair_satisfies(&flat, complementary_regex) {
            return self.empty;
        }
        if flat.contains(&self.epsilon) {
            return if flat.iter().all(|child| self.nullable(*child)) {
                self.epsilon
            } else {
                self.empty
            };
        }
        if flat
            .iter()
            .any(|child| !is_epsilon_complement(*child) && !self.nullable(*child))
        {
            flat.retain(|child| !is_epsilon_complement(*child));
        }
        if flat
            .iter()
            .any(|candidate| matches!(candidate.get().kind, RegexKind::Union(_)))
        {
            let siblings = flat.clone();
            flat.retain(|candidate| !regex_absorbed_by_sibling(*candidate, &siblings));
        }
        match flat.as_slice() {
            [] => self.all,
            [only] => *only,
            _ => {
                let nullable = flat.iter().all(|child| self.nullable(*child));
                let values = self.regexes.arena().alloc_slice_copy(&flat);
                self.intern_regex(RegexKind::Intersect(values), nullable)
            }
        }
    }

    /// Constructs canonical ordered concatenation.
    ///
    /// Empty annihilates the product, epsilon is removed as its identity, and nested concatenations
    /// are flattened without sorting or deduplication because factor order and multiplicity are
    /// semantic. A nontrivial result is nullable iff every factor is nullable.
    ///
    /// Example reductions:
    ///
    /// ```text
    /// Empty · R → Empty                Epsilon · R → R
    /// R · Epsilon → R                  (R · S) · T → R · S · T
    /// nullable(R · S) = nullable(R) ∧ nullable(S)
    /// ```
    ///
    /// # Preconditions
    /// Every child must be a canonical normalized regex from `self`. Their order is semantic;
    /// duplicates are permitted.
    pub(super) fn regex_concat(
        &mut self,
        children: impl IntoIterator<Item = RegexId<'arena>>,
    ) -> RegexId<'arena> {
        let mut flat = SmallVec::<[RegexId<'arena>; 4]>::new();
        for child in children {
            match child.get().kind {
                RegexKind::Empty => return self.empty,
                RegexKind::Epsilon => {}
                RegexKind::Concat(nested) => flat.extend_from_slice(nested),
                _ => flat.push(child),
            }
        }

        match flat.as_slice() {
            [] => self.epsilon,
            [only] => *only,
            _ => {
                let nullable = flat.iter().all(|child| self.nullable(*child));
                let values = self.regexes.arena().alloc_slice_copy(&flat);
                self.intern_regex(RegexKind::Concat(values), nullable)
            }
        }
    }

    /// Constructs canonical Kleene star.
    ///
    /// `Empty*` and `Epsilon*` reduce to epsilon, `All*` and the always-true one-event test star
    /// reduce to `All`, and nested star is idempotent. Every remaining star is nullable by
    /// definition.
    ///
    /// Example reductions:
    ///
    /// ```text
    /// Empty* → Epsilon                 Epsilon* → Epsilon
    /// All* → All                       Test(true)* → All
    /// (R*)* → R*                       nullable(R*) = true
    /// ```
    ///
    /// # Preconditions
    /// `inner` must be a canonical normalized regex from `self`.
    pub(super) fn regex_star(&mut self, inner: RegexId<'arena>) -> RegexId<'arena> {
        match inner.get().kind {
            RegexKind::Empty | RegexKind::Epsilon => self.epsilon,
            RegexKind::All => self.all,
            RegexKind::Test(test) if test == self.test_true => self.all,
            RegexKind::Star(_) => inner,
            _ => self.intern_regex(RegexKind::Star(inner), true),
        }
    }

    /// Constructs canonical whole-language complement.
    ///
    /// Empty and universal languages swap, double negation is removed, and all other syntax is kept
    /// under one `Not` node. Complement flips cached nullability because the empty word belongs to
    /// exactly one of a language and its complement.
    ///
    /// Example reductions:
    ///
    /// ```text
    /// Not(Empty) → All                 Not(All) → Empty
    /// Not(Not(R)) → R                  nullable(Not(R)) = ¬nullable(R)
    /// ```
    ///
    /// # Preconditions
    /// `inner` must be a canonical normalized regex from `self`.
    pub(super) fn regex_not(&mut self, inner: RegexId<'arena>) -> RegexId<'arena> {
        match inner.get().kind {
            RegexKind::Empty => self.all,
            RegexKind::All => self.empty,
            RegexKind::Not(value) => value,
            _ => self.intern_regex(RegexKind::Not(inner), !self.nullable(inner)),
        }
    }

    /// Returns cached empty-history acceptance directly from a canonical regex node.
    ///
    /// Nullability is computed by smart constructors and checked when equal syntax is reused, so
    /// this query performs no recursive traversal.
    ///
    /// Example cached equations:
    ///
    /// ```text
    /// nullable(Empty) = false          nullable(Epsilon) = true
    /// nullable(Test(φ)) = false        nullable(R ∪ S) = nullable(R) ∨ nullable(S)
    /// nullable(R ∩ S) = nullable(R) ∧ nullable(S)
    /// nullable(R · S) = nullable(R) ∧ nullable(S)
    /// ```
    ///
    /// # Preconditions
    /// `regex` must be a canonical regex from `self`.
    pub(super) fn nullable(&self, regex: RegexId<'arena>) -> bool {
        regex.get().nullable()
    }
}
