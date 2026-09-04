//! Criterion benchmarks for compilation, history evaluation, full scans, denial, and rollback.
//!
//! Run the suite from this package with `cargo bench --bench validator`. Pass a Criterion filter,
//! for example `cargo bench --bench validator -- history_scan`, to run one group.

#![allow(missing_docs)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fmt::Debug;
use std::hint::black_box;
use std::time::{Duration, Instant};

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rust_validator::{
    Action, AtomPattern, Bump, Comparison, ComponentPattern, Decision, Event, Head, Principal,
    RegexExpr, Request, Rule, RuleMode, TestExpr, Validator,
};

trait CheckedDecision<Metadata> {
    fn checked(self) -> Decision<Metadata>;
}

impl<Metadata> CheckedDecision<Metadata> for Decision<Metadata> {
    fn checked(self) -> Self {
        self
    }
}

impl<Metadata, Error> CheckedDecision<Metadata> for Result<Decision<Metadata>, Error>
where
    Error: Debug,
{
    fn checked(self) -> Decision<Metadata> {
        self.expect("validator evaluation succeeds")
    }
}

fn request(principal: &str, action: Action, resource: &[&str]) -> Request<()> {
    Request::new(Event::new(principal, action, resource.to_vec()), ())
}

fn prior_edit_rule(suffix: usize) -> Rule {
    let actor = format!("actor-{suffix}");
    let target = format!("target-{suffix}");
    let principal = TestExpr::atom(
        Comparison::Eq,
        AtomPattern::Principal(ComponentPattern::variable(actor.clone())),
    );
    let action = TestExpr::atom(
        Comparison::Eq,
        AtomPattern::Action(ComponentPattern::constant(Action::Edit)),
    );
    let resource = TestExpr::atom(
        Comparison::Eq,
        AtomPattern::Resource(ComponentPattern::variable(target.clone())),
    );
    Rule::new(
        RuleMode::Require,
        Head::new(
            ComponentPattern::variable(actor),
            ComponentPattern::constant(Action::Stage),
            ComponentPattern::variable(target),
        ),
        RegexExpr::concat([
            RegexExpr::all(),
            RegexExpr::test(TestExpr::and([principal, action, resource])),
        ]),
    )
}

fn duplicate_commit_rule() -> Rule {
    let matching_commit = RegexExpr::test(TestExpr::and([
        TestExpr::atom(
            Comparison::Eq,
            AtomPattern::Action(ComponentPattern::constant(Action::commit("ship"))),
        ),
        TestExpr::atom(
            Comparison::Eq,
            AtomPattern::Resource(ComponentPattern::variable("target")),
        ),
    ]));
    Rule::new(
        RuleMode::Forbid,
        Head::new(
            ComponentPattern::variable("actor"),
            ComponentPattern::constant(Action::commit("ship")),
            ComponentPattern::variable("target"),
        ),
        RegexExpr::concat([RegexExpr::all(), matching_commit, RegexExpr::all()]),
    )
}

fn every_action_leaf(index: usize) -> RegexExpr {
    RegexExpr::star(RegexExpr::test(TestExpr::atom(
        Comparison::Neq,
        AtomPattern::Action(ComponentPattern::constant(Action::commit(format!(
            "blocked-{index}"
        )))),
    )))
}

fn deeply_nested_action_allow_all_rule(depth: usize) -> Rule {
    assert!(depth > 0, "regex depth must be positive");
    let mut leaves = (0..depth).map(every_action_leaf);
    let mut tail = leaves.next().expect("positive depth has one leaf");
    for (index, leaf) in leaves.enumerate() {
        tail = if index % 2 == 0 {
            RegexExpr::union([tail, leaf])
        } else {
            RegexExpr::intersect([tail, leaf])
        };
    }
    Rule::new(
        RuleMode::Require,
        Head::new(
            ComponentPattern::variable("actor"),
            ComponentPattern::constant(Action::Stage),
            ComponentPattern::variable("target"),
        ),
        tail,
    )
}

fn unique_read(index: usize) -> Request<()> {
    Request::new(
        Event::new(
            format!("actor-{index}"),
            Action::Read,
            vec![format!("resource-{index}")],
        ),
        (),
    )
}

// Each distinct star accepts every benchmark event and is stable under differentiation.
fn every_event_leaf(index: usize) -> RegexExpr {
    RegexExpr::star(RegexExpr::test(TestExpr::atom(
        Comparison::Neq,
        AtomPattern::Principal(ComponentPattern::constant(Principal::new(format!(
            "blocked-{index}"
        )))),
    )))
}

fn deeply_nested_allow_all_rule(depth: usize) -> Rule {
    assert!(depth > 0, "regex depth must be positive");
    let mut leaves = (0..depth).map(every_event_leaf);
    let mut tail = leaves.next().expect("positive depth has one leaf");
    // Alternating operators retain binary nesting because canonicalization only flattens like kinds.
    for (index, leaf) in leaves.enumerate() {
        tail = if index % 2 == 0 {
            RegexExpr::union([tail, leaf])
        } else {
            RegexExpr::intersect([tail, leaf])
        };
    }

    Rule::new(
        RuleMode::Require,
        Head::new(
            ComponentPattern::variable("actor"),
            ComponentPattern::constant(Action::Stage),
            ComponentPattern::variable("target"),
        ),
        tail,
    )
}

fn advancing_optional_rule(steps: usize) -> Rule {
    let factors = (0..steps).map(|index| {
        RegexExpr::union([
            RegexExpr::epsilon(),
            RegexExpr::test(TestExpr::atom(
                Comparison::Neq,
                AtomPattern::Action(ComponentPattern::constant(Action::commit(format!(
                    "blocked-{index}"
                )))),
            )),
        ])
    });
    Rule::new(
        RuleMode::Require,
        Head::new(
            ComponentPattern::variable("actor"),
            ComponentPattern::constant(Action::Stage),
            ComponentPattern::variable("target"),
        ),
        RegexExpr::concat(factors),
    )
}

/// Language whose residual DAG gains one suffix alternative after each matching event.
///
/// `Σ* · Read · Σ^(window + 1)` recognizes histories whose `(window + 2)`th event from the end is a
/// read. A shorter all-read history keeps adding candidate suffixes without reaching a terminal
/// residual. The full DFA has exponentially many states even though this measured path grows
/// linearly.
fn growing_residual_rule(window: usize) -> Rule {
    assert!(window > 0, "residual-growth window must be positive");
    let any_event = RegexExpr::test(TestExpr::true_test());
    let read = RegexExpr::test(TestExpr::atom(
        Comparison::Eq,
        AtomPattern::Action(ComponentPattern::constant(Action::Read)),
    ));
    let factors = std::iter::once(RegexExpr::all())
        .chain(std::iter::once(read))
        .chain(std::iter::repeat_n(any_event, window + 1));
    Rule::new(
        RuleMode::Forbid,
        Head::new(
            ComponentPattern::variable("actor"),
            ComponentPattern::constant(Action::Stage),
            ComponentPattern::variable("target"),
        ),
        RegexExpr::concat(factors),
    )
}

/// One unique absent-witness rule that forces a complete nonterminal history scan.
fn absent_witness_rule(index: usize) -> Rule {
    let absent = RegexExpr::test(TestExpr::atom(
        Comparison::Eq,
        AtomPattern::Principal(ComponentPattern::constant(format!("missing-{index}"))),
    ));
    Rule::new(
        RuleMode::Forbid,
        Head::new(
            ComponentPattern::variable("actor"),
            ComponentPattern::constant(Action::Stage),
            ComponentPattern::variable("target"),
        ),
        RegexExpr::concat([RegexExpr::all(), absent, RegexExpr::all()]),
    )
}

// The matching Require rule forces all one million committed events through the depth-32 tail.
fn benchmark_million_event_nested_scan(criterion: &mut Criterion) {
    const HISTORY_LEN: usize = 1_000_000;
    const REGEX_DEPTH: usize = 32;

    let arena = Bump::new();
    let mut builder = Validator::builder(&arena);
    builder
        .add_rule(&deeply_nested_allow_all_rule(REGEX_DEPTH))
        .expect("benchmark rule is valid");
    let mut validator = builder.finish();
    for _ in 0..HISTORY_LEN {
        let _ = validator.check(request("alice", Action::Read, &[]));
    }
    assert_eq!(validator.history().len(), HISTORY_LEN);
    let checkpoint = validator.checkpoint();

    let mut group = criterion.benchmark_group("full_scan");
    group.throughput(Throughput::Elements(HISTORY_LEN as u64));
    group.sample_size(10);
    group.bench_function("1000000_events/depth_32", |bencher| {
        bencher.iter_custom(|iterations| {
            let mut elapsed = Duration::ZERO;
            for _ in 0..iterations {
                let candidate = request("alice", Action::Stage, &[]);
                let start = Instant::now();
                let decision = validator.check(black_box(candidate)).checked();
                elapsed += start.elapsed();
                assert!(decision.is_grant());
                validator.rollback(checkpoint);
            }
            elapsed
        });
    });
    group.finish();
}

// Every history symbol is distinct, defeating symbol-indexed successor caches. The regex only
// inspects actions, so unique principal/resource strings do not enter component resolution.
fn benchmark_high_cardinality_scan(criterion: &mut Criterion) {
    const HISTORY_LEN: usize = 100_000;
    const REGEX_DEPTH: usize = 32;

    let arena = Bump::new();
    let mut builder = Validator::builder(&arena);
    builder
        .add_rule(&deeply_nested_action_allow_all_rule(REGEX_DEPTH))
        .expect("benchmark rule is valid");
    let mut validator = builder.finish();
    for index in 0..HISTORY_LEN {
        let _ = validator.check(unique_read(index)).checked();
    }
    assert_eq!(validator.history().len(), HISTORY_LEN);
    let checkpoint = validator.checkpoint();

    let mut group = criterion.benchmark_group("high_cardinality_scan");
    group.throughput(Throughput::Elements(HISTORY_LEN as u64));
    group.sample_size(10);
    group.bench_function("100000_events/depth_32", |bencher| {
        bencher.iter_custom(|iterations| {
            let mut elapsed = Duration::ZERO;
            for _ in 0..iterations {
                let candidate = request("candidate", Action::Stage, &[]);
                let start = Instant::now();
                let decision = validator.check(black_box(candidate)).checked();
                elapsed += start.elapsed();
                assert!(decision.is_grant());
                validator.rollback(checkpoint);
            }
            elapsed
        });
    });
    group.finish();
}

// Every derivative advances through a new suffix of a long concatenation of optional predicates.
// Symbol caches cannot reuse `(transition, symbol)` because the transition changes at every event.
fn benchmark_advancing_derivatives(criterion: &mut Criterion) {
    const STEPS: usize = 16;

    let arena = Bump::new();
    let mut builder = Validator::builder(&arena);
    builder
        .add_rule(&advancing_optional_rule(STEPS))
        .expect("benchmark rule is valid");
    let mut validator = builder.finish();
    for _ in 0..STEPS {
        let _ = validator
            .check(request("history", Action::Read, &[]))
            .checked();
    }
    let checkpoint = validator.checkpoint();

    let mut group = criterion.benchmark_group("advancing_derivatives");
    group.throughput(Throughput::Elements(STEPS as u64));
    group.sample_size(10);
    group.bench_function("16_optional_factors", |bencher| {
        bencher.iter_custom(|iterations| {
            let mut elapsed = Duration::ZERO;
            for _ in 0..iterations {
                let candidate = request("candidate", Action::Stage, &[]);
                let start = Instant::now();
                let decision = validator.check(black_box(candidate)).checked();
                elapsed += start.elapsed();
                assert!(decision.is_grant());
                validator.rollback(checkpoint);
            }
            elapsed
        });
    });
    group.finish();
}

/// Growing-residual stress: compilation and evaluation, each in its own benchmark group.
fn benchmark_growing_residual_stress(criterion: &mut Criterion) {
    growing_residual_compile(criterion);
    growing_residual_evaluate(criterion);
}

/// Compile cost as the residual window grows.
fn growing_residual_compile(criterion: &mut Criterion) {
    let mut compile = criterion.benchmark_group("stress_growing_residual_compile");
    compile
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(3))
        .sample_size(10);
    for window in [4_usize, 8, 12] {
        compile.bench_with_input(
            BenchmarkId::from_parameter(window),
            &window,
            |bencher, &window| {
                bencher.iter_custom(|iterations| {
                    let mut elapsed = Duration::ZERO;
                    for _ in 0..iterations {
                        let source = growing_residual_rule(window);
                        let arena = Bump::new();
                        let start = Instant::now();
                        let mut builder = Validator::builder(&arena);
                        builder.add_rule(&source).expect("stress rule is valid");
                        let validator = builder.finish();
                        black_box(&validator);
                        elapsed += start.elapsed();
                    }
                    elapsed
                });
            },
        );
    }
    compile.finish();
}

/// Per-event decision cost against a grown residual.
fn growing_residual_evaluate(criterion: &mut Criterion) {
    let mut evaluate = criterion.benchmark_group("stress_growing_residual_evaluate");
    evaluate
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(3))
        .sample_size(10);
    for window in [8_usize, 16, 32, 64] {
        let arena = Bump::new();
        let mut builder = Validator::builder(&arena);
        builder
            .add_rule(&growing_residual_rule(window))
            .expect("stress rule is valid");
        let mut validator = builder.finish();
        for _ in 0..window {
            assert!(
                validator
                    .check(request("history", Action::Read, &["event"]))
                    .is_grant()
            );
        }
        let checkpoint = validator.checkpoint();
        evaluate.throughput(Throughput::Elements(window as u64));
        evaluate.bench_with_input(
            BenchmarkId::from_parameter(window),
            &window,
            |bencher, _| {
                bencher.iter_custom(|iterations| {
                    let mut elapsed = Duration::ZERO;
                    for _ in 0..iterations {
                        let candidate = request("candidate", Action::Stage, &["target"]);
                        let start = Instant::now();
                        let decision = validator.check(black_box(candidate));
                        elapsed += start.elapsed();
                        assert!(decision.is_grant());
                        validator.rollback(checkpoint);
                    }
                    elapsed
                });
            },
        );
    }
    evaluate.finish();
}

/// Many-rules stress: compilation and evaluation, each in its own benchmark group.
fn benchmark_many_rules_stress(criterion: &mut Criterion) {
    many_rules_compile(criterion);
    many_rules_evaluate(criterion);
}

/// Compile cost as the rule count grows.
fn many_rules_compile(criterion: &mut Criterion) {
    const RULE_COUNTS: [usize; 5] = [1, 16, 64, 256, 1_024];
    let mut compile = criterion.benchmark_group("stress_many_rules_compile");
    compile
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(3))
        .sample_size(10);
    for rule_count in RULE_COUNTS {
        compile.bench_with_input(
            BenchmarkId::from_parameter(rule_count),
            &rule_count,
            |bencher, &rule_count| {
                bencher.iter_custom(|iterations| {
                    let mut elapsed = Duration::ZERO;
                    for _ in 0..iterations {
                        let rules = (0..rule_count).map(absent_witness_rule).collect::<Vec<_>>();
                        let arena = Bump::new();
                        let start = Instant::now();
                        let mut builder = Validator::builder(&arena);
                        for rule in rules {
                            builder.add_rule(&rule).expect("stress rule is valid");
                        }
                        let validator = builder.finish();
                        black_box(&validator);
                        elapsed += start.elapsed();
                    }
                    elapsed
                });
            },
        );
    }
    compile.finish();
}

/// Per-event decision cost against a large rule table.
fn many_rules_evaluate(criterion: &mut Criterion) {
    const HISTORY_LEN: usize = 64;
    const RULE_COUNTS: [usize; 5] = [1, 16, 64, 256, 1_024];

    let mut evaluate = criterion.benchmark_group("stress_many_rules_evaluate");
    evaluate
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(3))
        .sample_size(10);
    for rule_count in RULE_COUNTS {
        let arena = Bump::new();
        let mut builder = Validator::builder(&arena);
        for index in 0..rule_count {
            builder
                .add_rule(&absent_witness_rule(index))
                .expect("stress rule is valid");
        }
        let mut validator = builder.finish();
        for _ in 0..HISTORY_LEN {
            assert!(
                validator
                    .check(request("history", Action::Read, &["event"]))
                    .is_grant()
            );
        }
        let checkpoint = validator.checkpoint();
        evaluate.throughput(Throughput::Elements(
            rule_count
                .checked_mul(HISTORY_LEN)
                .expect("stress work count fits u64") as u64,
        ));
        evaluate.bench_with_input(
            BenchmarkId::from_parameter(rule_count),
            &rule_count,
            |bencher, _| {
                bencher.iter_custom(|iterations| {
                    let mut elapsed = Duration::ZERO;
                    for _ in 0..iterations {
                        let candidate = request("candidate", Action::Stage, &["target"]);
                        let start = Instant::now();
                        let decision = validator.check(black_box(candidate));
                        elapsed += start.elapsed();
                        assert!(decision.is_grant());
                        validator.rollback(checkpoint);
                    }
                    elapsed
                });
            },
        );
    }
    evaluate.finish();
}

fn benchmark_compilation(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("compile_rules");
    for count in [1_usize, 16, 64] {
        group.bench_with_input(
            BenchmarkId::from_parameter(count),
            &count,
            |bencher, &count| {
                bencher.iter_custom(|iterations| {
                    let mut elapsed = Duration::ZERO;
                    for _ in 0..iterations {
                        let rules: Vec<Rule> = (0..count).map(prior_edit_rule).collect();
                        let arena = Bump::new();
                        let start = Instant::now();
                        let mut builder = Validator::builder(&arena);
                        for rule in rules {
                            builder.add_rule(&rule).expect("benchmark rule is valid");
                        }
                        let validator = builder.finish();
                        black_box(&validator);
                        elapsed += start.elapsed();
                        drop(validator);
                    }
                    elapsed
                });
            },
        );
    }
    group.finish();
}

fn validator_with_edit_history(arena: &Bump, history_len: usize) -> Validator<'_> {
    let mut builder = Validator::builder(arena);
    builder
        .add_rule(&prior_edit_rule(0))
        .expect("benchmark rule is valid");
    let mut validator = builder.finish();
    for _ in 0..history_len {
        let decision = validator.check(request("alice", Action::Edit, &["src", "a.rs"]));
        debug_assert!(decision.is_grant());
    }
    validator
}

fn benchmark_history_scan(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("history_scan");
    for history_len in [1_usize, 32, 256] {
        let arena = Bump::new();
        let mut validator = validator_with_edit_history(&arena, history_len);
        let checkpoint = validator.checkpoint();
        group.bench_with_input(
            BenchmarkId::from_parameter(history_len),
            &history_len,
            |bencher, _| {
                bencher.iter_custom(|iterations| {
                    let mut elapsed = Duration::ZERO;
                    for _ in 0..iterations {
                        let candidate = request("alice", Action::Stage, &["src", "a.rs"]);
                        let start = Instant::now();
                        let decision = validator.check(black_box(candidate));
                        elapsed += start.elapsed();
                        debug_assert!(decision.is_grant());
                        validator.rollback(checkpoint);
                    }
                    elapsed
                });
            },
        );
    }
    group.finish();
}

fn benchmark_denial(criterion: &mut Criterion) {
    let arena = Bump::new();
    let mut builder = Validator::builder(&arena);
    builder
        .add_rule(&duplicate_commit_rule())
        .expect("benchmark rule is valid");
    let mut validator = builder.finish();
    let first = validator.check(request("alice", Action::commit("ship"), &["a"]));
    debug_assert!(first.is_grant());

    criterion.bench_function("deny_duplicate_commit", |bencher| {
        bencher.iter_custom(|iterations| {
            let mut elapsed = Duration::ZERO;
            for _ in 0..iterations {
                let candidate = request("alice", Action::commit("ship"), &["a"]);
                let start = Instant::now();
                let decision = validator.check(black_box(candidate));
                elapsed += start.elapsed();
                debug_assert!(matches!(decision, Decision::Denied(_)));
            }
            elapsed
        });
    });
}

fn benchmark_rollback(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("rollback");
    for removed_events in [1_usize, 64, 1024] {
        let arena = Bump::new();
        group.bench_with_input(
            BenchmarkId::from_parameter(removed_events),
            &removed_events,
            |bencher, &removed_events| {
                bencher.iter_batched(
                    || {
                        let mut validator = Validator::builder(&arena).finish();
                        let checkpoint = validator.checkpoint();
                        for _ in 0..removed_events {
                            let decision = validator.check(request("alice", Action::Read, &["a"]));
                            debug_assert!(decision.is_grant());
                        }
                        (validator, checkpoint)
                    },
                    |(mut validator, checkpoint)| {
                        validator.rollback(checkpoint);
                        black_box(validator);
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    benchmark_compilation,
    benchmark_history_scan,
    benchmark_million_event_nested_scan,
    benchmark_high_cardinality_scan,
    benchmark_advancing_derivatives,
    benchmark_growing_residual_stress,
    benchmark_many_rules_stress,
    benchmark_denial,
    benchmark_rollback,
);
criterion_main!(benches);
