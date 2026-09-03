/**
 * simple-git is the ground truth for the git trace policy.
 *
 * The Rust crate generates traces and decides them (`cargo run --example git_policy_traces`); this
 * file replays every operation the policy *granted* against a freshly seeded scratch repository
 * through simple-git. A failure here means the policy authorized something git rejects — a checker
 * bug — and the scratch repository is retained so the failure can be inspected.
 *
 * The converse is deliberately not asserted: denied operations are never exported and never run, so
 * a denial is never claimed to be necessary.
 */

import { test } from "bun:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import {
  appendFile,
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  stat,
  unlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { GitError, simpleGit, type SimpleGit, type SimpleGitOptions } from "simple-git";

/** Number of traces the exporter replays from its fixed seeded byte stream. */
const SEEDED_TRACE_COUNT = 32;
/** Counters the fixed seeded stream must produce; a drift here means generation changed. */
const SEEDED_SUMMARY = { granted: 258, denied: 191, commits: 0 };
/** Environment variable that pins the exporter's random seed; mirrors `git_policy_harness`. */
const SEED_VARIABLE = "JUNCO_FUZZ_SEED";
/** The fuzz crate: the Cargo working directory of the trace exporter. */
const FUZZ_ROOT = fileURLToPath(new URL("../fuzz/", import.meta.url));

/** Every concrete operation the exporter can emit, matching `GeneratedOperation::as_str`. */
const OPERATIONS = {
  create: true,
  modify: true,
  delete: true,
  stage: true,
  unstage: true,
  commit: true,
  checkout: true,
  stash: true,
  read: true,
  diff: true,
  history: true,
  remove: true,
  clean: true,
} as const;

type Operation = keyof typeof OPERATIONS;

type TraceSummary = {
  granted: number;
  denied: number;
  commits: number;
};

type ValidatedOperation = {
  principal: string;
  operation: Operation;
  path: string;
  step: number;
};

type ValidatedTrace = {
  source: string;
  summary: TraceSummary;
  operations: ValidatedOperation[];
};

type TraceExport = {
  fileCount: number;
  seededSummary: TraceSummary;
  randomSeed: string;
  randomTraceCount: number;
  traces: ValidatedTrace[];
};

const execFileAsync = promisify(execFile);

/**
 * A git command that exited non-zero, with the streams the default `GitError` discards.
 *
 * It extends `GitError` because simple-git's `onFatalException` replaces any other error class
 * with a plain `GitError` carrying only the stringified message, which would lose these fields.
 */
class GitExitError extends GitError {
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;

  constructor(exitCode: number, stdout: string, stderr: string) {
    super(undefined, `git exited ${exitCode}\nstdout:\n${stdout}stderr:\n${stderr}`);
    this.name = "GitExitError";
    this.exitCode = exitCode;
    this.stdout = stdout;
    this.stderr = stderr;
  }
}

/** A granted operation that failed to execute, carrying the retained scratch repository. */
class TraceExecutionError extends Error {
  readonly repository: string;

  constructor(message: string, repository: string, options: { cause: unknown }) {
    super(message, options);
    this.name = "TraceExecutionError";
    this.repository = repository;
  }
}

/**
 * Narrows parsed JSON to a property bag. Reads stay `unknown` and are validated individually, so
 * this widening asserts nothing about the shape beyond "not null and an object", already checked.
 */
function asRecord(value: unknown, label: string): Record<string, unknown> {
  assert.ok(typeof value === "object" && value !== null, `${label} must be an object`);
  return value as Record<string, unknown>;
}

function assertCounter(value: unknown, label: string): asserts value is number {
  assert.ok(
    typeof value === "number" && Number.isInteger(value) && value >= 0,
    `${label} must be a non-negative integer, got ${JSON.stringify(value)}`,
  );
}

function assertSummary(value: unknown, label: string): asserts value is TraceSummary {
  const summary = asRecord(value, label);
  assertCounter(summary.granted, `${label}.granted`);
  assertCounter(summary.denied, `${label}.denied`);
  assertCounter(summary.commits, `${label}.commits`);
}

function assertOperation(
  value: unknown,
  label: string,
  fileCount: number,
): asserts value is ValidatedOperation {
  const operation = asRecord(value, label);
  assert.ok(
    typeof operation.principal === "string" && operation.principal.length > 0,
    `${label}.principal must be a non-empty string`,
  );
  assert.ok(
    typeof operation.operation === "string" && Object.hasOwn(OPERATIONS, operation.operation),
    `${label}.operation is not a known operation: ${JSON.stringify(operation.operation)}`,
  );
  assert.ok(typeof operation.path === "string", `${label}.path must be a string`);
  const pooled = /^src\/file(\d+)\.txt$/.exec(operation.path);
  assert.ok(pooled !== null, `${label}.path must be src/file<N>.txt, got ${operation.path}`);
  assert.ok(
    Number(pooled[1]) < fileCount,
    `${label}.path is outside the ${fileCount} pooled paths: ${operation.path}`,
  );
  assertCounter(operation.step, `${label}.step`);
}

/**
 * Validates the exporter's wire contract, so malformed exporter output fails at the JSON boundary
 * instead of surfacing later as an unrelated git error.
 */
function assertTraceExport(value: unknown): asserts value is TraceExport {
  const exported = asRecord(value, "trace export");

  assertCounter(exported.fileCount, "fileCount");
  assert.ok(exported.fileCount > 0, "fileCount must be positive");
  assertSummary(exported.seededSummary, "seededSummary");
  assert.ok(
    typeof exported.randomSeed === "string" && /^0x[0-9a-f]{16}$/.test(exported.randomSeed),
    `randomSeed must be a 0x-prefixed 64-bit hex seed, got ${JSON.stringify(exported.randomSeed)}`,
  );
  assertCounter(exported.randomTraceCount, "randomTraceCount");
  assert.ok(Array.isArray(exported.traces), "traces must be an array");

  const sources = new Set<string>();
  for (const [index, entry] of exported.traces.entries()) {
    const label = `traces[${index}]`;
    const trace = asRecord(entry, label);

    assert.ok(
      typeof trace.source === "string" && trace.source.length > 0,
      `${label}.source must be a non-empty string`,
    );
    assert.ok(!sources.has(trace.source), `${label}.source is duplicated: ${trace.source}`);
    sources.add(trace.source);

    assertSummary(trace.summary, `${label}.summary`);
    assert.ok(Array.isArray(trace.operations), `${label}.operations must be an array`);
    for (const [position, candidate] of trace.operations.entries()) {
      assertOperation(candidate, `${label}.operations[${position}]`, exported.fileCount);
    }
    assert.equal(
      trace.operations.length,
      trace.summary.granted,
      `${label} exports ${trace.operations.length} operations for ${trace.summary.granted} grants`,
    );
  }
}

/** Runs the Rust exporter once and parses its stdout. This process never executes git itself. */
async function loadTraceExport(): Promise<TraceExport> {
  let stdout: string;
  try {
    ({ stdout } = await execFileAsync(
      "cargo",
      ["run", "--quiet", "--example", "git_policy_traces"],
      { cwd: FUZZ_ROOT, maxBuffer: 16 * 1024 * 1024 },
    ));
  } catch (error) {
    const stderr =
      error instanceof Error && "stderr" in error && typeof error.stderr === "string"
        ? error.stderr
        : "";
    throw new Error(
      `cargo run --example git_policy_traces failed: ${String(error)}\n${stderr}`,
      { cause: error },
    );
  }

  const parsed: unknown = JSON.parse(stdout);
  assertTraceExport(parsed);
  return parsed;
}

/**
 * A child environment that cannot be steered by the developer's or CI's git configuration, and that
 * simple-git's environment vulnerability check accepts.
 */
function isolatedGitEnvironment(absentConfig: string): NodeJS.ProcessEnv {
  const environment: NodeJS.ProcessEnv = { ...process.env };
  for (const key of Object.keys(environment)) {
    const upper = key.toUpperCase();
    if (
      upper.startsWith("GIT_") ||
      upper === "EDITOR" ||
      upper === "PAGER" ||
      upper === "PREFIX" ||
      upper === "SSH_ASKPASS"
    ) {
      delete environment[key];
    }
  }

  if (process.platform === "win32") {
    // Windows environment keys are case-insensitive; the spawned child gets exactly one PATH.
    let search: string | undefined;
    for (const key of Object.keys(environment)) {
      if (key.toUpperCase() === "PATH") {
        search ??= environment[key];
        delete environment[key];
      }
    }
    if (search !== undefined) {
      environment.PATH = search;
    }
  }

  // Never created: git treats a missing configuration file as empty.
  environment.GIT_CONFIG_GLOBAL = absentConfig;
  environment.GIT_CONFIG_SYSTEM = absentConfig;
  environment.GIT_CONFIG_NOSYSTEM = "1";
  environment.GIT_TERMINAL_PROMPT = "0";
  environment.GIT_OPTIONAL_LOCKS = "0";
  return environment;
}

/**
 * One simple-git instance bound to `root` and attributed to `principal`.
 *
 * `config` entries are prefixed as `-c <entry>` to every command, isolating results from
 * `core.autocrlf`, `commit.gpgsign` and friends.
 */
function createGit(root: string, principal: string, initialize = false): SimpleGit {
  const config = [
    `user.name=${principal}`,
    `user.email=${principal}@fuzz.invalid`,
    "core.autocrlf=false",
    "commit.gpgsign=false",
  ];
  if (initialize) {
    config.push("init.defaultBranch=main");
  }

  const options: Partial<SimpleGitOptions> = {
    baseDir: root,
    binary: "git",
    maxConcurrentProcesses: 1,
    trimmed: false,
    config,
    // Solely to allow the fixed GIT_CONFIG_GLOBAL/GIT_CONFIG_SYSTEM isolation paths below, which
    // simple-git 3.36.0 blocks by default. No other unsafe category is enabled.
    unsafe: { allowUnsafeConfigPaths: true },
    // simple-git's stock detection (`exitCode && stdErr.length`) lets a non-zero exit with empty
    // stderr pass — `git commit` with nothing to commit is exactly that. Fail on the exit code
    // alone, as the previous Rust executor did.
    errors(error, result) {
      if (result.exitCode !== 0) {
        return new GitExitError(
          result.exitCode,
          Buffer.concat(result.stdOut).toString("utf8"),
          Buffer.concat(result.stdErr).toString("utf8"),
        );
      }
      return error;
    },
  };

  return simpleGit(options).env(isolatedGitEnvironment(join(root, "no-such-gitconfig")));
}

/** Creates a repository whose initial commit contains every pooled path. */
async function seedRepository(root: string, fileCount: number): Promise<void> {
  await mkdir(join(root, "src"), { recursive: true });
  for (let file = 0; file < fileCount; file += 1) {
    await writeFile(join(root, "src", `file${file}.txt`), `seed line for file${file}\n`);
  }

  const git = createGit(root, "seed", true);
  await git.init(["--quiet"]);
  await git.add("src");
  await git.commit("seed", { "--quiet": null });
}

/**
 * Executes one granted operation for real. Filesystem operations embed the step index so a write
 * can never coincidentally reproduce the committed blob; git operations go through simple-git.
 */
async function executeOperation(root: string, operation: ValidatedOperation): Promise<void> {
  const absolute = join(root, operation.path);
  switch (operation.operation) {
    // git tracks files, not directories, so removing the last entry under `src/` prunes the
    // directory itself. A later granted `create` there is legitimate and must recreate it,
    // exactly as a real agent writing the file would.
    case "create":
      await mkdir(dirname(absolute), { recursive: true });
      await writeFile(absolute, `created by ${operation.principal} at step ${operation.step}\n`);
      return;
    case "modify":
      await appendFile(absolute, `edited by ${operation.principal} at step ${operation.step}\n`);
      return;
    case "delete":
      await unlink(absolute);
      return;
    case "read":
      await readFile(absolute);
      return;
    case "stage":
      await createGit(root, operation.principal).add(operation.path);
      return;
    case "unstage":
      await createGit(root, operation.principal).raw([
        "restore",
        "--staged",
        "--",
        operation.path,
      ]);
      return;
    case "commit":
      await createGit(root, operation.principal).commit(
        `step ${operation.step}`,
        [operation.path],
        { "--quiet": null },
      );
      return;
    // From `HEAD`, not from the index: the index form fails after a staged deletion, which is a
    // modelling artifact rather than a policy question.
    case "checkout":
      await createGit(root, operation.principal).checkout([
        "--quiet",
        "HEAD",
        "--",
        operation.path,
      ]);
      return;
    case "stash":
      await createGit(root, operation.principal).stash(["push", "--quiet", "--", operation.path]);
      return;
    case "diff":
      await createGit(root, operation.principal).diff(["--", operation.path]);
      return;
    // Not `git.log({ file })`: that injects `--follow` and changes the command under test.
    case "history":
      await createGit(root, operation.principal).raw(["log", "--", operation.path]);
      return;
    case "remove":
      await createGit(root, operation.principal).raw(["rm", "--quiet", "--", operation.path]);
      return;
    case "clean":
      await createGit(root, operation.principal).raw([
        "clean",
        "--force",
        "--quiet",
        "--",
        operation.path,
      ]);
      return;
    default: {
      const unreachable: never = operation.operation;
      throw new Error(`unhandled operation ${String(unreachable)}`);
    }
  }
}

/**
 * Renders everything needed to reproduce a failure: the retained repository, the granted history,
 * the offending step, and — for a randomized trace — the exact command that regenerates it.
 */
function describeFailure(
  source: string,
  repository: string,
  executed: readonly ValidatedOperation[],
  offending: ValidatedOperation | undefined,
  error: unknown,
  reproduce: string,
): string {
  const render = (operation: ValidatedOperation) =>
    `${operation.principal} ${operation.operation} ${operation.path} at step ${operation.step}`;
  const history = executed.map((operation) => `  ${render(operation)}\n`).join("");
  const detail =
    error instanceof GitExitError
      ? `exit code: ${error.exitCode}\nstdout:\n${error.stdout}stderr:\n${error.stderr}`
      : `error: ${String(error)}`;

  return (
    "the git policy granted an operation that simple-git rejected\n" +
    `source: ${source}\n` +
    `reproduce with: ${reproduce}\n` +
    `repository (retained): ${repository}\n` +
    `granted history (${executed.length} operations):\n${history}` +
    `offending step: ${offending === undefined ? "repository seeding" : render(offending)}\n` +
    detail
  );
}

/** Clears the read-only bit git sets on loose objects and packs, which blocks removal on Windows. */
async function clearReadOnly(path: string): Promise<void> {
  const entry = await lstat(path);
  if (!entry.isDirectory()) {
    await chmod(path, 0o666).catch(() => {});
    return;
  }
  await chmod(path, 0o777).catch(() => {});
  for (const child of await readdir(path)) {
    await clearReadOnly(join(path, child));
  }
}

async function discardRepository(root: string): Promise<void> {
  await clearReadOnly(root);
  await rm(root, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
}

/**
 * Seeds a scratch repository and replays `operations` in order. The repository is removed on
 * success and retained on failure.
 */
async function executeTrace(
  source: string,
  operations: readonly ValidatedOperation[],
  fileCount: number,
  reproduce: string,
): Promise<void> {
  const root = await mkdtemp(join(tmpdir(), "rust-validator-fuzz-"));
  const executed: ValidatedOperation[] = [];
  let offending: ValidatedOperation | undefined;

  try {
    await seedRepository(root, fileCount);
    for (const operation of operations) {
      offending = operation;
      await executeOperation(root, operation);
      offending = undefined;
      executed.push(operation);
    }
  } catch (error) {
    // Deliberately no cleanup: the repository is the finding.
    throw new TraceExecutionError(
      describeFailure(source, root, executed, offending, error, reproduce),
      root,
      { cause: error },
    );
  }

  await discardRepository(root);
}

test(
  "every operation the git policy grants succeeds through simple-git",
  async () => {
    const exported = await loadTraceExport();

    assert.deepEqual(exported.seededSummary, SEEDED_SUMMARY);
    assert.ok(
      exported.randomTraceCount > 0,
      "every run must explore a randomized set, not only the fixed seeded one",
    );
    assert.equal(exported.traces.length, SEEDED_TRACE_COUNT + exported.randomTraceCount);
    for (const trace of exported.traces) {
      assert.equal(trace.operations.length, trace.summary.granted);
    }

    // The randomized traces differ every run, so a failure is only actionable with the seed that
    // produced them; the fixed set reproduces from its own name.
    const reproduce = `${SEED_VARIABLE}=${exported.randomSeed} bun run test:fuzz`;
    for (const trace of exported.traces) {
      await executeTrace(trace.source, trace.operations, exported.fileCount, reproduce);
    }

    console.log(
      `replayed ${exported.traces.length} validated traces ` +
        `(${SEEDED_TRACE_COUNT} seeded + ${exported.randomTraceCount} random, ` +
        `seed ${exported.randomSeed})`,
    );
  },
  900_000,
);

test(
  "a git rejection fails the trace and retains its repository",
  async () => {
    // Committing a path with no working-tree change exits non-zero with empty stderr — the case
    // simple-git's default error detection misses.
    const probe: ValidatedOperation[] = [
      { principal: "agent0", operation: "commit", path: "src/file0.txt", step: 0 },
    ];

    let repository: string | undefined;
    try {
      const failure: unknown = await executeTrace(
        "probe/commit-without-changes",
        probe,
        1,
        "this probe is synthetic and takes no seed",
      ).then(
        () => undefined,
        (reason: unknown) => reason,
      );

      assert.ok(
        failure instanceof TraceExecutionError,
        `expected a TraceExecutionError, got ${String(failure)}`,
      );
      repository = failure.repository;

      assert.ok(
        failure.cause instanceof GitExitError,
        `expected a GitExitError cause, got ${String(failure.cause)}`,
      );
      assert.notEqual(failure.cause.exitCode, 0);
      assert.match(failure.message, /offending step: agent0 commit src\/file0\.txt at step 0/);
      assert.ok((await stat(repository)).isDirectory(), "the failing repository must be retained");
    } finally {
      // An intentional probe, not a fuzz finding: this repository is not worth keeping.
      if (repository !== undefined) {
        await discardRepository(repository);
      }
    }
  },
  120_000,
);
