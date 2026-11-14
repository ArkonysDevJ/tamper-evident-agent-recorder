# Spec 008 — Durable file primitives

Normative source: `docs/BLUEPRINT.md`. This spec only points to it. Each acceptance criterion names the test
that proves it.

## 1. Objective

Provide the namespace file operations the anchoring flow and recovery build on: durable publish, durable
delete, the recovered-package durability barrier, and fail-stop handling of any mutation failure.

## 2. Blueprint sections

§5.5.

## 3. Out of scope

- When and why the primitives are called: the TSA flow (§5.7) — spec 003; recovery (§5.6) — spec 006.
- Namespace provisioning (§5.1) and the invalidation barrier itself (§5.3) — spec 001.

## 4. Acceptance criteria

| ID | Criterion | Blueprint | Test |
| --- | --- | --- | --- |
| AC-1 | Publish follows the §5.5 call sequence (open `.tmp`, write, fsync, close, rename, fsync directory, close in finally), checked by call order. | §5.5 | `008 AC-1 publish` |
| AC-2 | Durable delete unlinks, then fsyncs the directory; ENOENT is ignored only for a target declared optional. | §5.5 | `008 AC-2 durable-delete` |
| AC-3 | The recovered-package barrier opens each file as a regular file without following symlinks, fsyncs it, then fsyncs the directory; a symlink is rejected. | §5.5 | `008 AC-3 recovered-package-barrier` |
| AC-4 | Every primitive checks the invalidation guard before it starts and runs on the chain's serial queue. | §5.3, §5.5 | `008 AC-4 guarded-and-queued` |
| AC-5 | A failure in any unlink, file fsync, rename, directory fsync or close invalidates the writer, starts the drain-and-exit protocol and starts no cleanup. | §5.5 | `008 AC-5 mutation-failure` |

## 5. Dependencies

Spec 001.

## Implementation choices (not normative)

Recorded here and declared in the report of the work package that implements them.

- **Mutation queue:** each writer generation owns one `DurableNamespace`, whose strict FIFO queue carries every
  file mutation of the chain and tracks it until it settles. Chain operations that publish or delete (anchoring,
  recovery, close) await these mutations from inside their own slot of the chain's operation queue, so the two
  queues never interleave work for one chain. §5.3 requires every file mutation of a chain to share one strict
  serial queue; it does not require that queue to be the chain's operation queue.
- **Guard checks:** the guard is checked before each operation starts and again before each mutating system call
  inside it. An invalidation observed mid-operation stops it there, with no cleanup.
- **Entry names:** a mutation accepts only a plain entry name inside the namespace and never `.writer.lock`; an
  invalid name is rejected before any system call and is not a mutation failure.
- **Fail-stop:** a failed mutation invalidates the guard, refuses all later work, and calls the owner's
  drain-and-exit handler once, after everything already queued has settled.
