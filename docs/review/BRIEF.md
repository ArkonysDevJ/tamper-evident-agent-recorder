# Adversarial review brief — TEAR repository

**For:** an independent reviewer with no prior context on this project.
**Object:** the public repository at the commit given by the author. Read-only review: do not modify files, do not open pull requests.
**Time box:** one pass, about 60–90 minutes. Report what you could not cover.

## What the repository claims

Read `README.md` and `docs/REPORT.md` first. They state what was built, what was measured, and what was not tested. The normative specification is `docs/BLUEPRINT.md` (`docs/BLUEPRINT.rendered.md` is the same text, easier to read).

Your job is to find where **the code or the tests do not support what those two documents say**. Assume the documents may overstate, and assume the tests may be weaker than they look.

## Questions, in priority order

1. **False accepts in the verifier.** Is there any input for which `tear-verify` exits 0 or reports `VERIFIED_ANCHORED` when the specification requires a failure? Look hardest at: the DER reader (the project's own code, never externally reviewed), time-stamp token validation, certificate path building against the pinned bundle, and the precedence of checks.
2. **Tests that cannot fail.** For the tamper matrix (`test/tamper/`): are the expected outcomes written independently of the code under test, or derived from it? Does each mutation really change the bytes it claims to change? Would the test still pass if the verifier were broken in an obvious way? Same question for the layer ladder and the pause-exposure experiment.
3. **Recording before acting.** Is there any path where a tool runs, or an answer is delivered, without a confirmed durable commit of its record? Any path where an error is swallowed and execution continues?
4. **Report versus repository.** Pick ten concrete claims or numbers from `docs/REPORT.md` and trace each to the test or generated file that produces it. List any you cannot trace, and any that the code contradicts.
5. **"Not tested" list.** Is there anything the code does not test that the report fails to list? Is anything listed as tested that is only exercised with a stub or a test double?
6. **Repository hygiene.** Secrets, private keys, personal data, or real e-mail addresses in files or commit messages. Dependencies and install scripts that deserve a second look.

## How to report

For each finding:

- **Severity:** *breaks a reported result* / *weakens a claim* / *minor*.
- **Where:** file and line, or commit.
- **What:** the concrete input, state or code path, and what happens.
- **Evidence:** how you know. Mark clearly whether you **ran** it, **read** it, or **inferred** it.

Then two lists: what you checked and found sound, and what you did not get to.

Do not propose redesigns. Do not rate the project. If you find nothing in an area, say so in one line.
