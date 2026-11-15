# Synthetic trace dataset

`traces.jsonl` is **synthetic**: it is produced by a script with a fixed seed and does not represent the
behavior of any agent or model. It feeds experiment B (the exposure window of an epistemic pause) through the
real interceptor.

- Generator: `scripts/generate-dataset.ts` (`npm run dataset:generate`), no dependencies, no external services.
- PRNG: mulberry32 (a small seeded generator, not cryptographic), seed `20261115`.
- 1000 steps, JSON Lines, UTF-8, one object per line with `task_id`, `step` and `kind` (`tool_call`,
  `epistemic_pause`, `human_resolution`, `final_answer`). A `tool_call` line carries its `result` or its
  `error` (`{"error_type", "message"}`); the replay adapter records the call, then the result, and generates
  `call_id` values unique across the whole chain.
- Parameters (declared in the script): pause probability 0.15 per non-final step (12.5 % of the steps are pauses);
  a resolution follows a pause with probability 0.5; tool error rate 0.1; task length 4–12 steps; argument size
  classes of about 100 bytes (share 0.7), 2 KB (0.25) and 20 KB (0.05).
- All text comes from closed lists of neutral words in the script: no person names, e-mail addresses, phone
  numbers, URLs or real organizations. No string is empty where Blueprint §4.4 requires a value, and none
  contains U+0000.
- SHA-256 of `traces.jsonl`: `b82cbe3be7fac8e48f90071a0b060679a28240dafc26eb625284d07a1ac55ea1`. A CI test regenerates it and checks this digest and that two runs give
  identical bytes.

License: AGPL-3.0-or-later, as the rest of the repository.
