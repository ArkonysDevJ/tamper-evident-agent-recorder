# Layer ladder (experiment A)

The 17 cases of the tamper battery (15 primary, X1, X2) on copies of the frozen fixture, unchanged.
L3 is a SIMULATION of the external custodian: the retained manifest (bundle fingerprint and original
receipts) is built by the test from the original fixture, and compared with SHA-256 outside tear-verify.
Expected outcomes were predeclared before measurement (test/experiments/expected.ts).

| Case | L0 · plain log | L1 · local chain | L2 · chain and presented anchors | L3 · plus retained references (simulated custodian) |
| --- | --- | --- | --- | --- |
| T1-A2a | accepted | detected | detected | detected |
| T1-A2b | accepted | accepted | detected | detected |
| T2-A2a | accepted | detected | detected | detected |
| T2-A2b | accepted | detected | detected | detected |
| T3a-A2a | accepted | accepted | detected | detected |
| T3a-A2b | accepted | accepted | detected | detected |
| T3b-A2a | accepted | accepted | accepted | accepted |
| T3b-A2b | accepted | accepted | accepted | accepted |
| T4-A2a | accepted | detected | detected | detected |
| T4-A2b | accepted | detected | detected | detected |
| T5-A2a | accepted | detected | detected | detected |
| T5-A2b | accepted | detected | detected | detected |
| T6a-A2b | accepted | accepted | detected | detected |
| T6b-A2b | accepted | accepted | accepted | detected |
| T7-A2b | accepted | accepted | reduced coverage | reduced coverage |
| X1 | accepted | accepted | reduced coverage | reduced coverage |
| X2 | accepted | accepted | accepted | detected |
| **Totals** | 0 detected · 17 accepted · 0 reduced | 7 detected · 10 accepted · 0 reduced | 11 detected · 4 accepted · 2 reduced | 13 detected · 2 accepted · 2 reduced |
