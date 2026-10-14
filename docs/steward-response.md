# PolicyProof steward remediation

Public replacement app: https://policyproof-reviewed.tinymule33.chatgpt.site (public deployment succeeded). Network: StudioNet, chain 61999.

| Request | Implementation and verification |
| --- | --- |
| Invalid evidence must not veto opposing reliable evidence | Per-attachment status and fingerprint; valid pages are evaluated independently. Tests cover malicious hashes from both sides, unavailable optional sources, and supported violations. |
| Compare substantive evidence across validators | Independently retrieved full-content hashes, reliable source fingerprints and requirement outcomes must match. Validators independently verify the leader’s quotes in their own full documents and compare the material supporting facts semantically; equivalent excerpts need not match character for character. Source-version and factual-outcome conflicts reject consensus. |
| Requirement-level citations | Immutable ordered requirements, complete ID coverage, exact substring quotation checks, separate semantic entailment audit, and preserved requirement/source/quote records in reviews and attestations. |
| Fair late challenges | Fixed filing deadline plus one full response window from filing; opponent-only counter-evidence, no reply extensions, second review cannot execute early. Last-second and deadline-boundary tests included. |
| Sender identity/authentication | Wallet signatures or ephemeral local signers. Typed addresses are read-only. Proxy recovers the signer and validates chain, sender and target. Organizations remain SELF_DECLARED. Tests include address impersonation and live unauthorized owner-only publication. |
| Long documents | Complete documents through 64,000 characters in both semantic passes. Larger sources are individually marked TOO_LARGE and excluded; no 16,000-character prefix judgments. Tail qualification and over-limit tests included. |
| Adversarial tests | 60 distinct Python behavioral cases and 23 Node cases, plus TypeScript and a production build. These are separate from live network consensus evidence. |
| Two-participant contested StudioNet demonstration | Completed on the replacement contract. Two distinct signed parties, an invalid organization hash, NON_COMPLIANT first review, substantive organization challenge, requester counter-evidence, PARTIALLY_COMPLIANT second review, and FINALIZED violation record. All 12 deployment/workflow receipts finalized; independent verification is in live-dispute-verified.json. |

The fixture is a clearly labeled fictional disclosure/remediation dispute. An authoritative ledger records disclosure after 48 hours against a 24-hour requirement. The organization initially attaches a deliberately wrong hash. Its challenge introduces an on-time remediation report and disputes disclosure timing; the requester counters with a final authoritative timing correction. The desired supported result is a violation on disclosure and satisfaction on remediation, without interpreting invalid evidence as a veto.

Reliable source versions and decision-critical factual agreement are conservative; equivalent valid excerpts are independently checked rather than compared as strings. Conflicting source versions can prevent a transaction reaching consensus rather than producing an unsupported record. Semantic evaluation and its audit remain LLM-based judgments; automated tests do not establish model infallibility or real-world organizational identity.

An earlier live attempt failed closed when a model returned non-JSON output during the second review. `docs/live-dispute-superseded.json` preserves that attempt; it is not presented as completed evidence. The replacement uses JSON response mode with strict schema checks and a safe fenced-JSON fallback. Browser wallet extension interactions were not automated; signed proxy requests were verified against the public deployed app.

## Completed live dispute

Contract: `0x6614698395eb72b90ed6602Aa8416b398B25140C`. Check: `check-1`. Final result: **PARTIALLY_COMPLIANT**, record type **VIOLATION**. R1 disclosure timing is VIOLATED; R2 remediation is SATISFIED. Both reviews preserve quotations and independently retrieved source fingerprints. The organization’s HASH_MISMATCH attachment remains recorded and cannot veto these findings.

The original signed parties filed the substantive challenge and counter-evidence before the interruption. A fresh signed keeper resumed the permissionless second review and finalization after the bounded response deadline; it did not submit party evidence or impersonate either participant. All deployment and workflow receipts were checked as FINALIZED, including the expected rejected unauthorized publication. The final registry was read with LATEST_FINAL, and deployed contract bytes match the checked source.

The public application was rechecked against this contract: finalized reads succeeded, unsigned writes were rejected, and a signed fictional organization creation finalized successfully. Receipt: `0x01c3d78f812253090b3ada94462d83791315de40c0ee2375f9342a0a590cf2ca`.
