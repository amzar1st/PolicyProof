# PolicyProof review evidence

- Public replacement application: https://policyproof-reviewed.tinymule33.chatgpt.site (public deployment confirmed).
- Repository: https://github.com/amzar1st/PolicyProof
- Contract: see `lib/deployment.json` for the replacement deployment.
- Steward remediation details: `docs/steward-response.md`.
- Contract implementation: `contracts/policyproof.py`.
- Behavioral tests: `tests/test_policyproof.py` and `tests/fake_genlayer.py`.
- Signed-account, action and receipt tests: `tests/frontend.test.mjs`.
- Two-party live demonstration: `docs/live-dispute.json` contains the completed two-party disputed workflow and finalized receipts; `docs/live-dispute-verified.json` independently verifies source equality, execution results and final state.

The existing `docs/live-verification.json` and `docs/studio-finalized.jpg` are historical evidence for the original contract. They are not evidence that the revised adjudication mechanism completed a disputed check.

Only a successful final record and finalized receipts demonstrate completion. Synthetic fixtures are labeled fictional and are not evidence of a real organization's compliance. Registrations are self-declared even where the sender's account control is authenticated by a transaction signature.

## Completed remediation result

83 automated tests passed (60 Python, 23 Node); TypeScript passed. The replacement deployment finalized check-1 as PARTIALLY_COMPLIANT / VIOLATION after two reviews, a substantive challenge, and counter-evidence. See `docs/steward-response.md` for the request-by-request implementation and `docs/live-dispute-verified.json` for the 12 finalized deployment/workflow receipts. The unauthorized owner-only publication was an expected finalized failure, not a successful write.
