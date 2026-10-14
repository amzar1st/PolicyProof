# PolicyProof

PolicyProof uses GenLayer Intelligent Contracts to assess public evidence against immutable organization-published policies. Each mandatory requirement receives its own outcome, source fingerprints, exact quotations, and support audit. Final records preserve the complete evidence-to-verdict relationship.

Public app: https://policyproof-reviewed.tinymule33.chatgpt.site

## Development deployment

This is a resettable StudioNet demonstration (chain 61999), with fictional organizations and incidents. Registrations are **SELF_DECLARED**. A signed account proves account control, not legal identity, professional accreditation, or domain ownership. There are no payments, escrows, or legal certifications.

The current contract and network configuration are in [`lib/deployment.json`](lib/deployment.json). The replacement public app URL and verified dispute receipts are documented in [`docs/steward-response.md`](docs/steward-response.md) and [`docs/live-dispute.json`](docs/live-dispute.json).

## Evidence integrity

- Each attachment records the leader’s retrieval result as `VALID`, `EMPTY`, `UNAVAILABLE`, `HASH_MISMATCH`, or `TOO_LARGE`, its party, expected commitment and retrieved content SHA-256 when available. Rejected attachments cannot veto reliable opposing evidence.
- Full documents up to 64,000 characters are passed to both the requirement evaluation and a separate semantic support audit. Larger documents are excluded completely, never silently truncated. Necessary missing facts yield `UNKNOWN`; affirmative independently supported violations can still be recorded.
- Optional hashes commit to exact UTF-8 rendered text, not raw HTML or screenshot bytes.
- Policies contain 1–24 immutable requirements separated by newlines or semicolons. Compound clauses remain part of the same requirement and must all be satisfied. Review cannot omit or duplicate a requirement ID.
- `SATISFIED` and `VIOLATED` need exact source quotations, checked as contiguous substrings of successfully retrieved full documents. A separate semantic audit checks whether those quotations entail the particular requirement outcome in context, including later qualifications and contradictory facts. Unsupported relations become `UNKNOWN`.
- Validators independently fetch sources and run the requirement evaluation and support audit. Invalid-source failure details are recorded individually and cannot veto otherwise sufficient reliable evidence. Consensus compares each attachment’s validity, reliable content fingerprints, and requirement outcomes; rejected-source diagnostics are retained for audit without requiring their irrelevant failure details to match. Each validator also verifies the leader’s quoted spans against its own complete retrievals and independently checks that they substantiate materially equivalent decision-critical facts. Different reliable page versions or conflicting factual observations cannot silently agree merely because their verdict labels match.
- Aggregate verdicts are derived deterministically: all satisfied = `COMPLIANT`; both satisfied and violated = `PARTIALLY_COMPLIANT`; any violation with no satisfied requirement = `NON_COMPLIANT`; otherwise ambiguity or missing facts remain unresolved. Missing evidence alone cannot prove a violation.

Equivalent valid quotations can differ in wording or span when independent semantic verification confirms the same decisive facts. Transient failures of necessary sources, conflicting facts, or changed reliable source bytes can prevent consensus. Participants can retry an unaccepted transaction; they cannot overwrite a recorded review or reset its filing deadline. Immutable, hash-committed sources are preferable. LLM entailment remains a semantic judgment, not a mathematical proof.

## Disputes

`create_organization → publish_policy → open_compliance_check → submit_evidence / submit_response → validator_review → challenge → submit_counter_evidence → validator_review → finalize`

Each side has four initial evidence slots and two reserved dispute slots. The original challenge **filing deadline** stays fixed. A challenge opens one full, separate, bounded response period from its filing time, even if filed just before the filing deadline. Only the opposing party can append counter-evidence during this period; replies cannot extend it. The second review waits for the response deadline. One challenge round is allowed, and the second review can be finalized immediately. A hard expiry permits `resolve_timeout` without attestation.

Only finalized `COMPLIANT` issues a scoped attestation. Partial/non-compliance produces a violation record. Ambiguity, insufficient evidence, and expired checks remain unresolved. Invalid unrelated attachments do not automatically prevent an otherwise supported attestation.

## Signed accounts

The app supports a connected wallet on StudioNet or a freshly generated local demo signer. Demo private keys stay in browser memory, never server logs or persistent browser storage, and disappear on refresh. Use a wallet for durable ownership. Entering another address is read-only and cannot provide its signing key.

The proxy accepts only signed, zero-value transactions for the configured PolicyProof contract, recovers the signer, requires it to match the consensus transaction sender, and checks the chain ID. The contract enforces organization-owner and party restrictions using the transaction sender. Tests include forged sender substitution, wrong-chain signatures, foreign contract targets, and another participant attempting owner-only publication.

## Verification

```bash
python -m unittest discover -s tests -v
node --experimental-strip-types --test tests/frontend.test.mjs
pnpm install --frozen-lockfile
pnpm exec tsc --noEmit
pnpm build
node scripts/verify-live.mjs
```

The Python suite is a behavioral harness, not GenVM or network consensus. Node tests cover receipts, deadline/account gating and cryptographic sender checks. Live evidence is recorded separately and is complete only when receipts and execution are successful, the final state is confirmed with `LATEST_FINAL`, and deployed source equality is checked. Pending, accepted, reverted, or historical results are never represented as a completed new demonstration.

[`scripts/live-dispute.mjs`](scripts/live-dispute.mjs) deploys the current source with 120-second evidence and 180-second challenge/response windows, generates two distinct ephemeral signing accounts, attempts unauthorized publication, and runs the fictional contested workflow. It uses accepted state only for orchestration, then independently waits for all transaction finalizations and reads final state. Generated keys never enter the proof file. Running it deploys a new contract and updates `lib/deployment.json`; do not run it against a production account.

The original demonstration remains in `docs/live-verification.json` as historical evidence and does not prove the upgraded contract's behavior.
