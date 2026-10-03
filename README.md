# PolicyProof

GenLayer DApp for checking whether an organization complied with an immutable, owner-published natural-language policy. Validators independently retrieve public evidence, interpret the policy, and reach consensus before a scoped attestation or violation record is finalized.

## Deployment

- Public app: [PolicyProof](https://policyproof.amzar1st96.chatgpt.site).

- Network: **Studionet (61999)**, development environment; state can reset.
- Contract: [`0xFe06c46228B2a35Af131BB175FB1F043473f4D10`](https://explorer-studio.genlayer.com/address/0xFe06c46228B2a35Af131BB175FB1F043473f4D10).
- RPC: `https://studio.genlayer.com/api`.
- Source: [`contracts/policyproof.py`](contracts/policyproof.py).
- Deployment via GenLayer Studio's built-in account, Normal (Full Consensus); no external wallet connection.
- Evidence window: 300 seconds; challenge window: 120 seconds; resolution deadline: 86,400 seconds.
- Synthetic demonstration: `org-1`, `policy-1`, `check-1`. The fictional incident and organization are explicitly labeled; no real entity is being certified.

## Workflow

`create_organization → publish_policy → open_compliance_check → submit_evidence / submit_response → validator_review → challenge / submit_counter_evidence → validator_review → finalize`

Unfinished checks have a deadline-gated `resolve_timeout` exit. All public writes are exposed in the frontend, including challenge, counter-evidence, retry review, finalization, and timeout.

Verdicts: `COMPLIANT`, `PARTIALLY_COMPLIANT`, `NON_COMPLIANT`, `POLICY_AMBIGUOUS`, `INSUFFICIENT_EVIDENCE`.

Only finalized `COMPLIANT` creates an attestation. Partial and non-compliance record violations. Ambiguous, insufficient, and expired checks remain unresolved without an attestation. There are no escrow balances, payment flows, or bonds.

## Safeguards

- Only the organization owner publishes policies. Versions are immutable and checks pin a policy ID and SHA256.
- Registrations are **SELF_DECLARED**, not domain ownership or legal identity verification.
- Only the requester and organization owner submit evidence. Each side has four initial slots and two reserved challenge slots; one side cannot consume the other's capacity.
- Review cannot precede the submission deadline. Challenges preserve their original deadline. One challenge round per check prevents indefinite extension; finalization waits for the post-review challenge period.
- Each validator independently fetches evidence and runs the AI interpretation; the verdict, fetched URLs, failed URLs, and citations must agree.
- Every substantive verdict needs exact citations among successfully fetched URLs. Unavailable, empty, or optional hash-mismatched submitted evidence blocks a positive attestation.
- Optional hashes commit to **exact UTF-8 rendered text**, not HTML, screenshots, or raw document bytes. Snapshot hashes record the leader's fetched text; they are audit references, not proof that all validators saw identical page bytes.
- Policy text, claims, responses, and page content are delimited as untrusted data in the AI prompt. This reduces, but cannot eliminate, prompt injection and model interpretation risk.
- All frontend reads explicitly use `LATEST_FINAL`. Pending and Accepted transactions are not shown as completed writes. A finalized receipt must also contain a successful leader execution; receipts can be rechecked without resubmission.
- The app's fixed upstream RPC proxy allows zero-value writes only to PolicyProof through the Studionet consensus contract. No private keys or wallet extension connection are used.

## Studio account model

The app supports the same address-based development sender model as the Studio simulator. Select an address from Studio or generate a new development sender. These addresses **do not provide production wallet authentication**. This deployment is suitable for development demonstrations; use a persistent testnet with signed wallet transactions and authenticated organization identity for production use. Attestations cover a particular policy version and check scope, not general legal or regulatory compliance.

## Verify

```bash
python -m unittest discover -s tests -v
node --experimental-strip-types --test tests/frontend.test.mjs
pnpm install --frozen-lockfile
pnpm exec tsc --noEmit
pnpm build
node scripts/verify-live.mjs
```

The behavioral suite has 37 tests with a lightweight GenLayer harness; it verifies contract rules, not actual GenVM storage or network consensus. The 12 frontend tests cover account/deadline gating and finalized receipt failure handling. `verify-live.mjs` independently checks deployed source equality, finalized reads, and public transaction receipts. See [`docs/live-verification.json`](docs/live-verification.json) for the latest network evidence.

## Reviewer walkthrough

1. Open the app and inspect `check-1` in the Checks tab.
2. Read the immutable policy, synthetic evidence, validator reasoning, fetched citations, and final attestation.
3. Open the contract explorer and match the address to `lib/deployment.json`.
4. Select a fresh Studio development account; register your own organization and publish a policy.
5. Open a check, add public evidence, and optionally respond as the organization owner.
6. Wait five minutes; request validator review. Wait two minutes, then finalize, or challenge within the window with a new evidence URL.
7. Inspect the Transactions tab and wait for finalized successful execution; use Recheck receipt if needed.

The live example proves only the fictional fixture's workflow. It is not an independent audit of a real organization's conduct.

## Verified live demo

Studionet full consensus finalized `check-1` with `COMPLIANT`, issuing `attestation-check-1` after the challenge window. This attestation covers fictional incident PP-DEMO-001 only. The deployed source matches `contracts/policyproof.py` byte for byte. Deployment, organization, policy, check, response, review, and finalization transactions all finalized successfully. See [sanitized live verification](docs/live-verification.json).

Validation: 37 contract behavior tests, 12 frontend action/receipt tests, TypeScript checking, and a successful production build. The Python harness simulates the runtime; the live consensus demonstration is verified separately.
