# Causal Replay

## Flight recorder note 44

The loudest failure is often not the first one. Causal Replay freezes an ordered execution trace beside the runbook that was supposed to govern it. A nominated analyst asks validators to locate the earliest material divergence, assign one bounded cause class, and preserve both source digests. Later symptoms cannot replace the first causal coordinate.

## Transcript

```text
OPEN
  analyst reconstructs
REPLAYED(index + class + rationale)
  auditor may attach fresh-origin correction
CHALLENGED
  anyone closes after the window
REOPENED
```

An unchallenged reconstruction closes as `CONFIRMED`. A material challenge must change the index or cause class and is itself validator-checked. The owner cannot suppress either outcome; finalization and expiry are permissionless after their clocks.

## Cause alphabet

`CONFIG / DATA / SEQUENCE / PERMISSION / EXTERNAL / NONE`

## Reproduce the recorder

```bash
genvm-lint contracts/contract.py
python -m pytest -q
```

The three files under `evidence/` are operator-created technical fixtures, not independent incident authorities.
