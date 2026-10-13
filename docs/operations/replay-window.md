# Replay-window operations

Each page file keeps an exact, non-configurable replay window of **32** applied operation records. It is an idempotency record, not a cache and not a capacity setting. Configuration must reject every replay-window/count override; do not add an environment variable, project setting, or operational exception for it.

## Normal rollover

Replay records are ordered oldest to newest.

- At **31 -> 32**, append the new applied record. All 31 existing records remain, followed by the new record.
- At **32 -> 33**, construct the next candidate window by dropping only the oldest existing record and appending the new record. The persisted candidate still contains exactly 32 records: prior records 2 through 32, then the new record.

An operation ID already in the current window is resolved before revision checks. An identical operation returns its recorded result; the same ID with a different kind or input digest is rejected as reuse.

## Byte limits do not change rollover

The replay-result, replay-ledger, and page-file byte limits are evaluated against the full candidate after normal rollover. They must never cause early eviction of records from the existing window.

If any candidate exceeds a byte limit:

- return a **no-write** result with the limit reason and measured byte sizes;
- preserve the current page file unchanged, including its revision and all current replay records;
- do not persist the candidate and do not discard an existing record to make it fit.

In particular, a failed operation at 32 records leaves the original 32 records intact. It does not turn the window into 31 records and does not consume the failed operation ID.

## No-write remediation

1. Treat no-write as an uncommitted mutation. Do not acknowledge success, advance the expected revision, or run an automatic retry loop.
2. Capture the no-write reason (`result-bytes`, `ledger-bytes`, or `page-file-bytes`), measured byte sizes, project/page ID, and current revision. Do not record the token or full annotation content in logs unless the normal protected diagnostic process permits it.
3. Keep the existing replay ledger intact. Never manually delete or trim records, and never try to make room by changing the replay-window count.
4. Make the intended mutation fit the effective byte limits: reduce an oversized submitted value, or use a legitimate mutation that reduces page-file content. Limits can only be made more restrictive by configuration; an override cannot increase the built-in byte ceilings.
5. Resubmit after the change using the current page revision. An identical retry may use its original operation ID because the no-write was not recorded; a changed payload must use a new operation ID.
6. If no valid mutation can fit, leave the page unchanged and escalate the data/limit condition. Do not bypass the result, ledger, or page-file check.

This preserves idempotency for the last 32 committed operations while ensuring a byte-limit rejection never silently weakens replay protection.
