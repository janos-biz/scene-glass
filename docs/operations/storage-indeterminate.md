# Storage indeterminate-write runbook

A page-file mutation is durable only after the following ordered state transition. Treat any error as a failed mutation unless this runbook explicitly says otherwise; never report a successful write merely because the new bytes can be seen once.

```text
PREPARED -- atomic rename --> RENAMED -- fsync(parent directory) --> DURABLE
```

## Write-state contract

- **PREPARED**: Write the complete candidate page file to a new temporary file in the target directory, flush the file, and `fsync` that temporary file. The existing target is still the authoritative old page file.
- **RENAMED**: Atomically rename the prepared temporary file over the target in the same directory. The candidate may be visible as the target, but the directory entry has not yet been confirmed durable.
- **DURABLE**: `fsync` the parent directory succeeds after the rename. Only now may the mutation be acknowledged as committed.

Keep the temporary file in the same filesystem and parent directory as the target. A cross-directory move is not this protocol.

## Failure before rename

A failure while creating, writing, flushing, validating, or `fsync`ing the temporary file is a **pre-rename failure**:

1. Do not rename the temporary file and do not acknowledge the mutation.
2. Keep the old target as authoritative; its revision and replay window are unchanged.
3. Remove the incomplete temporary file only as best-effort cleanup. Failure to remove it does not make the mutation committed.
4. Return a failed/no-write result. A client may retry the same operation under ordinary idempotency rules only after the storage fault is resolved.

Do not replace the target manually from a partial temporary file.

## Directory-`fsync` failure after rename

An error from `fsync(parent directory)` after a successful rename is **indeterminate**. The process may see the old or new target, and a crash could produce a different durable result. Do not acknowledge the operation, retry a write, overwrite the target, or infer durability from the in-memory candidate.

1. Stop mutations for the affected page file and put it in quarantine. Do not run exports or repair jobs that rewrite it.
2. Preserve the pre-rename bytes, candidate bytes, operation ID, expected and candidate revisions, rename result, and the directory-`fsync` error. Do not include tokens in this record.
3. Read the target again using the normal strict page-file parser and all effective byte limits. Compare the entire validated file to the preserved pre-rename and candidate files; a matching revision alone is insufficient.
4. Classify the strict read-back:
   - **visible-old**: the complete validated target exactly matches the pre-rename file. The operation is not acknowledged.
   - **visible-new**: the complete validated target exactly matches the prepared candidate. The operation is still not acknowledged, because `DURABLE` was not reached.
   - **anything else**: missing file, parse failure, byte-limit failure, partial content, or a file matching neither expected value. Keep it quarantined as corruption.
5. Leave both `visible-old` and `visible-new` in quarantine until storage is healthy and recovery performs another strict read-back with a successful parent-directory `fsync`. Never "repair" by choosing a value from a partial read or by merging page files.
6. After a clean recovery check, resume writes from the recovered validated page file. If it is `visible-new`, retain its replay record so an identical retry resolves as an exact replay; if it is `visible-old`, the operation remains uncommitted and can be retried under normal idempotency rules.

## Release criteria

Remove quarantine only when the page file strictly validates, exactly matches a known old or candidate state, the parent directory can be `fsync`ed successfully, and the recovery outcome is recorded. Escalate a target that matches neither state as storage corruption; restore only through the approved backup/recovery process, not by hand-editing JSON.
