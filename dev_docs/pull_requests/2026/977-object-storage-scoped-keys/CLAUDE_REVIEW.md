# PR #977 — Pass the object storage check for a key limited to buckets

**Author:** timujinne · **Merged:** 2026-10-24 (f2ba0b24f) · **Reviewer:** Claude

## Summary

An `object_storage` connection's Test Connection calls `ListBuckets`. A key
scoped to one bucket (an R2 token limited to specific buckets/objects) gets
`AccessDenied` there, which used to fail the check permanently on a correctly
configured connection. `AccessDenied` now passes as `{:ok, %{fact: note}}`
("not allowed to list buckets — bucket access was not verified"), the same shape
as SES's `AccessDenied` for `GetSendQuota`.

Verdict: correct.

- `request_list_buckets/2` hands any non-`{:invalid, _}` result through, so the
  `{:ok, note}` reaches the verdict unchanged, with and without the confirm
  retry; both paths are tested.
- `InvalidAccessKeyId` / `SignatureDoesNotMatch` still go through the retry and
  fail; busy codes still say "try again".
- Bucket access is still checked where it matters: the bucket form's
  `S3.test_connection/1` does a put/get/delete probe on the bucket itself.
- The changed msgid is in `default.pot` and all nine `.po` files, translated
  (en empty as usual), no fuzzy entry, old msgid gone.

## Findings

- None. The note deliberately does not claim the cause (an IAM user with no S3
  rights also answers `AccessDenied`), which is the honest wording for a pass.
