# PR #670 — Fix double interception on a queue worker's re-send

**Author:** Timujeen · **Merged:** 2026-07-29 (`3cbddd11`) · **Reviewed:** 2026-07-29

Follow-up to the GLM review of #668. Adds `already_intercepted: true` so a queue
worker's drain call does not run `intercept_before_send/2` a second time, logs
out-of-contract returns from `maybe_enqueue/2`, and closes the two test gaps GLM
flagged (the queue seam and the `Validators.smtp/1` translation arms).

**Verdict: sound.** The fix is the right one of the three GLM offered — it makes
"already handled" explicit rather than asking every provider to be idempotent.
One contract hazard, fixed below; one GLM finding left deliberately open.

---

## IMPROVEMENT - MEDIUM — `already_intercepted` and `skip_queue` were independent, so the contract could be got half right

`lib/phoenix_kit/mailer.ex:380-410`

The provider docs instruct the worker to pass **both** opts. Nothing enforced it.
A worker that passed only `already_intercepted: true` skipped interception and
then fell through to `offer_to_queue/3` — handing its own dequeued job straight
back to the queue it came from. That is an enqueue loop, produced by getting one
half of a two-part contract right, and it would only ever be discovered in a
host app with a real queue provider installed (there is none in core, which is
why no test could have caught it).

`already_intercepted: true` has exactly one meaning — "a worker is re-sending
what it dequeued" — so it now implies `skip_queue`. Passing both is still legal
and still clearer to read.

**Fixed.** `mailer.ex` + the `maybe_enqueue/2` callback doc in
`email/provider.ex`. Test: `mailer_test.exs` — "already_intercepted alone still
skips the queue, so a worker cannot loop".

## NITPICK — the `queued: true` shape is documented on `deliver_email/2`, the two opts that control it are not

`lib/phoenix_kit/mailer.ex:190-212` documents the return shape and mentions
`skip_queue: true`, but `already_intercepted:` appears only on the `maybe_enqueue/2`
callback doc in `email/provider.ex`. A worker author reads the Mailer's docs.
Left as-is — the callback doc is where a queue implementer is already looking,
and duplicating opt tables is how they drift.

## Left open (GLM finding 4) — "sent" copy for a message that was only queued

`email_sending.ex:137-144` flashes "Test email sent to …" and
`notifications/channels/email.ex:60` marks the notification delivered, both on a
`{:ok, %{queued: true}}` that no relay has seen. GLM raised it; #670 did not
address it and neither did I. It needs a product decision (is "accepted for
delivery" close enough for the operator-facing copy?) rather than a fix, and
touching it means touching notification delivery accounting. Recorded so the API
evolution stays a conscious choice.

---

## Verified, not changed

- `offer_to_queue/3`'s `Code.ensure_loaded?` + `function_exported?` pair is
  correct for an unloaded module under a release, per the registry rule in
  `CLAUDE.md`.
- The new `other ->` branch fails **open to sending** and logs. Right call: a
  provider bug must not silently eat mail.
- `handle_after_send/2` still runs on the worker's re-send. That is what closes
  out the log row the message already carries, and the new test pins it.
- The `Validators.smtp/1` test covers all five new translation arms; those sit
  outside `Probe.run`'s rescue, so an unmatched reason really would surface as a
  `CaseClauseError` in the LiveView callback. Good test to have written.
