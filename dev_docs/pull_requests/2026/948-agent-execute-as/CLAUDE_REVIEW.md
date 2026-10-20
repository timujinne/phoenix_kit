# PR #948 — Run API tools on behalf of a live session (reads only)

**Author:** timujinne · **Reviewer:** Claude · **State at review:** merged

## Review

No defects found. `SessionRef.scope_for_session/2` rebuilds the scope from the token row on
every call by the web's own rules (`session` context, not expired, not `api_only`, same user,
active, confirmed, invite gate), and the active role comes from the same virtual field the
cookie path uses. `execute_as/5` checks scope, then the tool's own permission, then refuses any
non-read tool before validation and `Flow.gate/1`; `allow:` raises on anything but `:read`; the
rate-limit bucket is per user and the refusal path pays one unit like a key's. `Actor` hides
`:scope` from `inspect/1`, and `Keys.actor/3` reuses one scope build for the key's scopes and
`ctx.scope`. The reference is documented as an in-process credential taken only from the signed
session of the running LiveView.

- **NITPICK** — `SessionRef.from_session/1` does not refuse an impersonated session; that is
  `MultiSession.impersonated?/1`'s job and both moduledocs say so. A caller that forgets it
  acts as the borrowed account. Left to the caller by design.
