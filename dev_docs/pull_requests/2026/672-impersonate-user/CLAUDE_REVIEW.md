# PR #672 — Add sign-in-as-user on an administrator's authority

**Author:** Timujeen · **Merged:** 2026-07-29 (`c2948d07`) · **Reviewed:** 2026-07-29

`MultiSession.impersonate/2` + a `Session` controller action + one route, built
on the existing multi-account stack.

**Verdict: the authority model is right; the audit trail did not match its own
docstring.** The role-based-not-permission-based decision is correct and the
reasoning in the docstring is worth keeping — `can_access_admin_area?/1` really
is true for any single permission holder, so a permission check here would have
let a customer with one self-service grant borrow another customer's account.
The escalation lattice (Owner never a target; Admin cannot take an Admin; Owner
can) is sound and the tests cover every arm of it.

What did not hold up is the part the docstring calls "the thing that makes this
feature dangerous": the record of what happened.

---

## BUG - HIGH — refused attempts left no trace, and the successful one was logged after the session had already changed

`lib/phoenix_kit_web/users/multi_session.ex:241-258`

The docstring: *"Logged as `session.impersonated` on the activity feed, always,
before the session changes."* The commit message: *"Every attempt is written to
the activity feed as `session.impersonated` before the session changes."*

Neither was true. `log_event/3` was called inside the `{:ok, conn}` branch of
`add_authenticated_user/2` — so it ran **only on success**, and **after** the
token had been minted and the session mutated. Every refusal wrote nothing:

- an Admin reaching for the Owner's account (`:target_is_owner`)
- an Admin reaching sideways for another Admin (`:target_is_staff`)
- a non-staff user hitting the endpoint directly (`:not_allowed`)

Those are the entries a security review actually goes looking for. A feature
whose stated justification is "an impersonation nobody can see afterwards is
dangerous" recorded exactly the case nobody needs to investigate.

**Fixed.** `impersonate/2` now records refusals as
`session.impersonation_refused` with the deciding rule in `metadata["reason"]`,
from both the authority check and the stack-append failures
(`:stack_full`, `:already_in_stack`, `:inactive`).

Refusal rows deliberately carry **no `target_uuid`**: `Activity.log/1` fans a row
with one out to that user's notification inbox, and "someone tried to sign in as
you and was refused" is a feed entry for whoever watches it, not a message to
send the owner.

## BUG - MEDIUM — a successful impersonation wrote two rows, one of them indistinguishable from a voluntary account add

`multi_session.ex:188-212`

`impersonate/2` delegated to `add_authenticated_user/2`, which unconditionally
logs `session.account_added` — then logged `session.impersonated` on top. Two
activity rows per impersonation, and the first is byte-identical in shape to what
a user adding a second account **of their own** writes. In the feed, filtered by
module or scanned by eye, an impersonation was indexed under the one sentence it
is precisely not.

**Fixed.** `add_authenticated_user/3` takes the event name (defaulting to
`session.account_added`, so the OAuth caller at `users/oauth.ex:327` is
unchanged) and `impersonate/2` passes `session.impersonated`. One row, correct
action. Test: "a success writes ONE row, and it says impersonated — not
account_added".

## BUG - MEDIUM — the impersonated user got an unmuteable inbox notification rendered as a raw action string

Both rows set `target_uuid` to the target, so `maybe_create_from_activity/1`
delivered **two** notifications to the customer. Neither action was claimed by
any type in `Notifications.Types.core_types/0`, so `key_for_action/1` returned
`nil`, `Prefs.user_wants?/2` failed open, and they could not be switched off —
they do not appear in the preferences UI at all. `Render.icon_and_text/2` had no
clause either, so they fell to the `humanize/1` fallback: the customer's bell
read **"Session impersonated"**.

This is the "two lists that must stay in sync" trap — a new action needs an entry
in `Types.core_types/0` and a clause in `Render`, and got neither.

**Fixed.** Both actions claimed by the `"security"` type (so they render in the
prefs UI and can be muted), and both given proper recipient-addressed copy:
"An administrator signed in to your account for support." Notifying the target is
kept — for an impersonation feature that is the correct default, and it was
already happening, just illegibly.

## BUG - MEDIUM — existence was checked before authority, making the endpoint a uuid oracle

`lib/phoenix_kit_web/users/session.ex:250-266`

The action resolved `Auth.get_user(user_uuid)` **first**, answering "User not
found." for an unused uuid and "You do not have permission to sign in as another
user." for a real one. `with_gate/3` admits every signed-in user — it only asks
that the root session be real — so any authenticated user could distinguish live
account uuids from dead ones by the flash. The precise-refusals design (right in
itself, and worth keeping) is what turned the ordering into a disclosure.

Impact is bounded: UUIDv7 identifiers are not guessable, so this confirms uuids
rather than discovering them. But `Session`'s own moduledoc lists "Prevents user
enumeration" as a security feature of the module.

**Fixed.** `MultiSession.may_impersonate?/1` settles the actor's authority before
the lookup. It shares the new `staff?/1` with `authorize_impersonation/2` so the
two rules cannot drift — the duplicated-authority-check smell is the thing to
avoid here, not the extra call. The pre-lookup refusal is logged too.

## IMPROVEMENT - HIGH — nothing marks a session as borrowed, so everything done inside one is attributed to the customer

Not fixed — flagging as a design gap before the feature is relied on.

Once the stack is `[admin(root), customer(active)]`, every subsequent action logs
`actor_uuid: customer.uuid` with nothing linking it back to the admin. The single
`session.impersonated` row at the moment of the switch is the only connection,
and correlating it with later activity means reasoning about timestamps.

The information is already there — `root_user(session) != active` is exactly the
condition — it just isn't surfaced onto `Scope` or read by `Activity.log/1`. A
`metadata["on_behalf_of"]` stamped when root ≠ active would close it. That is a
larger change than a post-merge fix, and it touches the activity write path for
every request, so it belongs in its own PR.

## IMPROVEMENT - MEDIUM — the feature ships inert; there is no button

`rg impersonat` finds the route, the controller, the context and the tests — and
zero templates or LiveViews. The controller docstring refers to *"the 'log in as
this user' button in the admin area"*; there isn't one. A host has to hand-roll a
POST form with a CSRF token and a `return_to` to reach it.

The PR says it was "verified against a running application", so the UI likely
exists downstream. Not fixed — adding an admin-user-list button is a product
surface decision, not a review fix. Recorded so the gap is known.

Related: `README.md:160` still lists "User impersonation" under *Missing features
for User Auth Module*.

## NITPICK — impersonation requires `multi_session_enabled`, and says so in switcher language

`with_gate/3` refuses when the setting is off, with *"Multi-account switching is
not available."* A host that wants support access but not user-facing account
switching cannot have one without the other, and the operator gets a message
about a feature they weren't using. Defensible — impersonation genuinely is built
on the stack — but worth knowing it is coupled.

## NITPICK — `metadata["actor_role"]` is hardcoded `"admin"`

`log_event/3` asserts the actor's role rather than deriving it, so an Owner
impersonating is recorded as an admin. Pre-existing (it predates this PR, via
`session.account_added`), left alone.

---

## Verified, not changed

- **`Auth.get_user/1` is uuid-safe** — it guards with `UUIDUtils.valid?/1` and
  returns `nil`, so `POST …/impersonate/garbage` is a flash, not an
  `Ecto.Query.CastError`. Checked because a raw `Repo.get` on a UUIDv7 primary
  key would have 500'd on any signed-in user's malformed input.
- **Authority reads the ROOT, never the active account.** This is the invariant
  that stops chaining, it is implemented correctly, and the test for it is real.
- **`:self` is checked before the role rules**, so an Owner cannot take their own
  account by falling through the `owner in actor_roles -> :ok` arm.
- **`renew_and_put_active_token/2` runs** on the impersonation path (inherited
  from `add_authenticated_user/3`), so session fixation protection applies.
- **`log_event/3` rescues.** A failed activity write cannot block a session
  operation. Correct trade-off here, and the same shape the rest of the module
  uses.
- The `"*"` superadmin permission key is **not** honoured by
  `authorize_impersonation/2`. Consistent with the role-based decision and
  correct — `"*"` is a permission grant, and the whole point of this rule is that
  permissions do not confer impersonation authority.
