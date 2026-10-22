# PR #953 — Make the public machine API module-neutral, with the shop paths as deprecated aliases

**Author:** timujinne · **Merged:** 2026-10-20 (1cc020760) · **Reviewer:** Claude

## Summary

Renames the public audience from `shop` to `public` (`/api/public/v1`, `/mcp/public`) behind one path table (`API.Paths`), keeps
`/api/shop/v1` and `/mcp/shop` as deprecated aliases (`Deprecation` + `Link: rel="successor-version"`, one log line per path per
node), and moves every shop-specific name into `API.Legacy` (deleted in 3.0.0): the three renamed rate-limit settings (new key,
then old key, then default), the `cart_token` client token (now `Tool.client_token`, read once the tool is known), the four shop
error codes (now `c:Module.api_problems/0`), and the credential-name rule (`Auth.credential_name?/1`, `*_token`).

Verdict: sound. The router forwards and `BodyGuard` read the same table, so they cannot disagree; the alias answers carry the
deprecation marks on every path that reveals anything and none on the bare 404; no document, catalog or `Link` advertises an alias.

Verified rather than assumed:

- `@1792454400` is 2026-10-20T00:00:00Z.
- `Confirmation` renames the field to `client_token_hash` with `source: :cart_token_hash`; the V220 column is untouched (no
  migration, `expected_schema` unchanged) and nothing in `lib/` still queries the old field name.
- Public rate limiting: the pre-lookup charge is now the network bucket only, so a flood of invented tool names creates no token
  counter; a call pays `cost` to the token bucket and `cost - 1` to the network bucket afterwards, i.e. `cost` in each.
- The Settings -> API form writes a limit that is in effect only through an old key under the new key (`rate_limits_without_fallback/0`).
- A tool that predates `client_token` keeps its rate limit, idempotency scope and danger gate through `Legacy.legacy_client_token/1`
  (executor, lint and `Flow.finish` all see the filled-in field).
- Tests: `test/phoenix_kit/api`, the four `api_*` web tests, `live/settings` and `integration/api` — 2086 tests, 0 failures.

## Findings

- **NITPICK (not changed):** `Auth.credential_name?/1` now refuses any query parameter that ends in `_token`
  (`token_in_url?/1`), and treats any output field ending in `_token` (`refresh_token`) as unstorable for replay. Both are
  deliberate and documented, but a future public GET tool with a pagination cursor named `page_token` would be refused with
  `400 token_in_url`; name such a cursor `cursor`.
- **NITPICK (not changed):** `Problem.resolve/1` asks every enabled module's `api_problems/0` for each non-core code it answers
  (documented in the moduledoc: "asks every module again on every call"). An anonymous caller can provoke a module code at will,
  but the network bucket bounds it and the callbacks are map literals. Cache only if a module ever computes its map.
- **NITPICK (not changed):** a public tool that names its client token without the `_token` suffix is neither refused in a URL nor
  filtered from the request log; the `Tool` docs say so and tell authors to use `*_token`.
- **NITPICK (fixed, found by /code-review):** the admin API guide still spelled `/api/admin/v1` and `/mcp/admin` by hand although
  `Paths` is "the one table"; it now takes `Paths.rest_path(:admin)` / `Paths.mcp_path(:admin)`.
- **NITPICK (not changed, /code-review):** `Paths.put_deprecation/2` runs at the top of `Auth.call`, so a request to a deprecated
  alias computes `PublicDiscovery.origin/1` (and the host's `:api_request_context` hook) before the URL-credential check and
  authentication. It touches only deprecated paths and the node's network bucket applies later; build the `Link` lazily if the
  aliases stay long.
- **NITPICK (not changed, /code-review):** the renamed `Actor.cart_token_hash` has no shim. `phoenix_kit_ecommerce` already reads the
  new field, so the one known consumer is covered; an unknown third-party module reading the old field would see a `KeyError`.
