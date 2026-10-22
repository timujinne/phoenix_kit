# PR #955 — Let X-Forwarded-Proto (API context, OAuth scheme) and the proxy rebind follow :trusted_proxies

**Author:** timujinne · **Merged:** 2026-10-21 (5b526e15a) · **Reviewer:** Claude

## Summary

Adds `IpAddress.trusted_proxy?/1` (the peer rule of `client_address/1`: unset = loopback/private, a list = only inside it, invalid =
nobody) and uses it for `X-Forwarded-Proto` in `API.RequestContext`, for the same header in `EnsureOAuthScheme` (which used to
believe it from any peer), and for the peer test in `SessionFingerprint.proxy_rebind_address/3`.

Verdict: sound and fail-closed; the string and tuple clauses share `proxy?/1`, an unparseable address is not trusted. The
`EnsureOAuthScheme` change closes a real hole (a direct client could send `X-Forwarded-Proto: https` and move the generated
callback scheme).

## Findings

- **IMPROVEMENT - MEDIUM (not changed, needs a decision):** the PR documents it as a "known gap" and it is real:
  `PhoenixKit.Config.get_string(:oauth_base_url)` answers `""` when the key is unset, `""` is truthy, so step 2 of
  `EnsureOAuthScheme` always applies. With no `oauth_base_url` every OAuth request is forced to `https` / port 443 (a dev
  server on `http://localhost:4000` gets `https://localhost:443`), and step 3 (the endpoint URL config) is unreachable. The
  trusted-proxy check this PR adds is still evaluated first, but when it refuses the header step 2 forces https anyway, so for a
  host without `oauth_base_url` the change has no visible effect either way. The fix is one line
  (`base_url = PhoenixKit.Config.get_string(:oauth_base_url); base_url != ""`), but it changes the callback URL of every host
  that relies on the forced https today (a production endpoint with `url: [port: 80]` behind a proxy that is not trusted would
  flip to http). Left for the maintainer: choose the fix, and add the release-note line with it.
- Tests: `ip_address_trusted_proxies_test.exs` covers the new function and the three readers — green.
