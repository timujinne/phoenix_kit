# PR #971 — Fix EnsureOAuthScheme forcing https on 443 when oauth_base_url is unset

**Author:** timujinne · **Merged:** 2026-10-23 (00c8004b5) · **Reviewer:** Claude

## Summary

`PhoenixKit.Config.get_string(:oauth_base_url)` answers `""` when unset, which is truthy, so step 2 always won and step 3 (endpoint `url:`) was dead
code: every request got `https` on 443, breaking plain-http local dev. The plug now treats `""` as unset and rewrites step 3 to fill the gaps: scheme =
endpoint `:scheme`, else https when port is 443, else the request's scheme when both endpoint host and request host are loopback, else https; host =
endpoint host or request host; port = endpoint port, else 443 for https, else the request's port.

Verdict: correct and well tested (14 cases incl. loopback spellings, look-alike hosts, a leftover `localhost` in a prod endpoint). Checked against
`deps/ueberauth/.../helpers.ex` `full_url/2`: Ueberauth takes the host from `x-forwarded-host`/`Host` (so the plug's `conn.host` is only a fallback, as the
moduledoc says), the scheme from `x-forwarded-proto` first, and `conn.port` only when the `Host` header carries no port — so the scheme/port outcomes the
docs list are the ones that reach the callback URL. Behaviour for installs with no endpoint `url:` on a real host is unchanged (https/443).

## Findings

- **IMPROVEMENT - MEDIUM (fixed):** the endpoint `url: [port: ...]` was used as-is, but Phoenix accepts an integer, a numeric string or
  `{:system, var}` (`Phoenix.Endpoint.Supervisor.port_to_integer/1`). With `port: "443"` the new `port == 443` test missed, so `localhost` + `"443"`
  stayed `http`, and `conn.port` was set to a binary. Added `url_port/1` (integer / numeric string / `{:system, _}` / else unset) and tests for each,
  plus the previously untested "conn without an endpoint" path.
- **NITPICK (not changed):** `loopback?/1` knows `localhost`, `*.localhost`, `127.0.0.1`, `::1` only; `127.0.0.2` (rest of 127/8) counts as a real host and
  gets https. Dev servers essentially never use it.
- **NITPICK (not changed):** `parse_scheme/1` maps an atom scheme (`:http`) to `:https`. Phoenix documents `scheme` as a string; pre-existing.
- **Process note:** no CHANGELOG entry was added with the PR (behaviour change: dev http works again; `url: [host:, port: 4000]` without a scheme is now
  https on 4000, previously 443). It belongs in the release entry; deliberately not added here.
