# PR #952 — Add host application tools to the shop API guide

**Author:** timujinne · **Reviewer:** Claude · **State at review:** merged

## Review

Docs-only (`dev_docs/guides/2026-10-11-shop-api.md`, one line of `AGENTS.md`). The new "Tools of the
host application" section was checked claim by claim against the code; every one holds:

- **Discovery includes the host.** `ModuleDiscovery` selects code-path ebin dirs whose `.app` lists
  `:phoenix_kit` in `applications` (only `:phoenix_kit` itself is excluded), and the host's own app
  qualifies. The `config :phoenix_kit, modules:` caveat is also right: on a cold build the router
  compiles before the host's beams exist, so only a configured module is seen there.
- **API surface named in the example exists:** `ModuleRegistry.rescan/0`, `Tool.new!/1`
  (`handler` is a plain `{module, function}`, `check_handler/1` does not load the module, so the
  run-time `Module.concat/2` form passes), `Permissions.register_custom_key/2` with
  `auto_grant_admin: false`, `Executor.visible_for/3` (admin audience, `:read` only, no write and no
  `system.*` tools), `ToolLint`, and the "Declaring tools" / "lint" sections it points to.
- **`module_key/0` and `module_name/0` are what the doc says:** the key is the entry in
  `api_disabled_modules` (`api_module_key/1`), the name is the row label (`api_module_name/1`).
- **The always-on stubs are safe.** `enable_system/0` / `disable_system/0` are only called from the
  Modules page toggle, which a module without `permission_metadata/0` has no card for, so
  `{:error, :always_on}` is never reached. The doc says exactly that ("no card on the Modules page").
- **Badge wording** ("every such module that has a card", link to the "Modules" card): the badge is
  rendered per card in `modules.html.heex` and links to `#api-modules-card`, which exists in
  `settings/api.html.heex`.
- **Router recompile note** is correct: a compile-time dependency on the module follows its runtime
  dependencies, so a handler named by a literal would pull the handler's whole call tree into the
  router's recompile set; building the name at run time avoids that.

No findings; nothing changed in code or tests.

- **NITPICK (not fixed)** — the example's `api_tools/0` is deliberately partial ("the other required
  fields ... as in 'Declaring tools' above"), so it is not copy-paste runnable. Fine for a guide
  that points at the full list; a runnable example would drift from `Tool` as fields change.
