defmodule PhoenixKit.Test.SecretKeyPerimeter do
  @moduledoc """
  S015 pt.5: closes the specific hole the external review found in the
  partition invariant (`settings_test.exs`, "every get_defaults/0 key is
  classified exactly once") — that check only walks `Settings.get_defaults/0`,
  so a secret-shaped setting key core never added to `get_defaults/0` at all
  is invisible to it, not merely misclassified. That is exactly how
  `billing_stripe_secret_key` and its siblings went unrestricted: they are
  written through `PhoenixKit.Settings.update_setting/2` by a separate hex
  package, and no `get_defaults/0` entry ever named them, so the invariant
  had nothing to compare them against — verified live in
  `settings_secret_perimeter_test.exs`, "a key outside get_defaults/0
  entirely is invisible to the old partition invariant".

  This module answers a narrower question than "every key core's source
  references must be classified" — that assertion fails today against dozens
  of legitimate module settings never meant to be on either list
  (`entities_max_per_user`, `shop_hide_zero_decimals`, the whole
  `billing_company_*`/`billing_bank_*` invoice-detail group in
  `lib/phoenix_kit/utils/country_data.ex`, ...). Instead: find every key
  literal that LOOKS like it carries live credential material, wherever
  core's own source references or seeds one, so the caller can assert those
  specifically are restricted.

  ## What this can and cannot see

  Scans core's own `lib/` tree and its migration seeds — the two places a
  gap of this exact shape (seeded/referenced, never classified) can actually
  occur inside THIS repository. It structurally CANNOT see a key that only
  exists inside a separate hex package's source (`phoenix_kit_billing`,
  `phoenix_kit_emails`, ...) — those are different git repositories with no
  path into this one, which is exactly why the original billing secrets
  needed a manual cross-repo audit (S015 pt.4) and why this module cannot
  replace one for a FUTURE module package. It closes the perimeter for what
  core owns and can read; what core cannot read stays on manual audit.
  """

  # Ends this way => public by the provider's own design (an id/username/
  # publishable key meant for client-side use), even when the generic
  # "ends in _key" rule below would otherwise catch it — the same reasoning
  # settings.ex's own comment gives for oauth_*_client_id/app_id, extended to
  # their billing-provider counterparts by the S015 pt.4 audit.
  @secret_suffix_exclusions ~w(
    _client_id
    _app_id
    _key_id
    _webhook_id
    _publishable_key
    _username
    _account_name
  )

  @secret_substrings ~w(secret password private_key api_key)

  @doc """
  Whether a setting key's NAME looks like it carries live credential material
  worth guarding — independent of whether it is actually classified
  anywhere. This is the heuristic that already separated the 13 restricted
  keys from their public siblings during the S015 audit, made checkable
  instead of remembered.
  """
  @spec secret_shaped?(String.t()) :: boolean()
  def secret_shaped?(key) when is_binary(key) do
    cond do
      Enum.any?(@secret_suffix_exclusions, &String.ends_with?(key, &1)) -> false
      Enum.any?(@secret_substrings, &String.contains?(key, &1)) -> true
      String.ends_with?(key, "_key") -> true
      true -> false
    end
  end

  @doc """
  Every setting-key literal passed to a single-key `PhoenixKit.Settings`
  read/write function (`get_setting/1,2`, `update_setting/2`,
  `update_setting_with_module/3`) anywhere under `root`'s `.ex` files —
  aliased (`Settings.foo("key")`) or fully qualified
  (`PhoenixKit.Settings.foo("key")`).

  List-taking readers (`get_settings_direct/1`, `get_settings_cached/2`, ...)
  are not covered — every secret the S015 audit found was written through one
  of the four functions above; extending the regex to list literals is
  separate work, not something this task's evidence depends on.
  """
  @spec scan_settings_literals(String.t()) :: [String.t()]
  def scan_settings_literals(root) do
    regex =
      ~r/(?:PhoenixKit\.)?Settings\.(?:get_setting|update_setting|update_setting_with_module)\(\s*"([a-z0-9_]+)"/

    for path <- Path.wildcard(Path.join(root, "**/*.ex")),
        {:ok, content} = File.read(path),
        [_, key] <- Regex.scan(regex, content) do
      key
    end
    |> Enum.uniq()
  end

  @doc """
  Every setting key seeded by a `phoenix_kit_settings` INSERT in a core
  migration (`lib/phoenix_kit/migrations/postgres/*.ex`) — the exact shape
  `billing_stripe_enabled` and its siblings were added by, in v135, without
  ever reaching `get_defaults/0`. Matches the two-line
  `INSERT INTO ... phoenix_kit_settings (...)` / `VALUES ('key', ...)` shape
  every seed in this codebase uses.
  """
  @spec scan_migration_seed_literals(String.t()) :: [String.t()]
  def scan_migration_seed_literals(root) do
    for path <- Path.wildcard(Path.join(root, "**/*.ex")),
        {:ok, content} = File.read(path) do
      lines = String.split(content, "\n")

      lines
      |> Enum.zip(tl(lines) ++ [""])
      |> Enum.filter(fn {line, _next} ->
        String.contains?(line, "phoenix_kit_settings") and String.contains?(line, "INSERT INTO")
      end)
      |> Enum.flat_map(fn {_line, next_line} ->
        case Regex.run(~r/VALUES\s*\(\s*'([a-z0-9_]+)'/, next_line) do
          [_, key] -> [key]
          nil -> []
        end
      end)
    end
    |> List.flatten()
    |> Enum.uniq()
  end
end
