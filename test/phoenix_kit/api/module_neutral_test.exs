defmodule PhoenixKit.API.ModuleNeutralTest do
  # Guards the module-neutrality of the machine API: `lib/phoenix_kit/api/` knows no
  # module, so it must not spell "shop" or "cart". Everything that still has to (the
  # deprecated names) lives in `PhoenixKit.API.Legacy`, which is deleted in 3.0.0.
  use ExUnit.Case, async: true

  @api_dir Path.expand("../../../lib/phoenix_kit/api", __DIR__)
  @legacy Path.join(@api_dir, "legacy.ex")

  test "lib/phoenix_kit/api/ names no module outside Legacy and the allowlist" do
    offenders =
      @api_dir
      |> Path.join("**/*.ex")
      |> Path.wildcard()
      |> Enum.reject(&(&1 == @legacy))
      |> Enum.flat_map(&offending_lines/1)

    assert offenders == [],
           "the machine API must stay module-neutral; move the name to PhoenixKit.API.Legacy " <>
             "or reword it:\n" <> Enum.join(offenders, "\n")
  end

  test "Legacy is deleted when the deprecation window closes (3.0.0)" do
    if Version.match?(Mix.Project.config()[:version], ">= 3.0.0") and File.exists?(@legacy) do
      flunk(
        "version #{Mix.Project.config()[:version]} closes the deprecation window: delete " <>
          "lib/phoenix_kit/api/legacy.ex, its callers' fallbacks and the allowlist of this test"
      )
    end
  end

  defp offending_lines(path) do
    relative = Path.relative_to(path, @api_dir)

    path
    |> File.stream!()
    |> Stream.with_index(1)
    |> Enum.filter(fn {line, _number} ->
      Regex.match?(~r/shop|cart/i, line) and not allowed?(relative, line)
    end)
    |> Enum.map(fn {line, number} ->
      "lib/phoenix_kit/api/#{relative}:#{number}: #{String.trim(line)}"
    end)
  end

  # The only lines outside `legacy.ex` that may match, as {file relative to the API
  # directory, regex of the line}. Keep this list minimal. (A function, not an attribute:
  # a compiled regex cannot be stored in one.)
  defp allowed do
    [
      # The V220 column is `cart_token_hash` and is not renamed (no migration), so the
      # schema maps its neutral field onto it. Permanent.
      {"confirm/confirmation.ex", ~r/source: :cart_token_hash/},
      # The deprecated `check_cart_rows/1` (and its @spec), still called by name by a
      # module written before `check_new_rows/1`. Removed in 3.0.0.
      {"rate_limit.ex", ~r/^\s*(@spec|def) check_cart_rows\b/}
    ]
  end

  defp allowed?(relative, line) do
    Enum.any?(allowed(), fn {file, regex} -> file == relative and Regex.match?(regex, line) end)
  end
end
