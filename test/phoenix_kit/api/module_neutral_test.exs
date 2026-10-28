defmodule PhoenixKit.API.ModuleNeutralTest do
  # Guards the module-neutrality of the machine API: `lib/phoenix_kit/api/` knows no
  # module, so it must not spell "shop" or "cart". (The deprecated shop names lived in
  # `PhoenixKit.API.Legacy`, deleted in 3.0.0.)
  use ExUnit.Case, async: true

  @api_dir Path.expand("../../../lib/phoenix_kit/api", __DIR__)

  test "lib/phoenix_kit/api/ names no module outside the allowlist" do
    offenders =
      @api_dir
      |> Path.join("**/*.ex")
      |> Path.wildcard()
      |> Enum.flat_map(&offending_lines/1)

    assert offenders == [],
           "the machine API must stay module-neutral; reword it:\n" <> Enum.join(offenders, "\n")
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

  # The only lines that may match, as {file relative to the API
  # directory, regex of the line}. Keep this list minimal. (A function, not an attribute:
  # a compiled regex cannot be stored in one.)
  defp allowed do
    [
      # The V220 column is `cart_token_hash` and is not renamed (no migration), so the
      # schema maps its neutral field onto it. Permanent.
      {"confirm/confirmation.ex", ~r/source: :cart_token_hash/}
    ]
  end

  defp allowed?(relative, line) do
    Enum.any?(allowed(), fn {file, regex} -> file == relative and Regex.match?(regex, line) end)
  end
end
