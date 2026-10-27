defmodule PhoenixKit.Modules.Storage.ShortCode do
  @moduledoc """
  The short code of a file (`phoenix_kit_files.short_code`, V225): 8 random
  characters of base58, `k3Fq9xA2`, that name the file in a URL instead of its UUID.

  Base58 leaves out `0`, `O`, `I` and `l`, so a code survives being read aloud or
  copied from a screenshot. It is case-sensitive. 58^8 is about 1.3 × 10^14, so two
  files drawing the same code is a question of luck only when a site holds
  billions of them; the unique index is the guarantee, not the draw.

  A code is random and says nothing about the file. It is not a secret: whether a
  file may be read is decided by the library it is in, never by knowing its code.
  """

  @alphabet ~c"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
  @length 8
  @pattern ~r/\A[1-9A-HJ-NP-Za-km-z]{8}\z/

  @doc "A new random code."
  @spec generate() :: String.t()
  def generate, do: draw(@length, [])

  @doc "Whether `value` has the shape of a code (it may still belong to no file)."
  @spec valid?(term()) :: boolean()
  def valid?(value) when is_binary(value), do: Regex.match?(@pattern, value)
  def valid?(_value), do: false

  # A byte below 232 (4 × 58) maps to a character without bias; the others are redrawn.
  defp draw(0, acc), do: List.to_string(acc)

  defp draw(left, acc) do
    chars =
      for <<byte <- :crypto.strong_rand_bytes(left * 2)>>, byte < 232 do
        Enum.at(@alphabet, rem(byte, 58))
      end
      |> Enum.take(left)

    draw(left - length(chars), chars ++ acc)
  end
end
