defmodule PhoenixKit.API.LogSafe do
  @moduledoc """
  What the API may write to the server log about a term that came from a
  request or from code that handled one.

  The log learns the kind and the size of a term, never its values: they may
  hold bearer tokens, client tokens or personal data. The exception message
  is kept only for the exceptions in `@fixed_message_exceptions`, and then as
  the text of the exception class, never the text the instance carries.
  """

  # How much of an exception's message the log keeps.
  @log_message_codepoints 500

  # The exceptions whose message is fixed text that cannot hold a value of the
  # failing call ("bad argument in arithmetic expression", "no function clause
  # matching in M.f/1"). Every other message may print the data it failed on:
  # `KeyError` the map, `MatchError` the right-hand side, `Ecto.InvalidChangesetError`
  # the changes, and the stdlib raises `ArgumentError`, `RuntimeError` and
  # `UndefinedFunctionError` with the failing input (`Date.from_iso8601!/1`,
  # `Module.concat/1`), which may hold tokens or personal data.
  @fixed_message_exceptions [ArithmeticError, FunctionClauseError]

  # The only atoms the log prints by name. Any other atom may have been made
  # from a request value (`String.to_atom/1`), so it is logged as "an atom".
  @plain_atoms [nil, true, false, :ok, :error]

  @doc """
  The shape of a term, without its values: "a map", "a binary of 12 bytes",
  "a tuple of size 2 tagged :ok", "a Plug.Conn struct".
  """
  @spec shape(term()) :: String.t()
  def shape(value) when is_atom(value), do: atom_shape(value)
  def shape(value) when is_binary(value), do: "a binary of #{byte_size(value)} bytes"
  def shape(%module{}), do: "a #{inspect(module)} struct"
  def shape(value) when is_map(value), do: "a map"
  def shape(value) when is_list(value), do: "a list"

  def shape(value) when is_tuple(value) do
    case Tuple.to_list(value) do
      [tag | _rest] when tag in @plain_atoms ->
        "a tuple of size #{tuple_size(value)} tagged #{inspect(tag)}"

      _other ->
        "a tuple of size #{tuple_size(value)}"
    end
  end

  def shape(_value), do: "a value of another type"

  defp atom_shape(atom) when atom in @plain_atoms, do: inspect(atom)
  defp atom_shape(_atom), do: "an atom"

  @doc """
  An exception as the log may see it: `** (Module)`, followed by its message
  (cut at 500 code points) only for the exceptions with a fixed message.
  """
  @spec exception_label(Exception.t()) :: String.t()
  def exception_label(%module{} = error),
    do: "** (#{inspect(module)})#{message_part(module, error)}"

  defp message_part(module, error) when module in @fixed_message_exceptions,
    do: " " <> take_codepoints(class_message(error), @log_message_codepoints)

  defp message_part(_module, _error), do: ""

  # The text of the class: an `ArithmeticError` can carry any message when it
  # is built by hand (`raise ArithmeticError, message: ...`), and a blamed
  # `FunctionClauseError` prints the arguments of the call; neither reaches
  # the log.
  defp class_message(%ArithmeticError{}), do: Exception.message(%ArithmeticError{})

  defp class_message(%FunctionClauseError{} = error),
    do: Exception.message(%{error | args: nil, clauses: nil})

  @doc """
  The first `limit` code points of `string` (not graphemes: a single grapheme
  can be arbitrarily long).
  """
  @spec take_codepoints(String.t(), non_neg_integer()) :: String.t()
  def take_codepoints(string, limit), do: take_codepoints(string, limit, [])

  defp take_codepoints(_rest, 0, taken), do: reversed_to_binary(taken)

  defp take_codepoints(rest, left, taken) do
    case String.next_codepoint(rest) do
      {codepoint, tail} -> take_codepoints(tail, left - 1, [codepoint | taken])
      nil -> reversed_to_binary(taken)
    end
  end

  defp reversed_to_binary(taken), do: taken |> Enum.reverse() |> IO.iodata_to_binary()
end
