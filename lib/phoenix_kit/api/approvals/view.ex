defmodule PhoenixKit.API.Approvals.View do
  @moduledoc """
  What the approvals page shows of an approval's preview and result, read from the shape
  every module's tools already share, so that no module needs a page of its own.

  ## The common preview shape

      %{
        "rows" => [
          %{
            "ref" => "SKU-1", "id" => "...", "name" => "Oak shelf", "action" => "update",
            "changes" => %{"price" => %{"from" => "10.00", "to" => "12.50"}},
            "warnings" => ["..."]
          }
        ],
        "totals" => %{"rows" => 1, "update" => 1},
        "warnings" => ["..."]
      }

  The catalogue tools write the counts as `"summary"` (and may add `"requires_confirmation"`);
  that is read like `"totals"` when there are no `"totals"`.

  `preview/1` reads it into a table (`Item | Field | Was | Becomes | Delta`), a list of
  totals and the warnings. Whatever does not fit (a key the table has no column for, a row
  without a name, `changes` that are not from/to pairs, totals that are not plain values)
  is not dropped: `:technical` then holds the whole preview, with the rows cut to the ones
  listed, for the page's collapsed "Technical details" block. `:technical` is `nil` only
  when everything was understood.

  The functions return data; the words around it belong to the page.
  """

  @max_rows 25
  @max_text 160
  @max_reasons 5
  @label_keys ~w(name ref id)
  @row_keys ~w(name ref id action changes warnings error)
  @top_keys ~w(rows totals summary warnings requires_confirmation)
  @error_text_keys ~w(message detail)
  @error_keys ~w(code message detail context)
  @reason_keys ~w(path message)

  @type change :: %{field: String.t(), from: term(), to: term(), pct: String.t() | nil}
  @type row :: %{
          label: String.t(),
          sub: String.t() | nil,
          action: String.t() | nil,
          changes: [change()],
          warnings: [String.t()],
          error: String.t() | nil,
          error_code: String.t() | nil,
          error_reasons: [String.t()]
        }
  @type t :: %{
          count: non_neg_integer() | nil,
          rows: [row()],
          hidden: non_neg_integer(),
          summary: [{String.t(), term()}],
          warnings: [String.t()],
          technical: map() | nil
        }

  @doc "The number of rows the page lists at most."
  @spec max_rows() :: pos_integer()
  def max_rows, do: @max_rows

  @doc "Reads `preview` for the page."
  @spec preview(term()) :: t()
  def preview(preview) when is_map(preview) do
    all_rows = if is_list(preview["rows"]), do: preview["rows"], else: []
    shown = Enum.take(all_rows, @max_rows)
    count = count(preview, all_rows)
    parsed = Enum.map(shown, &row/1)
    {summary, totals_ok?} = totals(preview)
    {warnings, warnings_ok?} = warnings(preview["warnings"])

    understood? =
      totals_ok? and warnings_ok? and rows_ok?(preview, parsed) and
        Enum.all?(Map.keys(preview), &(&1 in @top_keys))

    %{
      count: count,
      rows: for({:ok, row, _clean?} <- parsed, do: row),
      hidden: max(max(count || 0, length(all_rows)) - length(shown), 0),
      summary: summary,
      warnings: warnings,
      technical: if(understood?, do: nil, else: technical(preview, shown))
    }
  end

  def preview(_not_a_map), do: preview(%{})

  # `rows` absent is fine; present, it must be a list in which every row was read cleanly.
  defp rows_ok?(%{"rows" => rows}, parsed) when is_list(rows),
    do: Enum.all?(parsed, &match?({:ok, _row, true}, &1))

  defp rows_ok?(%{"rows" => _not_a_list}, _parsed), do: false
  defp rows_ok?(_preview, _parsed), do: true

  defp technical(preview, shown) do
    case preview["rows"] do
      rows when is_list(rows) -> Map.put(preview, "rows", shown)
      _other -> preview
    end
  end

  defp count(%{"totals" => %{"rows" => count}}, _rows) when is_integer(count) and count >= 0,
    do: count

  defp count(_preview, [_ | _] = rows), do: length(rows)
  defp count(_preview, _rows), do: nil

  # -- rows --------------------------------------------------------------------

  # `{:ok, row, clean?}`: `clean?` says that every key of the row was shown. `:error` is a
  # row with nothing to call it by, which is left to the technical details alone.
  defp row(%{} = row) do
    case label(row) do
      {label, sub} ->
        {changes, changes_ok?} = changes(row["changes"])
        {warnings, warnings_ok?} = warnings(row["warnings"])
        {error, error_code, error_reasons, error_ok?} = error(row["error"])
        {action, action_ok?} = text(row["action"])

        clean? =
          changes_ok? and warnings_ok? and error_ok? and action_ok? and
            Enum.all?(Map.keys(row), &(&1 in @row_keys))

        {:ok,
         %{
           label: label,
           sub: sub,
           action: action,
           changes: changes,
           warnings: warnings,
           error: error,
           error_code: error_code,
           error_reasons: error_reasons
         }, clean?}

      nil ->
        :error
    end
  end

  defp row(_not_a_map), do: :error

  # The item is called by its name, else its ref, else its id; with a name, the ref is the
  # small line under it.
  defp label(row) do
    case Enum.map(@label_keys, &scalar_text(row[&1])) do
      [name, ref, _id] when is_binary(name) and ref != name -> {name, ref}
      [name, _ref, _id] when is_binary(name) -> {name, nil}
      [nil, ref, _id] when is_binary(ref) -> {ref, nil}
      [nil, nil, id] when is_binary(id) -> {id, nil}
      _none -> nil
    end
  end

  defp changes(nil), do: {[], true}

  defp changes(%{} = changes) do
    parsed =
      for {field, change} <- Enum.sort(changes) do
        case change do
          %{"from" => from, "to" => to} = pair when map_size(pair) == 2 ->
            {:ok, %{field: to_string(field), from: from, to: to, pct: delta_pct(from, to)}}

          _other ->
            :error
        end
      end

    {for({:ok, change} <- parsed, do: change), Enum.all?(parsed, &match?({:ok, _}, &1))}
  end

  defp changes(_other), do: {[], false}

  defp warnings(nil), do: {[], true}

  defp warnings(list) when is_list(list),
    do: {Enum.filter(list, &is_binary/1), Enum.all?(list, &is_binary/1)}

  defp warnings(_other), do: {[], false}

  # A row's error is a sentence, or the tools' `%{"code", "message", "context"}`. Of the
  # context, the field errors (`%{"errors" => [%{"path", "message"}]}`) are read as reasons;
  # any other context is for the technical details of a caller, not for the table.
  defp error(nil), do: {nil, nil, [], true}
  defp error(text) when is_binary(text), do: {blank_to_nil(text), nil, [], true}

  defp error(%{} = map) do
    case error_message(map) do
      nil ->
        {nil, nil, [], false}

      message ->
        code = map["code"]
        {reasons, context_ok?} = reasons(map["context"])

        clean? =
          (is_nil(code) or is_binary(code)) and context_ok? and
            Enum.all?(@error_text_keys, &text_or_blank?(map[&1])) and
            Enum.all?(Map.keys(map), &(&1 in @error_keys))

        {message, if(is_binary(code), do: blank_to_nil(code)), reasons, clean?}
    end
  end

  defp error(_other), do: {nil, nil, [], false}

  # Both the message and the detail, the message first, when the tool wrote both.
  defp error_message(map) do
    @error_text_keys
    |> Enum.map(&binary_value(map, &1))
    |> Enum.reject(&is_nil/1)
    |> Enum.uniq()
    |> case do
      [] -> nil
      texts -> Enum.join(texts, " ")
    end
  end

  defp text_or_blank?(value), do: is_nil(value) or is_binary(value)

  defp reasons(nil), do: {[], true}
  defp reasons(context) when context == %{}, do: {[], true}

  defp reasons(%{"errors" => errors} = context) when is_list(errors) and map_size(context) == 1 do
    parsed = errors |> Enum.take(@max_reasons + 1) |> Enum.map(&reason/1)
    shown = for {:ok, text, _clean?} <- Enum.take(parsed, @max_reasons), do: text

    ok? =
      length(errors) <= @max_reasons and
        Enum.all?(parsed, &match?({:ok, _text, true}, &1))

    {shown, ok?}
  end

  defp reasons(_other), do: {[], false}

  # `{:ok, "path: message", clean?}`; `clean?` is false for text that was cut or for keys
  # of the entry that were not shown.
  defp reason(%{} = entry) do
    path = binary_value(entry, "path")

    case binary_value(entry, "message") do
      nil ->
        :error

      message ->
        {text, cut?} = cap(if(path, do: path <> ": " <> message, else: message))

        clean? =
          not cut? and Enum.all?(Map.keys(entry), &(&1 in @reason_keys)) and
            (is_nil(entry["path"]) or is_binary(entry["path"]))

        {:ok, text, clean?}
    end
  end

  defp reason(_other), do: :error

  defp cap(text) do
    if String.length(text) > @max_text,
      do: {String.slice(text, 0, @max_text - 1) <> "…", true},
      else: {text, false}
  end

  defp binary_value(map, key) do
    case map[key] do
      value when is_binary(value) and value != "" -> value
      _other -> nil
    end
  end

  defp blank_to_nil(""), do: nil
  defp blank_to_nil(value), do: value

  defp text(nil), do: {nil, true}
  defp text(text) when is_binary(text), do: {blank_to_nil(text), true}
  defp text(_other), do: {nil, false}

  # -- totals ------------------------------------------------------------------

  # The plain values of `totals`, or of `summary` (the catalogue tools' name for the same
  # counts) when there are no `totals`, in key order; the `rows` count has its own place. A
  # preview with both is not read twice: the `summary` is left to the technical details.
  defp totals(%{"totals" => totals, "summary" => _summary}) do
    {plain, _ok?} = counts(totals)
    {plain, false}
  end

  defp totals(%{"totals" => totals}), do: counts(totals)
  defp totals(%{"summary" => summary}), do: counts(summary)
  defp totals(_preview), do: {[], true}

  defp counts(nil), do: {[], true}

  defp counts(%{} = totals) do
    entries = totals |> Map.delete("rows") |> Enum.sort()
    plain = for {key, value} <- entries, plain?(value), do: {to_string(key), value}
    {plain, length(plain) == length(entries)}
  end

  defp counts(_other), do: {[], false}

  defp plain?(value) when is_number(value) or is_boolean(value), do: true
  defp plain?(value) when is_binary(value), do: byte_size(value) <= @max_text
  defp plain?(_other), do: false

  defp scalar_text(value) when is_binary(value) and value != "", do: value
  defp scalar_text(value) when is_integer(value), do: Integer.to_string(value)
  defp scalar_text(_other), do: nil

  # -- percentages -------------------------------------------------------------

  @doc """
  The change from `from` to `to` as a signed percentage of `from` with one decimal
  (`"+25.0"`), or `nil` when either is not a plain number or `from` is zero.
  """
  @spec delta_pct(term(), term()) :: String.t() | nil
  def delta_pct(from, to) do
    with %Decimal{} = from <- decimal(from),
         %Decimal{} = to <- decimal(to),
         false <- Decimal.eq?(from, 0) do
      pct =
        to
        |> Decimal.sub(from)
        |> Decimal.mult(100)
        |> Decimal.div(Decimal.abs(from))
        |> Decimal.round(1)
        |> unsigned_zero()

      sign = if Decimal.compare(pct, 0) == :gt, do: "+", else: ""
      sign <> Decimal.to_string(pct, :normal)
    else
      _ -> nil
    end
  end

  # A change that rounds to nothing is "0.0", not "-0.0".
  defp unsigned_zero(pct), do: if(Decimal.eq?(pct, 0), do: Decimal.abs(pct), else: pct)

  defp decimal(value) when is_integer(value), do: Decimal.new(value)
  defp decimal(value) when is_float(value), do: Decimal.from_float(value)

  defp decimal(value) when is_binary(value) do
    case Decimal.parse(String.trim(value)) do
      {%Decimal{coef: coef} = decimal, ""} when is_integer(coef) -> decimal
      _ -> nil
    end
  end

  defp decimal(_other), do: nil

  # -- results -----------------------------------------------------------------

  @doc """
  The numbers a finished approval's result reports, for "Done: updated 2": the result's
  `"summary"` map if it has one, else its own top-level values; plain numbers and
  booleans only, zeros left out.
  """
  @spec facts(term()) :: [{String.t(), number() | boolean()}]
  def facts(%{"summary" => %{} = summary}), do: plain_facts(summary)
  def facts(%{} = result), do: plain_facts(result)
  def facts(_other), do: []

  defp plain_facts(map) do
    for {key, value} <- Enum.sort(map),
        (is_number(value) and value != 0) or value == true,
        do: {to_string(key), value}
  end
end
