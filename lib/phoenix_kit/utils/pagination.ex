defmodule PhoenixKit.Utils.Pagination do
  @moduledoc """
  Page-number arithmetic for paginated lists.

  Before this module every paginated LiveView hand-rolled the same two
  computations — a "parse the ?page param" private and a
  `ceil(total / per_page)` — and they disagreed: some floored the result
  at one page, most did not, which is how empty lists ended up with
  `total_pages: 0` and `1..total_pages` became the DECREASING range
  `[1, 0]` in page-range builders. Host apps copied the same privates into
  every admin view.

  Two deliberate choices, made once here so call sites stop deciding
  differently:

    * `parse_page/1` is loose — `"2abc"` parses as 2, junk and non-positives
      fall back to 1. That matches what every existing call site (and their
      tests) already did; a ?page param is navigation state, not input worth
      erroring on.

    * `total_pages/2` floors at 1 — an empty list is one empty page, not
      zero pages. The pagination components already render controls only
      for `total_pages > 1`, so the floor changes no UI. A site that wants
      a sentinel "nothing loaded" state (e.g. an invalid scope) assigns its
      literal `0` itself, deliberately.
  """

  @doc """
  The page number carried by a `?page` param: a positive integer, or 1.

  Accepts what params actually arrive as — binaries, integers (LiveView
  event payloads), `nil` when absent — and never raises.

      iex> PhoenixKit.Utils.Pagination.parse_page("3")
      3

      iex> PhoenixKit.Utils.Pagination.parse_page("0")
      1

      iex> PhoenixKit.Utils.Pagination.parse_page(nil)
      1
  """
  @spec parse_page(term()) :: pos_integer()
  def parse_page(page) when is_integer(page) and page > 0, do: page

  def parse_page(page) when is_binary(page) do
    case Integer.parse(page) do
      {n, _} when n > 0 -> n
      _ -> 1
    end
  end

  def parse_page(_), do: 1

  @doc """
  How many pages `total_count` items make at `per_page` per page — at
  least 1.

  Integer arithmetic throughout; a negative `total_count` counts as 0.
  Raises on `per_page < 1`, which is a caller bug, not data.

      iex> PhoenixKit.Utils.Pagination.total_pages(51, 25)
      3

      iex> PhoenixKit.Utils.Pagination.total_pages(0, 25)
      1
  """
  @spec total_pages(integer(), pos_integer()) :: pos_integer()
  def total_pages(total_count, per_page)
      when is_integer(total_count) and is_integer(per_page) and per_page >= 1 do
    total_count
    |> max(0)
    |> Kernel.+(per_page - 1)
    |> div(per_page)
    |> max(1)
  end

  def total_pages(total_count, per_page)
      when is_integer(total_count) and is_integer(per_page) do
    raise ArgumentError, "per_page must be >= 1, got: #{inspect(per_page)}"
  end
end
