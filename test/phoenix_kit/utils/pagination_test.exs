defmodule PhoenixKit.Utils.PaginationTest do
  use ExUnit.Case, async: true

  alias PhoenixKit.Utils.Pagination

  doctest PhoenixKit.Utils.Pagination

  describe "parse_page/1" do
    test "accepts what params arrive as" do
      assert Pagination.parse_page("7") == 7
      # LiveView event payloads can carry integers already
      assert Pagination.parse_page(7) == 7
      assert Pagination.parse_page(nil) == 1
    end

    test "loose by choice: junk, negatives and trailing garbage fall back" do
      # "2abc" → 2 matches every call site this replaced; a ?page param is
      # navigation state, not input worth erroring on.
      assert Pagination.parse_page("2abc") == 2
      assert Pagination.parse_page("abc") == 1
      assert Pagination.parse_page("-3") == 1
      assert Pagination.parse_page("0") == 1
      assert Pagination.parse_page(-3) == 1
      assert Pagination.parse_page(%{"page" => "2"}) == 1
    end
  end

  describe "total_pages/2" do
    test "integer ceiling division" do
      assert Pagination.total_pages(50, 25) == 2
      assert Pagination.total_pages(51, 25) == 3
      assert Pagination.total_pages(1, 25) == 1
    end

    test "floors at one page — an empty list is one empty page, not zero" do
      # The unfloored version fed 1..total_pages builders the DECREASING
      # range [1, 0] on empty lists.
      assert Pagination.total_pages(0, 25) == 1
      assert Pagination.total_pages(-5, 25) == 1
    end

    test "per_page below 1 is a caller bug and raises" do
      assert_raise ArgumentError, ~r/per_page must be >= 1/, fn ->
        Pagination.total_pages(10, 0)
      end
    end
  end
end
