defmodule PhoenixKit.Activity.HumanizeMetadataValueTest do
  @moduledoc """
  The admin activity feed and the single-entry page render arbitrary
  per-module metadata. A structural change event stores a nested
  `%{"from" => _, "to" => _}` map; interpolating that as a scalar used to raise
  `Protocol.UndefinedError` (String.Chars not implemented for Map) and take the
  whole `/admin/activity` page down. These pin the tolerant rendering.
  """
  use ExUnit.Case, async: true

  alias PhoenixKit.Activity

  test "a from/to diff renders as an arrow, never raising on the map" do
    assert Activity.humanize_metadata_value(%{"from" => "1", "to" => "2"}) == "1 → 2"
  end

  test "a nested field-change map (the exact crash payload) is readable" do
    value = %{"qty" => %{"from" => "1", "to" => "2"}}
    assert Activity.humanize_metadata_value(value) == "qty: 1 → 2"
  end

  test "legacy inspect-serialised Decimals are unwrapped to the bare number" do
    assert Activity.humanize_metadata_value("Decimal.new(\"1\")") == "1"

    assert Activity.humanize_metadata_value(%{
             "from" => "Decimal.new(\"1\")",
             "to" => "Decimal.new(\"2\")"
           }) ==
             "1 → 2"
  end

  test "plain scalars pass through" do
    assert Activity.humanize_metadata_value("hello") == "hello"
    assert Activity.humanize_metadata_value(42) == "42"
    assert Activity.humanize_metadata_value(nil) == ""
  end

  test "a generic (non from/to) map renders key: value pairs without raising" do
    assert Activity.humanize_metadata_value(%{"a" => "1"}) == "a: 1"
  end

  test "a list renders comma-joined" do
    assert Activity.humanize_metadata_value(["a", "b"]) == "a, b"
  end
end
