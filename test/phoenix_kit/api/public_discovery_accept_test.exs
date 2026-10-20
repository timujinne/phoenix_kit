defmodule PhoenixKit.API.PublicDiscovery.AcceptTest do
  @moduledoc """
  Which representation of the guide a request gets: `?format=md`, the quality
  values of `Accept`, the MCP client that asks for an event stream only.
  """
  use ExUnit.Case, async: true

  alias PhoenixKit.API.PublicDiscovery.Accept

  defp pick(accept, format \\ nil), do: Accept.representation(format, List.wrap(accept))

  describe "HTML is the default" do
    test "no Accept, a wildcard, an explicit HTML, unknown and malformed headers" do
      for accept <- [
            [],
            "*/*",
            "text/*",
            "text/html",
            "text/html, application/xhtml+xml, */*;q=0.8",
            "application/json",
            "application/xml",
            "",
            "garbage",
            ";;;",
            "text/markdown;q=0, text/html;q=0"
          ] do
        assert pick(accept) == :html, inspect(accept)
      end
    end
  end

  describe "Markdown" do
    test "format=md wins over any Accept, including an event stream" do
      for accept <- [[], "text/html", "text/event-stream", "*/*"] do
        assert pick(accept, "md") == :markdown, inspect(accept)
      end
    end

    test "any other format value is ignored" do
      for format <- ["html", "markdown", "", nil, ["md"], %{"x" => "md"}] do
        assert pick("text/html", format) == :html, inspect(format)
      end
    end

    test "when text/markdown outranks text/html" do
      for accept <- [
            "text/markdown",
            "text/markdown, text/html;q=0.5",
            "text/markdown;q=0.9, text/html;q=0.8",
            "text/markdown, */*;q=0.1",
            "text/markdown, text/*;q=0.5",
            "TEXT/Markdown",
            "text/markdown; charset=utf-8",
            ["text/html;q=0.1", "text/markdown"]
          ] do
        assert pick(accept) == :markdown, inspect(accept)
      end
    end

    test "when it does not: a tie or a lower quality is HTML" do
      for accept <- [
            "text/markdown, text/html",
            "text/markdown;q=0.5, text/html",
            "text/markdown, */*",
            "text/html, text/markdown",
            "text/markdown;q=0.5, text/html;q=0.5"
          ] do
        assert pick(accept) == :html, inspect(accept)
      end
    end

    test "q is clamped, and a malformed q counts as 1" do
      assert pick("text/markdown;q=5, text/html;q=0.9") == :markdown
      assert pick("text/markdown;q=-1, text/html;q=0.1") == :html
      assert pick("text/markdown;q=abc, text/html;q=0.9") == :markdown
    end

    test "the most specific range decides, not the first" do
      assert pick("*/*;q=1, text/markdown;q=0.1") == :html
      assert pick("text/*;q=1, text/html;q=0.1, text/markdown") == :markdown
    end
  end

  describe "an MCP client that was given the guide URL as its server URL" do
    test "an event stream and neither HTML nor Markdown is not acceptable" do
      for accept <- [
            "text/event-stream",
            "application/json, text/event-stream",
            "text/event-stream, application/json",
            "text/event-stream;q=0.5",
            ["application/json", "text/event-stream"]
          ] do
        assert pick(accept) == :not_acceptable, inspect(accept)
      end
    end

    test "any way to accept HTML or Markdown keeps it a page" do
      assert pick("text/event-stream, */*") == :html
      assert pick("text/event-stream, text/*") == :html
      assert pick("text/event-stream, text/html") == :html
      assert pick("text/event-stream, text/markdown") == :markdown
    end

    test "an event stream with q=0 is not asking for one" do
      assert pick("text/event-stream;q=0") == :html
    end

    test "HTML and Markdown that are refused (q=0) do not count as accepted" do
      assert pick("text/event-stream, text/html;q=0") == :not_acceptable
      assert pick("text/event-stream, text/html;q=0, text/markdown;q=0") == :not_acceptable
    end
  end
end
