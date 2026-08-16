defmodule PhoenixKit.Modules.Crawlers.LlmsTxtTest do
  use ExUnit.Case, async: true

  alias PhoenixKit.Modules.Crawlers.LlmsTxt

  describe "build_for/2" do
    test "title becomes the H1" do
      assert LlmsTxt.build_for("Topp", "") == "# Topp\n"
    end

    test "extra markdown is appended verbatim after a blank line" do
      out = LlmsTxt.build_for("Topp", "> Estonian rank tracking.\n\n- [Docs](/docs)")

      assert out == "# Topp\n\n> Estonian rank tracking.\n\n- [Docs](/docs)\n"
    end

    test "nil or blank title falls back rather than rendering an empty heading" do
      assert LlmsTxt.build_for(nil, "") == "# This site\n"
      assert LlmsTxt.build_for("   ", "") == "# This site\n"
    end

    test "extra is trimmed so stray whitespace does not stack blank lines" do
      assert LlmsTxt.build_for("T", "  hello  \n") == "# T\n\nhello\n"
    end
  end
end
