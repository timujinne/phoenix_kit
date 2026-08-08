defmodule PhoenixKit.Utils.HtmlSanitizerTest do
  use ExUnit.Case, async: true

  alias PhoenixKit.Utils.HtmlSanitizer

  describe "sanitize/1 strips dangerous content" do
    test "literal dangerous schemes are removed" do
      for scheme <- ~w(javascript vbscript data file blob) do
        html = ~s(<a href="#{scheme}:alert1">x</a>)
        refute HtmlSanitizer.sanitize(html) =~ "#{scheme}:"
      end
    end

    test "entity-encoded scheme bypass is closed (the reported XSS)" do
      # A browser decodes the attribute before dispatching, so a blacklist over
      # the raw text misses these — normalize (decode + strip) then allowlist.
      vectors = [
        ~s(<a href="jav&#x61;script:alert1">x</a>),
        ~s(<a href="jav&#97;script:alert1">x</a>),
        ~s(<a href="java&Tab;script:alert1">x</a>),
        ~s(<a href="java&NewLine;script:alert1">x</a>),
        ~s(<a href="javascript&colon;alert1">x</a>)
      ]

      for html <- vectors do
        clean = HtmlSanitizer.sanitize(html)
        refute clean =~ ~r/href/i, "leaked a dangerous href: #{clean}"
      end
    end

    test "whitespace/control-char obfuscation in the scheme is closed" do
      clean = HtmlSanitizer.sanitize("<a href=\"java\tscript:alert1\">x</a>")
      refute clean =~ ~r/href/i
    end

    test "unquoted dangerous href is removed" do
      refute HtmlSanitizer.sanitize("<a href=javascript:alert1>x</a>") =~ "javascript"
    end
  end

  describe "sanitize/1 keeps safe URLs" do
    test "allowed schemes and relative URLs survive intact" do
      for url <- [
            "https://example.com/page?q=1",
            "http://example.com",
            "mailto:me@example.com",
            "tel:+123456789",
            "/relative/path",
            "#fragment",
            "?just=query"
          ] do
        html = ~s(<a href="#{url}">link</a>)
        assert HtmlSanitizer.sanitize(html) =~ ~s(href="#{url}")
      end
    end

    test "safe img src survives; a data: src is dropped" do
      assert HtmlSanitizer.sanitize(~s(<img src="/img/a.png">)) =~ ~s(src="/img/a.png")
      refute HtmlSanitizer.sanitize(~s(<img src="data:image/png;base64,AAAA">)) =~ "data:"
    end

    test "a href value that merely contains 'javascript' as text is not itself a scheme" do
      # e.g. a link TO a page about javascript — path, not scheme.
      html = ~s(<a href="/articles/javascript-guide">JS guide</a>)
      assert HtmlSanitizer.sanitize(html) =~ ~s(href="/articles/javascript-guide")
    end
  end

  describe "sanitize/1 non-URL vectors (unchanged behaviour)" do
    test "script/style/event handlers still stripped" do
      assert HtmlSanitizer.sanitize("<p>Hi</p><script>x</script>") == "<p>Hi</p>"
      assert HtmlSanitizer.sanitize("<p onclick=\"x()\">Hi</p>") == "<p>Hi</p>"
    end
  end

  describe "sanitize/1 slash-separated attributes" do
    # HTML allows `/` between attributes and browsers parse
    # `<img/src=x/onerror=alert(1)>` exactly like the spaced form. The
    # patterns required WHITESPACE, so these passed through completely
    # untouched — verified against this module before the fix. Product
    # descriptions render through here on the unauthenticated storefront,
    # so this was reachable by anyone who could edit a product or supply a
    # CSV import feed.
    test "event handlers separated by a slash never survive as attributes" do
      # The property is "no event-handler ATTRIBUTE survives", not "the
      # string 'onerror' is absent". A parser can legitimately fold
      # `<img/src=x/onerror=alert(1)>` into `<img src="x/onerror=alert(1)">`,
      # where the text sits inside a quoted URL and is inert — the browser
      # tries to fetch a relative path and fails. Asserting on the substring
      # would fail that correct output, so assert on attribute position.
      for payload <- [
            "<svg/onload=alert(1)>",
            "<img/src=x/onerror=alert(1)>",
            "<div/onclick=alert(1)>hi</div>",
            "<body/onload=alert(1)>"
          ] do
        out = HtmlSanitizer.sanitize(payload)

        refute out =~ ~r/<[^>]*\son\w+\s*=/i,
               "an event-handler attribute survived: #{payload} -> #{out}"
      end
    end

    test "the space-separated forms remain stripped" do
      # Output is re-serialized from a parse tree, so attribute values come
      # back quoted — the handler is gone, which is what matters.
      out = HtmlSanitizer.sanitize("<img src=x onerror=alert(1)>")
      assert out == ~s(<img src="x">)
      refute out =~ ~r/\son\w+\s*=/i
    end

    test "svg and math are dropped as foreign-content vectors" do
      # Both introduce their own scripting surface (`<svg><script>`,
      # `xlink:href="javascript:"`) that HTML-shaped patterns do not
      # reason about correctly.
      # `~s|...|` rather than `~s(...)`: the paren in `alert(1)` would close
      # a paren-delimited sigil early.
      refute HtmlSanitizer.sanitize(~s|<svg><a xlink:href="javascript:alert(1)">x</a></svg>|) =~
               "<svg"

      refute HtmlSanitizer.sanitize("<math><mtext>x</mtext></math>") =~ "<math"
    end

    test "ordinary markup survives" do
      # Sanitizing must not eat legitimate content. Output is normalised
      # (void elements lose the self-closing slash, attributes are quoted)
      # because it is re-serialized from a parse tree.
      assert HtmlSanitizer.sanitize("<p>Hello <strong>world</strong></p>") ==
               "<p>Hello <strong>world</strong></p>"

      assert HtmlSanitizer.sanitize(~s(<img src="/a.png" alt="a">)) =~ ~s(src="/a.png")
      assert HtmlSanitizer.sanitize("<br/>") == "<br>"
      assert HtmlSanitizer.sanitize("<ul><li>a</li></ul>") == "<ul><li>a</li></ul>"
      assert HtmlSanitizer.sanitize("<h2>H</h2><blockquote>q</blockquote>") =~ "<blockquote>"
    end

    test "relative, anchor, mailto and tel URLs survive" do
      # Regression guard: a scheme allowlist must not break ordinary links.
      assert HtmlSanitizer.sanitize(~s(<a href="/docs">d</a>)) =~ ~s(href="/docs")
      assert HtmlSanitizer.sanitize(~s(<a href="#top">t</a>)) =~ ~s(href="#top")
      assert HtmlSanitizer.sanitize(~s(<a href="mailto:a@b.com">m</a>)) =~ "mailto:a@b.com"
      assert HtmlSanitizer.sanitize(~s(<a href="tel:+123">p</a>)) =~ "tel:+123"
    end
  end

  describe "sanitize/1 presentational attributes" do
    # The rewrite swapped a blacklist (which passed every attribute it did
    # not recognise) for ammonia's allowlist, which keeps `class` on only
    # code/div/pre/span and drops `target` outright. Both were documented
    # as allowed and both are emitted by ordinary rich-text editors, so
    # they are added back explicitly in `@sanitize_options`.

    test "class survives on any tag, not just ammonia's four" do
      assert HtmlSanitizer.sanitize(~s|<p class="text-center">Hi</p>|) ==
               ~s|<p class="text-center">Hi</p>|

      assert HtmlSanitizer.sanitize(~s|<img src="/a.png" class="rounded">|) =~ ~s|class="rounded"|
      assert HtmlSanitizer.sanitize(~s|<code class="language-elixir">:ok</code>|) =~ "language-"
    end

    test "class does not smuggle a handler back in" do
      assert HtmlSanitizer.sanitize(~s|<p class="a" onclick="x()">Hi</p>|) ==
               ~s|<p class="a">Hi</p>|
    end

    test "target survives on links, and rel is always ours" do
      out = HtmlSanitizer.sanitize(~s|<a href="https://x.com" target="_blank">t</a>|)
      assert out =~ ~s|target="_blank"|
      # The forced link_rel is what makes `target` safe to allow at all.
      assert out =~ ~s|rel="noopener noreferrer"|

      # An author-supplied rel is overwritten, not merged — so a stored
      # `rel=""` can't strip the tabnabbing guard back off.
      assert HtmlSanitizer.sanitize(~s|<a href="https://x.com" target="_blank" rel="">t</a>|) =~
               ~s|rel="noopener noreferrer"|
    end

    test "target does not rescue a dangerous href" do
      out = HtmlSanitizer.sanitize(~s|<a href="javascript:alert(1)" target="_blank">x</a>|)
      refute out =~ "href="
      refute out =~ "javascript"
    end

    test "id is dropped from every tag (deliberate — see @sanitize_options)" do
      assert HtmlSanitizer.sanitize(~s|<p id="x">Hi</p>|) == "<p>Hi</p>"
      assert HtmlSanitizer.sanitize(~s|<h2 id="section">H</h2>|) == "<h2>H</h2>"
      # The link half of an in-page anchor still survives; only the target
      # attribute is gone, so anchors resolve against app-rendered ids.
      assert HtmlSanitizer.sanitize(~s|<a href="#section">go</a>|) =~ ~s|href="#section"|
    end
  end

  describe "sanitize/1 slash-separated attributes (continued)" do
    test "entity-encoded dangerous schemes are caught" do
      # The old blacklist could be walked past with `jav&#x61;script:`;
      # a parser decodes before validating the scheme.
      # `~s|...|`: the paren in `alert(1)` would close a `~s(...)` sigil early.
      out = HtmlSanitizer.sanitize(~s|<a href="jav&#x61;script:alert(1)">x</a>|)
      refute out =~ "javascript"
      refute out =~ "href="
    end
  end
end
