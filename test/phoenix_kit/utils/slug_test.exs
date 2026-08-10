defmodule PhoenixKit.Utils.SlugTest do
  use ExUnit.Case, async: true

  alias PhoenixKit.Utils.Slug

  describe "slugify/2" do
    test "lowercases, separates words, and trims" do
      assert Slug.slugify("  Geometric Planter!  ") == "geometric-planter"
      assert Slug.slugify("A -- B") == "a-b"
      assert Slug.slugify("Under_scored") == "under-scored"
    end

    test "honors a custom separator" do
      assert Slug.slugify("Geometric Planter", separator: "_") == "geometric_planter"
    end

    test "blank and unconvertible input yields an empty slug" do
      assert Slug.slugify(nil) == ""
      assert Slug.slugify("") == ""
      assert Slug.slugify(:not_a_string) == ""
    end

    test "a Cyrillic title slugs without needing transliterate: true" do
      # This test used to assert the OPPOSITE — that a Cyrillic title "still collapses
      # to empty" without the flag. That was the bug, not the contract: seven call
      # sites across entities and ai omitted the flag and silently stored empty slugs,
      # which callers read as "no slug yet" and regenerated forever. Romanization is
      # the default now.
      assert Slug.slugify("Кашпо") == "kashpo"
      assert Slug.slugify("Кашпо", transliterate: true) == "kashpo"
    end

    test "transliterate: true turns a Cyrillic title into a real slug" do
      assert Slug.slugify("Кашпо", transliterate: true) == "kashpo"
      # One table serves Russian and Ukrainian, so "и" maps to "i" for both
      # rather than following each language's own romanization standard.
      assert Slug.slugify("Чашка Кави", transliterate: true) == "chashka-kavi"
      assert Slug.slugify("Щётка", transliterate: true) == "shchetka"
    end

    test "transliterate: true strips Latin diacritics" do
      assert Slug.slugify("Café Crème", transliterate: true) == "cafe-creme"
    end

    test "transliteration is stable, so a second run finds the same slug" do
      once = Slug.slugify("Кашпо Керамічне", transliterate: true)
      assert once == Slug.slugify("Кашпо Керамічне", transliterate: true)
      assert once == Slug.slugify(once, transliterate: true)
    end

    test "accented Latin was mangled by the old default too, not just Cyrillic" do
      # Worth pinning separately from the Cyrillic case above, because the
      # moduledoc's "existing URLs are unaffected" is only true of STORED slugs.
      # Anything that re-derives a slug from a title to find a row gets a
      # different string now, and these are the inputs that make that concrete:
      # the old default produced "caf" and "n-c-d-t-st" respectively.
      assert Slug.slugify("Café") == "cafe"
      assert Slug.slugify("Ünïcödé Tëst") == "unicode-test"
      assert Slug.slugify("Größe Fußball") == "grosse-fussball"
    end

    test "the output is ASCII, whatever the input" do
      # `fallback: :empty` is what buys this, and it is the invariant the rest of
      # the codebase assumes: these slugs land in paths built by code that never
      # percent-encodes. A future default change in the dependency that let
      # native script through would be caught here rather than in a URL.
      inputs = [
        "日本",
        "日本 Cafe",
        "emoji 🎉 party",
        "a/b?c=d#e",
        "../../etc/passwd",
        "<script>alert(1)</script>",
        "​zero​width",
        "Ελληνικά",
        "Цветокоррекция"
      ]

      for input <- inputs do
        slug = Slug.slugify(input)

        assert slug =~ ~r/\A[a-z0-9-]*\z/,
               "#{inspect(input)} produced a non-URL-safe slug: #{inspect(slug)}"
      end
    end
  end

  describe "transliterate/1" do
    test "leaves characters it has no mapping for alone" do
      assert Slug.transliterate("abc 123") == "abc 123"
      assert Slug.transliterate("日本") == "日本"
    end

    test "spacing and punctuation survive — generate_username_from_email/1 needs them" do
      # The username path romanizes and only THEN turns "." into "_". Fold the dot
      # into a separator here and `ülo.kask@` becomes `ulokask`, silently joining
      # two name parts.
      assert Slug.transliterate("ülo.kask") == "ulo.kask"
      assert Slug.transliterate("  spaced  out  ") == "  spaced  out  "
      assert Slug.transliterate("a--b__c") == "a--b__c"
    end

    test "the result is lower-cased, which the old table did not do" do
      # Not preservation of the previous contract, and worth a test rather than a
      # sentence: the old map had only lowercase Cyrillic keys, so it half-mapped
      # uppercase input ("Кашпо" came back "Кashpo") and left Latin case alone.
      assert Slug.transliterate("MiXeD CaSe") == "mixed case"
      assert Slug.transliterate("Кашпо") == "kashpo"
      assert Slug.transliterate("ÜLO KASK") == "ulo kask"
    end
  end

  describe "ensure_unique/2" do
    test "returns the slug untouched when free" do
      assert Slug.ensure_unique("planter", fn _ -> false end) == "planter"
    end

    test "appends the first free counter" do
      taken = MapSet.new(["planter", "planter-2", "planter-3"])
      assert Slug.ensure_unique("planter", &MapSet.member?(taken, &1)) == "planter-4"
    end

    test "an empty slug is never suffixed" do
      assert Slug.ensure_unique("", fn _ -> true end) == ""
    end
  end
end
