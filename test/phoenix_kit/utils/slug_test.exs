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

    test "without transliteration a Cyrillic title still collapses to empty" do
      assert Slug.slugify("Кашпо") == ""
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
  end

  describe "transliterate/1" do
    test "leaves characters it has no mapping for alone" do
      assert Slug.transliterate("abc 123") == "abc 123"
      assert Slug.transliterate("日本") == "日本"
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
