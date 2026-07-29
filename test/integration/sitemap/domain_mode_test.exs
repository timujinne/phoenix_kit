defmodule PhoenixKit.Integration.Sitemap.DomainModeProviderStub do
  @moduledoc false
  def ok do
    [
      %{host: "site.example.com", language: "en", primary: true},
      %{host: "site.example.fr", language: "fr", primary: false}
    ]
  end

  def no_primary, do: Enum.map(ok(), &%{&1 | primary: false})
  def two_primaries, do: Enum.map(ok(), &%{&1 | primary: true})

  def duplicate_language,
    do: ok() ++ [%{host: "other.example.fr", language: "fr-FR", primary: false}]

  def raising, do: raise("boom")
  def empty, do: []
end

defmodule PhoenixKit.Integration.Sitemap.DomainModeTest do
  use PhoenixKit.DataCase, async: false

  alias PhoenixKit.Integration.Sitemap.DomainModeProviderStub, as: Stub
  alias PhoenixKit.Modules.Sitemap.DomainMode
  alias PhoenixKit.Modules.Sitemap.UrlEntry
  alias PhoenixKit.Settings

  @base "https://legacy.example.com"

  setup do
    Settings.update_setting("languages_enabled", "true")

    Settings.update_json_setting("languages_config", %{
      "languages" => [
        %{"code" => "en-US", "name" => "English", "is_default" => true, "is_enabled" => true},
        %{"code" => "fr", "name" => "French", "is_default" => false, "is_enabled" => true},
        %{"code" => "de", "name" => "German", "is_default" => false, "is_enabled" => true}
      ]
    })

    on_exit(fn ->
      Application.delete_env(:phoenix_kit, :sitemap_domains_provider)
      Settings.update_setting("languages_enabled", "false")
    end)

    :ok
  end

  defp put_provider(fun) do
    Application.put_env(:phoenix_kit, :sitemap_domains_provider, {Stub, fun})
  end

  defp entry(loc, canonical_path) do
    UrlEntry.new(%{loc: @base <> loc, canonical_path: canonical_path, source: :test})
  end

  describe "domains/0 validation (B1)" do
    test "valid provider activates" do
      put_provider(:ok)
      assert [%{host: "site.example.com", primary: true} | _] = DomainMode.domains()
      assert DomainMode.active?()
    end

    test "no primary / two primaries / duplicate language / raising / empty ⇒ inactive" do
      for fun <- [:no_primary, :two_primaries, :duplicate_language, :raising, :empty] do
        put_provider(fun)
        assert DomainMode.domains() == [], "expected inactive for #{fun}"
      end
    end

    test "absent provider config ⇒ inactive" do
      Application.delete_env(:phoenix_kit, :sitemap_domains_provider)
      refute DomainMode.active?()
    end
  end

  describe "rebuild_for_domains/2" do
    setup do
      put_provider(:ok)
      :ok
    end

    test "fully translated group: membership, re-hosting, identical alternates, x-default" do
      entries = [
        entry("/decor/post", "/decor/post"),
        entry("/fr/decor/le-post", "/decor/post"),
        entry("/de/decor/der-post", "/decor/post")
      ]

      result = DomainMode.rebuild_for_domains(entries, @base)

      [en_entry] = result["site.example.com"]
      [fr_entry] = result["site.example.fr"]

      assert en_entry.loc == "https://site.example.com/decor/post"
      # fr loses its own prefix on its home domain
      assert fr_entry.loc == "https://site.example.fr/decor/le-post"

      # identical alternates on both duplicates
      assert en_entry.alternates == fr_entry.alternates

      hrefs = Map.new(en_entry.alternates, &{&1.hreflang, &1.href})
      assert hrefs["en"] == "https://site.example.com/decor/post"
      assert hrefs["fr"] == "https://site.example.fr/decor/le-post"
      # unmapped language stays prefixed on the primary domain
      assert hrefs["de"] == "https://site.example.com/de/decor/der-post"
      assert hrefs["x-default"] == "https://site.example.com/decor/post"
    end

    test "untranslated group appears only on its language's domain" do
      entries = [entry("/fr/only-french", "/only-french")]
      result = DomainMode.rebuild_for_domains(entries, @base)

      assert result["site.example.com"] == []
      [fr_entry] = result["site.example.fr"]
      assert fr_entry.loc == "https://site.example.fr/only-french"
      # no x-default: the primary language has no entry in this group (m2)
      refute Enum.any?(fr_entry.alternates, &(&1.hreflang == "x-default"))
    end

    test "canonical_path-less entry forms its own single-language group (m1)" do
      entries = [
        %{entry("/some/tool", nil) | canonical_path: nil}
      ]

      result = DomainMode.rebuild_for_domains(entries, @base)

      # unprefixed ⇒ default language (en) ⇒ primary domain only
      [en_entry] = result["site.example.com"]
      assert en_entry.loc == "https://site.example.com/some/tool"
      assert result["site.example.fr"] == []
    end

    test "a non-locale first segment is not treated as a language" do
      entries = [entry("/api/docs", nil)]
      result = DomainMode.rebuild_for_domains(entries, @base)

      [en_entry] = result["site.example.com"]
      assert en_entry.loc == "https://site.example.com/api/docs"
    end

    test "inactive provider yields empty map" do
      Application.delete_env(:phoenix_kit, :sitemap_domains_provider)
      assert DomainMode.rebuild_for_domains([entry("/x", "/x")], @base) == %{}
    end
  end
end
