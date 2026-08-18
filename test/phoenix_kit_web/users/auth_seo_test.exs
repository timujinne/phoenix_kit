defmodule PhoenixKitWeb.Users.AuthSEOTest.FakeResolver do
  @moduledoc false
  def host_for("en"), do: "en.example.test"
  def host_for("es"), do: "es.example.test"
  def host_for(_), do: nil
end

defmodule PhoenixKitWeb.Users.AuthSEOTest.RaisingResolver do
  @moduledoc false
  def host_for(_language), do: raise("boom")
end

defmodule PhoenixKitWeb.Users.AuthSEOTest.ExitingResolver do
  @moduledoc false
  def host_for(_language), do: exit(:boom)
end

defmodule PhoenixKitWeb.Users.AuthSEOTest do
  @moduledoc """
  `PhoenixKitWeb.Users.AuthSEO.seo_assigns/1` — canonical/hreflang for the
  stable, token-free auth pages (registration, log-in, magic-link
  registration request).

  Needs a DB-backed `Settings` read for `Languages.enabled?/0` and
  `Languages.get_enabled_languages/0`, so this uses `DataCase` rather than a
  no-DB unit test (mirrors `auth_locale_test.exs`).
  """

  use PhoenixKit.DataCase, async: false

  alias PhoenixKit.Settings
  alias PhoenixKitWeb.Users.AuthSEO

  setup do
    on_exit(fn ->
      Application.delete_env(:phoenix_kit, :canonical_host_resolver)
      Settings.update_setting("languages_enabled", "false")
    end)

    :ok
  end

  defp enable_languages(langs) do
    config = %{"languages" => langs}
    Settings.update_setting("languages_enabled", "true")
    Settings.update_json_setting("languages_config", config)
  end

  describe "with Languages disabled (single-language install)" do
    test "sets a self-referencing canonical_url and an empty hreflang set" do
      seo = AuthSEO.seo_assigns("/users/register")

      assert seo.canonical_url =~ "/users/register"
      assert seo.hreflang_links == []
    end
  end

  describe "with two enabled languages" do
    setup do
      enable_languages([
        %{"code" => "en", "name" => "English", "is_default" => true, "is_enabled" => true},
        %{"code" => "es", "name" => "Spanish", "is_default" => false, "is_enabled" => true}
      ])

      :ok
    end

    test "canonical_url is the current (Gettext) locale's own path" do
      seo = AuthSEO.seo_assigns("/users/log-in")

      # The test process's Gettext locale defaults to English.
      assert seo.canonical_url =~ "/en/users/log-in"
    end

    test "hreflang_links carries one absolute URL per enabled language" do
      seo = AuthSEO.seo_assigns("/users/register")

      assert %{code: "en", url: en_url} =
               Enum.find(seo.hreflang_links, &(&1.code == "en"))

      assert %{code: "es", url: es_url} =
               Enum.find(seo.hreflang_links, &(&1.code == "es"))

      assert en_url =~ "/en/users/register"
      assert es_url =~ "/es/users/register"
      assert length(seo.hreflang_links) == 2
    end

    test "a disabled language is excluded from hreflang_links" do
      enable_languages([
        %{"code" => "en", "name" => "English", "is_default" => true, "is_enabled" => true},
        %{"code" => "es", "name" => "Spanish", "is_default" => false, "is_enabled" => true},
        %{"code" => "fr", "name" => "French", "is_default" => false, "is_enabled" => false}
      ])

      seo = AuthSEO.seo_assigns("/users/register")

      refute Enum.any?(seo.hreflang_links, &(&1.code == "fr"))
    end
  end

  describe "with only one enabled language" do
    test "hreflang_links is empty — one language is not a hreflang set" do
      enable_languages([
        %{"code" => "en", "name" => "English", "is_default" => true, "is_enabled" => true}
      ])

      seo = AuthSEO.seo_assigns("/users/register")

      assert seo.hreflang_links == []
    end
  end

  describe "canonical_host_resolver" do
    setup do
      enable_languages([
        %{"code" => "en", "name" => "English", "is_default" => true, "is_enabled" => true},
        %{"code" => "es", "name" => "Spanish", "is_default" => false, "is_enabled" => true}
      ])

      :ok
    end

    test "an absent resolver falls back to the site base URL" do
      seo = AuthSEO.seo_assigns("/users/register")

      refute seo.canonical_url =~ "https://en.example.test"
    end

    test "a configured resolver puts the language on its own host, prefix stripped" do
      Application.put_env(
        :phoenix_kit,
        :canonical_host_resolver,
        {PhoenixKitWeb.Users.AuthSEOTest.FakeResolver, :host_for}
      )

      seo = AuthSEO.seo_assigns("/users/register")

      # English is the resolver's own home domain, so its locale prefix is
      # stripped: the domain itself carries the language. The PhoenixKit
      # mount prefix ("/phoenix_kit" in this test app) is not a locale
      # segment and stays.
      assert seo.canonical_url == "https://en.example.test/phoenix_kit/users/register"
      refute seo.canonical_url =~ "/en/"

      es_link = Enum.find(seo.hreflang_links, &(&1.code == "es"))
      assert es_link.url == "https://es.example.test/phoenix_kit/users/register"
      refute es_link.url =~ "/es/"
    end

    test "a resolver that raises falls back to the site base URL instead of crashing the mount" do
      Application.put_env(
        :phoenix_kit,
        :canonical_host_resolver,
        {PhoenixKitWeb.Users.AuthSEOTest.RaisingResolver, :host_for}
      )

      seo = AuthSEO.seo_assigns("/users/register")

      assert seo.canonical_url =~ "/en/users/register"
      refute seo.canonical_url =~ "https://"
    end

    test "a resolver that exits falls back to the site base URL instead of crashing the mount" do
      Application.put_env(
        :phoenix_kit,
        :canonical_host_resolver,
        {PhoenixKitWeb.Users.AuthSEOTest.ExitingResolver, :host_for}
      )

      seo = AuthSEO.seo_assigns("/users/register")

      assert seo.canonical_url =~ "/en/users/register"
      refute seo.canonical_url =~ "https://"
    end
  end
end
