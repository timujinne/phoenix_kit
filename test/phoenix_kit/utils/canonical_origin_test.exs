defmodule PhoenixKit.Utils.CanonicalOriginTest.Resolver do
  @moduledoc false
  def host_for(code) do
    send(self(), {:resolver_asked, code})
    answer(code)
  end

  defp answer("en"), do: "en.example.test"
  defp answer("en-US"), do: "en.example.test"
  defp answer("en-AU"), do: "en.example.test"
  defp answer("de"), do: "de.example.test"
  defp answer("de-DE"), do: "de.example.test"
  defp answer("blank"), do: "   "
  defp answer("padded"), do: "  padded.example.test  "
  defp answer("upper"), do: "DE.Example.test"
  defp answer("port"), do: "localhost:4000"
  defp answer("number"), do: 42
  defp answer("scheme"), do: "https://fr.example.test"
  defp answer("slash"), do: "de.example.test/"
  defp answer("path"), do: "de.example.test/pages"
  defp answer("query"), do: "de.example.test?x=1"
  defp answer("userinfo"), do: "user@de.example.test"
  defp answer("inner_space"), do: "de example.test"
  defp answer("raise"), do: raise("secret-detail")
  defp answer("exit"), do: exit({:secret_reason, :boom})
  defp answer("throw"), do: throw(:oops)
  defp answer(_), do: nil
end

defmodule PhoenixKit.Utils.CanonicalOriginTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias PhoenixKit.Cache
  alias PhoenixKit.Test.LanguageSettings
  alias PhoenixKit.Utils.CanonicalOriginTest.Resolver
  alias PhoenixKit.Utils.Routes

  # The site base is primed in the settings cache only, so a helper that read
  # the database (`Routes.base_url/0`) would see "http://localhost" instead.
  @base "https://site.example.test"

  setup do
    LanguageSettings.multilingual!()
    Cache.put(:settings, "site_url", @base <> "/")

    on_exit(fn -> Application.delete_env(:phoenix_kit, :canonical_host_resolver) end)

    %{base: @base}
  end

  defp resolver!,
    do: Application.put_env(:phoenix_kit, :canonical_host_resolver, {Resolver, :host_for})

  defp warnings(log), do: log |> String.split("[warning]") |> length() |> Kernel.-(1)

  describe "canonical_host/1 without a usable resolver" do
    test "nil when no resolver is configured" do
      log = capture_log(fn -> assert Routes.canonical_host("de") == nil end)
      assert log == ""
    end

    test "nil, and one warning, when the configured value is not an MFA pair" do
      for nonsense <- [:nonsense, {Resolver, :host_for, []}, &Resolver.host_for/1] do
        Application.put_env(:phoenix_kit, :canonical_host_resolver, nonsense)

        log =
          capture_log(fn ->
            assert Routes.canonical_host("de") == nil
            assert Routes.canonical_host("de") == nil
          end)

        assert log =~ "not a {module, function} pair"
        assert warnings(log) == 1
        Process.delete({Routes, :warned, :bad_config})
      end
    end

    test "nil when the resolver module does not exist" do
      Application.put_env(:phoenix_kit, :canonical_host_resolver, {Missing.Module, :host_for})

      assert capture_log(fn -> assert Routes.canonical_host("de") == nil end) =~ "raised"
    end
  end

  describe "canonical_host/1 with a resolver" do
    setup do
      resolver!()
    end

    test "returns the host the resolver gives" do
      assert Routes.canonical_host("de") == "de.example.test"
    end

    test "hands the language over as given, a dialect code included" do
      assert Routes.canonical_host("de-DE") == "de.example.test"
      assert_received {:resolver_asked, "de-DE"}

      assert Routes.canonical_host("en-GB") == nil
      assert_received {:resolver_asked, "en-GB"}

      assert Routes.canonical_host("en-AU") == "en.example.test"
    end

    test "trims the language before handing it over" do
      assert Routes.canonical_host("  de-DE ") == "de.example.test"
      assert_received {:resolver_asked, "de-DE"}
    end

    test "nil when the resolver has no host for the language, without a warning" do
      log = capture_log(fn -> assert Routes.canonical_host("uk") == nil end)
      assert log == ""
    end

    test "trims and lower-cases the host; blank is nil" do
      assert Routes.canonical_host("padded") == "padded.example.test"
      assert Routes.canonical_host("upper") == "de.example.test"
      assert Routes.canonical_host("blank") == nil
    end

    test "keeps a port" do
      assert Routes.canonical_host("port") == "localhost:4000"
    end

    test "a non-string answer is nil and is logged" do
      log = capture_log(fn -> assert Routes.canonical_host("number") == nil end)
      assert log =~ "non-string"
    end

    test "an answer that is not a bare host is nil and is logged" do
      for code <- ~w(scheme slash path query userinfo inner_space) do
        Process.delete({Routes, :warned, :bad_host})

        log = capture_log(fn -> assert Routes.canonical_host(code) == nil end)
        assert log =~ "not a bare host", "no warning for #{code}"
      end
    end

    test "a resolver that raises is nil and is logged by exception module only" do
      log = capture_log(fn -> assert Routes.canonical_host("raise") == nil end)
      assert log =~ "raised"
      assert log =~ "RuntimeError"
      refute log =~ "secret-detail"
    end

    test "a resolver that exits is nil and is logged without the reason" do
      log = capture_log(fn -> assert Routes.canonical_host("exit") == nil end)
      assert log =~ "exited"
      refute log =~ "secret_reason"
    end

    test "a resolver that throws is nil and is logged" do
      log = capture_log(fn -> assert Routes.canonical_host("throw") == nil end)
      assert log =~ "threw"
    end

    test "a failing resolver is logged once per process, not once per call" do
      log =
        capture_log(fn ->
          for _ <- 1..5, do: assert(Routes.canonical_host("raise") == nil)
        end)

      assert warnings(log) == 1
    end

    test "the warning comes back once the minute is over" do
      capture_log(fn -> Routes.canonical_host("raise") end)

      Process.put({Routes, :warned, :raised}, System.monotonic_time(:millisecond) - 61_000)

      log = capture_log(fn -> Routes.canonical_host("raise") end)
      assert warnings(log) == 1
    end

    test "no language, blank language or a non-string language is nil" do
      assert Routes.canonical_host(nil) == nil
      assert Routes.canonical_host("") == nil
      assert Routes.canonical_host("  ") == nil
      assert Routes.canonical_host(:de) == nil
      refute_received {:resolver_asked, _}
    end
  end

  describe "canonical_origin/1" do
    test "is the site's scheme plus the host, or nil" do
      assert Routes.canonical_origin("de") == nil

      resolver!()
      assert Routes.canonical_origin("de") == "https://de.example.test"
      assert Routes.canonical_origin("de-DE") == "https://de.example.test"
      assert Routes.canonical_origin("uk") == nil
    end

    test "follows the scheme of the site's base URL" do
      resolver!()

      Cache.put(:settings, "site_url", "http://staging.example.test")
      assert Routes.canonical_origin("de") == "http://de.example.test"

      Cache.put(:settings, "site_url", "ftp://staging.example.test")
      assert Routes.canonical_origin("de") == "https://de.example.test"
    end
  end

  describe "canonical_url/2" do
    test "without a host: the site base and the language-prefixed path", %{base: base} do
      assert Routes.canonical_url("/users/register", "de") ==
               base <> "/phoenix_kit/de/users/register"

      assert Routes.canonical_url("/users/register", "de-DE") ==
               base <> "/phoenix_kit/de/users/register"
    end

    test "with a host: the host and no language segment" do
      resolver!()

      assert Routes.canonical_url("/users/register", "de") ==
               "https://de.example.test/phoenix_kit/users/register"

      assert Routes.canonical_url("/users/register", "de-DE") ==
               "https://de.example.test/phoenix_kit/users/register"
    end

    test "a language without a host falls back to the site base", %{base: base} do
      resolver!()

      assert Routes.canonical_url("/users/register", "uk") ==
               base <> "/phoenix_kit/uk/users/register"
    end

    test "a failing resolver falls back to the site base", %{base: base} do
      resolver!()

      capture_log(fn ->
        assert Routes.canonical_url("/users/register", "raise") ==
                 base <> "/phoenix_kit/raise/users/register"

        assert Routes.canonical_url("/users/register", "exit") ==
                 base <> "/phoenix_kit/exit/users/register"
      end)
    end

    test "the root has one spelling, with or without a host" do
      resolver!()

      built = Routes.path("/", locale: "de")

      assert Routes.canonical_url("/", "de") == "https://de.example.test/phoenix_kit"
      assert Routes.canonical_url("/", "de") == Routes.canonical_absolute(built, "de")

      assert Routes.canonical_url("/", "uk") ==
               Routes.canonical_absolute(Routes.path("/", locale: "uk"), "uk")
    end
  end

  describe "canonical_absolute/2 without a host" do
    test "keeps the built path as it is behind the site base", %{base: base} do
      assert Routes.canonical_absolute("/de/pages/home", "de") ==
               base <> "/de/pages/home"

      resolver!()

      assert Routes.canonical_absolute("/uk/pages/home", "uk") ==
               base <> "/uk/pages/home"
    end

    test "a dialect the resolver has no host for keeps its own segment", %{base: base} do
      resolver!()

      assert Routes.canonical_absolute("/en-gb/pages", "en-GB") == base <> "/en-gb/pages"
    end
  end

  describe "canonical_absolute/2 with a host" do
    setup do
      resolver!()
    end

    test "removes the language segment" do
      assert Routes.canonical_absolute("/de/pages/home", "de") ==
               "https://de.example.test/pages/home"
    end

    test "a dialect code removes the base segment, case-insensitively" do
      assert Routes.canonical_absolute("/de/pages/home", "de-DE") ==
               "https://de.example.test/pages/home"

      assert Routes.canonical_absolute("/DE/pages/home", "de-DE") ==
               "https://de.example.test/pages/home"
    end

    test "a dialect segment is kept: it is not the page of the base segment" do
      assert Routes.canonical_absolute("/de-de/pages/home", "de-DE") ==
               "https://de.example.test/de-de/pages/home"

      assert Routes.canonical_absolute("/en-au/pages", "en-AU") ==
               "https://en.example.test/en-au/pages"

      assert Routes.canonical_absolute("/en/pages", "en-AU") ==
               "https://en.example.test/pages"
    end

    test "keeps the mount prefix and removes the segment after it" do
      assert Routes.canonical_absolute("/phoenix_kit/de/users/log-in", "de") ==
               "https://de.example.test/phoenix_kit/users/log-in"
    end

    test "only a segment of the language is removed" do
      assert Routes.canonical_absolute("/en/pages/home", "de") ==
               "https://de.example.test/en/pages/home"

      assert Routes.canonical_absolute("/pages/de", "de") ==
               "https://de.example.test/pages/de"

      assert Routes.canonical_absolute("/deutsch/pages", "de") ==
               "https://de.example.test/deutsch/pages"
    end

    test "a path without a segment is left alone" do
      assert Routes.canonical_absolute("/pages/home", "de") ==
               "https://de.example.test/pages/home"
    end

    test "the bare language root becomes the root" do
      assert Routes.canonical_absolute("/de", "de") == "https://de.example.test/"
      assert Routes.canonical_absolute("/de?x=1", "de") == "https://de.example.test/?x=1"
      assert Routes.canonical_absolute("/de#top", "de") == "https://de.example.test/#top"
      assert Routes.canonical_absolute("/de/", "de") == "https://de.example.test/"
    end

    test "the bare language root under the mount prefix becomes the prefix root" do
      assert Routes.canonical_absolute("/phoenix_kit/de", "de") ==
               "https://de.example.test/phoenix_kit"

      assert Routes.canonical_absolute("/phoenix_kit/de?x=1", "de") ==
               "https://de.example.test/phoenix_kit?x=1"

      assert Routes.canonical_absolute("/phoenix_kit/de/", "de") ==
               "https://de.example.test/phoenix_kit/"
    end

    test "the query and fragment survive" do
      assert Routes.canonical_absolute("/de/pages/home?a=1#top", "de") ==
               "https://de.example.test/pages/home?a=1#top"
    end

    test "a language segment inside the query is not touched" do
      assert Routes.canonical_absolute("/pages?lang=/de/x", "de") ==
               "https://de.example.test/pages?lang=/de/x"
    end

    test "the scheme is the site's" do
      Cache.put(:settings, "site_url", "http://staging.example.test")

      assert Routes.canonical_absolute("/de/pages", "de") == "http://de.example.test/pages"
    end
  end
end
