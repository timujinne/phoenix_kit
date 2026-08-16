defmodule PhoenixKit.Dashboard.TabTest do
  @moduledoc """
  Unit tests for PhoenixKit.Dashboard.Tab localized_label/1, localized_tooltip/1,
  and the gettext_backend / gettext_domain fields round-tripping through Tab.new/1.
  """

  use ExUnit.Case, async: false

  alias PhoenixKit.Dashboard.Tab

  @backend PhoenixKitWeb.Gettext
  @known_msgid "Dashboard"
  @known_ru_translation "Панель управления"
  @unknown_msgid "This string has no translation"

  setup do
    original_locale = Gettext.get_locale(@backend)

    on_exit(fn ->
      Gettext.put_locale(@backend, original_locale)
    end)

    :ok
  end

  describe "localized_label/1" do
    test "returns raw label when gettext_backend is nil (default)" do
      tab = Tab.new!(id: :home, label: "Home", path: "/home")
      assert Tab.localized_label(tab) == "Home"
    end

    test "returns nil when label is nil (divider tab)" do
      tab = %Tab{
        id: :divider,
        label: nil,
        path: nil,
        gettext_backend: nil,
        gettext_domain: "default"
      }

      assert Tab.localized_label(tab) == nil
    end

    test "returns nil when label is nil even with a gettext_backend set" do
      tab = %Tab{
        id: :divider,
        label: nil,
        path: nil,
        gettext_backend: @backend,
        gettext_domain: "default"
      }

      assert Tab.localized_label(tab) == nil
    end

    test "returns translated string when backend and locale are set" do
      Gettext.put_locale(@backend, "ru")

      tab =
        Tab.new!(
          id: :dashboard,
          label: @known_msgid,
          path: "/dashboard",
          gettext_backend: @backend
        )

      assert Tab.localized_label(tab) == @known_ru_translation
    end

    test "falls back to msgid when no translation exists for the requested locale" do
      Gettext.put_locale(@backend, "ru")

      tab =
        Tab.new!(
          id: :unknown,
          label: @unknown_msgid,
          path: "/unknown",
          gettext_backend: @backend
        )

      assert Tab.localized_label(tab) == @unknown_msgid
    end

    test "uses default domain when gettext_domain not specified" do
      Gettext.put_locale(@backend, "ru")

      tab =
        Tab.new!(
          id: :dashboard,
          label: @known_msgid,
          path: "/dashboard",
          gettext_backend: @backend
        )

      assert tab.gettext_domain == "default"
      assert Tab.localized_label(tab) == @known_ru_translation
    end

    test "renders raw label for a struct constructed without explicitly setting gettext fields" do
      # Simulates pre-1.8 callers — defstruct supplies nil/`"default"` defaults,
      # so the result must equal the raw label.
      tab = %Tab{id: :legacy, label: "Legacy", path: "legacy"}
      assert Tab.localized_label(tab) == "Legacy"
    end

    test "tolerates an old-shape struct missing :gettext_backend / :gettext_domain keys" do
      # Simulates the hot-reload + ETS scenario: a parent app's Registry GenServer
      # cached Tab structs under phoenix_kit ~> 1.7.x, where neither key existed
      # in defstruct. After upgrading to 1.8 without restarting, those cached
      # structs still flow through the sidebar render path. Map.get-based access
      # in localized_label/1 must fall back to the raw label instead of raising
      # FunctionClauseError.
      stale =
        Tab.new!(id: :legacy, label: "Legacy", path: "legacy")
        |> Map.delete(:gettext_backend)
        |> Map.delete(:gettext_domain)

      refute Map.has_key?(stale, :gettext_backend)
      refute Map.has_key?(stale, :gettext_domain)
      assert Tab.localized_label(stale) == "Legacy"
    end
  end

  describe "localized_tooltip/1" do
    test "returns raw tooltip when gettext_backend is nil" do
      tab = Tab.new!(id: :home, label: "Home", path: "/home", tooltip: "Go home")
      assert Tab.localized_tooltip(tab) == "Go home"
    end

    test "returns nil when tooltip is nil" do
      tab = Tab.new!(id: :home, label: "Home", path: "/home")
      assert Tab.localized_tooltip(tab) == nil
    end

    test "returns nil when tooltip is nil even with backend set" do
      tab =
        Tab.new!(
          id: :home,
          label: "Home",
          path: "/home",
          gettext_backend: @backend
        )

      assert Tab.localized_tooltip(tab) == nil
    end

    test "returns translated tooltip when backend and locale are set" do
      Gettext.put_locale(@backend, "ru")

      tab =
        Tab.new!(
          id: :dashboard,
          label: @known_msgid,
          path: "/dashboard",
          tooltip: @known_msgid,
          gettext_backend: @backend
        )

      assert Tab.localized_tooltip(tab) == @known_ru_translation
    end

    test "falls back to msgid when no tooltip translation exists for the requested locale" do
      Gettext.put_locale(@backend, "ru")

      tab =
        Tab.new!(
          id: :unknown,
          label: "Label",
          path: "/unknown",
          tooltip: @unknown_msgid,
          gettext_backend: @backend
        )

      assert Tab.localized_tooltip(tab) == @unknown_msgid
    end

    test "tolerates an old-shape struct missing gettext keys (hot-reload safety)" do
      stale =
        Tab.new!(id: :legacy, label: "Legacy", path: "/legacy", tooltip: "Help text")
        |> Map.delete(:gettext_backend)
        |> Map.delete(:gettext_domain)

      assert Tab.localized_tooltip(stale) == "Help text"
    end
  end

  describe "Tab.new/1 round-trips gettext fields" do
    test "round-trips gettext_backend and gettext_domain from keyword list" do
      {:ok, tab} =
        Tab.new(
          id: :test,
          label: "Test",
          path: "/test",
          gettext_backend: @backend,
          gettext_domain: "navigation"
        )

      assert tab.gettext_backend == @backend
      assert tab.gettext_domain == "navigation"
    end

    test "round-trips gettext_backend and gettext_domain from map" do
      {:ok, tab} =
        Tab.new(%{
          id: :test,
          label: "Test",
          path: "/test",
          gettext_backend: @backend,
          gettext_domain: "navigation"
        })

      assert tab.gettext_backend == @backend
      assert tab.gettext_domain == "navigation"
    end

    test "gettext_backend defaults to nil" do
      {:ok, tab} = Tab.new(id: :test, label: "Test", path: "/test")
      assert tab.gettext_backend == nil
    end

    test "gettext_domain defaults to 'default'" do
      {:ok, tab} = Tab.new(id: :test, label: "Test", path: "/test")
      assert tab.gettext_domain == "default"
    end
  end

  describe "group_header/1 visibility" do
    test "an explicit visible: false is preserved, not coerced to true" do
      # `opts[:visible] || true` turned false into true — the map constructor
      # and divider/1 always handled this correctly with is_nil checks.
      assert Tab.group_header(id: :h, label: "H", priority: 1, visible: false).visible ==
               false

      assert Tab.visible?(Tab.group_header(id: :h, label: "H", priority: 1), %{})
    end
  end

  describe "parameterized paths hide themselves" do
    test "a :param path is hidden unless the host explicitly opts in" do
      # These entries are routes, not navigation — they used to render a
      # literal ":uuid" in the sidebar unless hand-marked visible: false.
      route = Tab.new!(id: :show, label: "Project", path: "projects/:uuid")

      refute Tab.visible?(route, %{})
      assert Tab.hard_hidden?(route)

      forced = Tab.new!(id: :show, label: "Project", path: "projects/:uuid", visible: true)
      assert Tab.visible?(forced, %{})
      refute Tab.hard_hidden?(forced)
    end

    test "splat segments count as parameters" do
      assert Tab.parameterized_path?("files/*rest")
    end

    test "colons that are not parameter segments do not count" do
      # External URLs, ports, mailto — the reason detection is per-segment
      # rather than a substring search for ":".
      refute Tab.parameterized_path?("https://example.com/docs")
      refute Tab.parameterized_path?("http://example.com:8080/x")
      refute Tab.parameterized_path?("mailto:hi@example.com")
      refute Tab.parameterized_path?(nil)
    end

    test "a bare struct literal gets the same auto behavior" do
      # Struct literals bypass every constructor (the moduledoc's own
      # examples use them), so the default must live in visible?/2, not in
      # constructor normalization.
      refute Tab.visible?(%Tab{id: :x, label: "X", path: "x/:id"}, %{})
      assert Tab.visible?(%Tab{id: :x, label: "X", path: "x"}, %{})
    end
  end

  describe "divider/1 and group_header/1 gettext support" do
    test "Tab.divider/1 round-trips gettext_backend and gettext_domain" do
      tab =
        Tab.divider(
          priority: 100,
          label: "Account",
          gettext_backend: @backend,
          gettext_domain: "navigation"
        )

      assert tab.gettext_backend == @backend
      assert tab.gettext_domain == "navigation"
    end

    test "Tab.divider/1 defaults gettext_domain to 'default' when not provided" do
      tab = Tab.divider(priority: 100, label: "Account", gettext_backend: @backend)
      assert tab.gettext_domain == "default"
    end

    test "Tab.divider/1 defaults gettext_backend to nil" do
      tab = Tab.divider(priority: 100, label: "Account")
      assert tab.gettext_backend == nil
      assert tab.gettext_domain == "default"
    end

    test "localized_label/1 on a divider returns the translated label when locale is set" do
      Gettext.put_locale(@backend, "ru")

      tab =
        Tab.divider(
          priority: 100,
          label: @known_msgid,
          gettext_backend: @backend
        )

      assert Tab.localized_label(tab) == @known_ru_translation
    end

    test "Tab.group_header/1 round-trips gettext_backend and gettext_domain" do
      tab =
        Tab.group_header(
          id: :foo,
          label: "Foo",
          priority: 100,
          gettext_backend: @backend,
          gettext_domain: "default"
        )

      assert tab.gettext_backend == @backend
      assert tab.gettext_domain == "default"
    end

    test "Tab.group_header/1 defaults gettext_backend to nil" do
      tab = Tab.group_header(id: :foo, label: "Foo", priority: 100)
      assert tab.gettext_backend == nil
      assert tab.gettext_domain == "default"
    end

    test "localized_label/1 on a group_header returns the translated label when locale is set" do
      Gettext.put_locale(@backend, "ru")

      tab =
        Tab.group_header(
          id: :section,
          label: @known_msgid,
          priority: 100,
          gettext_backend: @backend
        )

      assert Tab.localized_label(tab) == @known_ru_translation
    end
  end
end
