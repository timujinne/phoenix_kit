defmodule PhoenixKit.ProfileSettingsTabTest do
  @moduledoc """
  Registered profile settings tabs (`PhoenixKit.ProfileSettingsTab`): what an
  entry may hold, where it lands in the strip, who is offered it, its label,
  and the routes the router macro generates for it.
  """
  # async: false - the tabs are read from application config.
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog
  import Phoenix.LiveViewTest

  alias PhoenixKit.ProfileSettingsTab
  alias PhoenixKit.Users.Auth.Scope
  alias PhoenixKit.Utils.Routes
  alias PhoenixKitWeb.Components.ProfileSettingsTabs

  defmodule OnModule do
    def enabled?, do: true
    def profile_settings_tabs, do: [%{id: "from-on", label: "On", after: "account"}]
  end

  defmodule OffModule do
    def permission_metadata, do: %{key: "profile_tab_off"}
    def enabled?, do: false

    def profile_settings_tabs,
      do: [%{id: "from-off", label: "Off", live_view: PhoenixKit.ProfileSettingsTabTest}]
  end

  defmodule UnavailableModule do
    def permission_metadata, do: %{key: "profile_tab_unavailable"}
    def enabled?, do: exit(:unavailable)
  end

  defmodule CollisionModule do
    def enabled?, do: true

    def profile_settings_tabs,
      do: [%{id: "from-off", label: "Collision", live_view: PhoenixKit.ProfileSettingsTabTest}]
  end

  defmodule ProbeLive do
    use Phoenix.LiveView

    @impl true
    def render(assigns), do: ~H"<div>Registered settings page</div>"
  end

  setup do
    forget_warnings()
    on_exit(&forget_warnings/0)
  end

  # Warnings are logged once per VM; each test starts from none.
  defp forget_warnings do
    for {{ProfileSettingsTab, :warned, _} = key, _} <- :persistent_term.get(),
        do: :persistent_term.erase(key)
  end

  def label, do: "Translated label"
  def raise_label, do: raise("boom")
  def yes(_scope), do: true
  def no(_scope), do: false
  def crash(_scope), do: raise("boom")

  defp put_tabs(tabs) do
    previous = Application.get_env(:phoenix_kit, :profile_settings_tabs)
    Application.put_env(:phoenix_kit, :profile_settings_tabs, tabs)

    on_exit(fn ->
      if previous,
        do: Application.put_env(:phoenix_kit, :profile_settings_tabs, previous),
        else: Application.delete_env(:phoenix_kit, :profile_settings_tabs)
    end)
  end

  describe "new/1" do
    test "a map or a keyword list, with defaults" do
      assert {:ok, %ProfileSettingsTab{id: "extra", label: "Extra", icon: "hero-squares-2x2"}} =
               ProfileSettingsTab.new(%{id: "extra", label: "Extra"})

      assert {:ok, %ProfileSettingsTab{live_view: {__MODULE__, :index}}} =
               ProfileSettingsTab.new(id: "extra", label: "Extra", live_view: __MODULE__)

      assert {:ok, %ProfileSettingsTab{live_view: {__MODULE__, :show}}} =
               ProfileSettingsTab.new(id: "extra", label: "Extra", live_view: {__MODULE__, :show})
    end

    test "refuses core's ids, ids that are not a URL segment, and unknown keys" do
      for id <- ProfileSettingsTab.reserved_ids() do
        assert {:error, _} = ProfileSettingsTab.new(%{id: id, label: "X"})
      end

      for id <- ["", "Has Caps", "a/b", "-lead", "a b", nil, :atom] do
        assert {:error, _} = ProfileSettingsTab.new(%{id: id, label: "X"})
      end

      assert {:error, reason} = ProfileSettingsTab.new(%{id: "x", label: "X", lable: "typo"})
      assert reason =~ "lable"
    end

    test "refuses a label, visible or live_view of the wrong shape" do
      assert {:error, _} = ProfileSettingsTab.new(%{id: "x"})
      assert {:error, _} = ProfileSettingsTab.new(%{id: "x", label: fn _ -> "X" end})
      assert {:error, _} = ProfileSettingsTab.new(%{id: "x", label: "X", visible: fn -> true end})
      assert {:error, _} = ProfileSettingsTab.new(%{id: "x", label: "X", live_view: "Mod"})
    end
  end

  describe "all/0" do
    test "drops invalid entries and later duplicates, with a warning" do
      put_tabs([
        %{id: "first", label: "First"},
        %{id: "first", label: "Again"},
        %{id: "account", label: "Mine"},
        :not_a_tab
      ])

      log =
        capture_log(fn -> assert [%{id: "first", label: "First"}] = ProfileSettingsTab.all() end)

      assert log =~ "already declared"
      assert log =~ "core's"
    end
  end

  describe "module tabs" do
    test "a disabled route owner does not hand its id to another module" do
      put_tabs([])
      modules = [OffModule, CollisionModule]
      Enum.each(modules, &PhoenixKit.ModuleRegistry.register/1)
      on_exit(fn -> Enum.each(modules, &PhoenixKit.ModuleRegistry.unregister/1) end)

      capture_log(fn ->
        assert [%{module: OffModule}] = ProfileSettingsTab.routed(modules)
        refute Enum.any?(ProfileSettingsTab.all(), &(&1.id == "from-off"))
      end)
    end

    test "come after the host's, and only while the module is enabled" do
      put_tabs([%{id: "from-host", label: "Host"}])
      Enum.each([OnModule, OffModule], &PhoenixKit.ModuleRegistry.register/1)

      on_exit(fn ->
        Enum.each([OnModule, OffModule], &PhoenixKit.ModuleRegistry.unregister/1)
      end)

      assert [%{id: "from-host", module: nil}, %{id: "from-on", module: OnModule}] =
               ProfileSettingsTab.all()

      # A disabled module's page is still routed; the strip leaves it out.
      assert [%{id: "from-off", live_view: {__MODULE__, :index}}] =
               ProfileSettingsTab.routed([OffModule])
    end
  end

  describe "the strip" do
    test "permission checks respect live feature state and fail closed on an exit" do
      modules = [OffModule, UnavailableModule]
      Enum.each(modules, &PhoenixKit.ModuleRegistry.register/1)
      on_exit(fn -> Enum.each(modules, &PhoenixKit.ModuleRegistry.unregister/1) end)

      for key <- ["profile_tab_off", "profile_tab_unavailable"] do
        {:ok, tab} = ProfileSettingsTab.new(%{id: "restricted", label: "X", permission: key})
        scope = %Scope{cached_permissions: MapSet.new([key])}
        capture_log(fn -> refute ProfileSettingsTab.visible?(tab, scope) end)
      end
    end

    test "a sub-permission requires its base permission" do
      {:ok, tab} =
        ProfileSettingsTab.new(%{id: "restricted", label: "X", permission: "media.manage"})

      refute ProfileSettingsTab.visible?(tab, %Scope{
               cached_permissions: MapSet.new(["media.manage"])
             })

      assert ProfileSettingsTab.visible?(tab, %Scope{
               cached_permissions: MapSet.new(["media", "media.manage"])
             })
    end

    test "places tabs after the one they name, in declared order, the rest at the end" do
      put_tabs([
        %{id: "loose", label: "Loose"},
        %{id: "second", label: "Second", after: "security"},
        %{id: "nested", label: "Nested", after: "first"},
        %{id: "first", label: "First", after: "security"},
        %{id: "lost", label: "Lost", after: "nowhere"},
        %{id: "cycle-a", label: "A", after: "cycle-b"},
        %{id: "cycle-b", label: "B", after: "cycle-a"}
      ])

      ids = ProfileSettingsTabs.tab_ids(nil)

      assert ids == Enum.uniq(ids)

      assert ids |> Enum.drop_while(&(&1 != "security")) |> Enum.take(4) ==
               ~w(security second first nested)

      assert Enum.take(ids, -4) == ~w(loose lost cycle-a cycle-b)
    end

    test "offers a tab only when its checks pass, and fails closed" do
      put_tabs([
        %{id: "open", label: "Open", visible: {__MODULE__, :yes}},
        %{id: "shut", label: "Shut", visible: {__MODULE__, :no}},
        %{id: "broken", label: "Broken", visible: {__MODULE__, :crash}},
        %{id: "keyed", label: "Keyed", permission: "integrations"}
      ])

      log =
        capture_log(fn ->
          ids = ProfileSettingsTabs.tab_ids(nil)
          assert "open" in ids
          refute "shut" in ids
          refute "broken" in ids
          # No scope holds no permission.
          refute "keyed" in ids
        end)

      assert log =~ "visibility check"
    end

    test "labels come from the registry; a label function is called on render" do
      put_tabs([
        %{id: "plain", label: "Plain", icon: "hero-star"},
        %{id: "mfa", label: {__MODULE__, :label, []}},
        %{id: "bad", label: {__MODULE__, :raise_label, []}}
      ])

      assert ProfileSettingsTabs.tab_label("plain") == "Plain"
      assert ProfileSettingsTabs.tab_icon("plain") == "hero-star"
      assert ProfileSettingsTabs.tab_label("mfa") == "Translated label"
      assert ProfileSettingsTabs.tab_label("account") == "Account"

      # A label that fails shows the id rather than breaking the strip.
      assert capture_log(fn -> assert ProfileSettingsTabs.tab_label("bad") == "bad" end) =~
               "raised"
    end

    test "rendered from a registered tab's page, every tab navigates and its own is active" do
      put_tabs([%{id: "extra", label: "Extra"}])

      html = render_component(&ProfileSettingsTabs.profile_tabs/1, active: "extra", scope: nil)
      doc = LazyHTML.from_fragment(html)

      links = LazyHTML.query(doc, "a")
      assert Enum.all?(links, &(LazyHTML.attribute(&1, "data-phx-link") == ["redirect"]))
      assert html =~ ~s(href="#{ProfileSettingsTabs.path("extra")}")
      assert html =~ "Extra"
    end

    test "from ProfileSettings, core's tabs patch and a registered tab navigates" do
      put_tabs([%{id: "extra", label: "Extra"}])

      html = render_component(&ProfileSettingsTabs.profile_tabs/1, active: "account", scope: nil)
      doc = LazyHTML.from_fragment(html)

      kinds =
        doc
        |> LazyHTML.query("a")
        |> Enum.map(&{LazyHTML.attribute(&1, "href"), LazyHTML.attribute(&1, "data-phx-link")})
        |> Map.new(fn {[href], [kind]} -> {href, kind} end)

      assert kinds[ProfileSettingsTabs.path("extra")] == "redirect"
      assert kinds[ProfileSettingsTabs.path("security")] == "patch"
    end
  end

  describe "routes" do
    test "the compiled host router routes both URL shapes to the registered view before :tab" do
      put_tabs([%{id: "routed", label: "Routed", live_view: {ProbeLive, :show}}])

      # Compile in the sync test phase, after all test files have loaded: application
      # config mutations at file scope race the other router fixtures.
      Module.create(
        __MODULE__.ProbeRouter,
        quote do
          use PhoenixKitWeb, :router
          import PhoenixKitWeb.Integration

          pipeline :browser do
            plug :fetch_session
          end

          phoenix_kit_routes()
        end,
        Macro.Env.location(__ENV__)
      )

      on_exit(fn ->
        :code.purge(__MODULE__.ProbeRouter)
        :code.delete(__MODULE__.ProbeRouter)
      end)

      prefix = Routes.prefix_base()

      for path <- ["#{prefix}/profile/settings/routed", "#{prefix}/et/profile/settings/routed"] do
        info = Phoenix.Router.route_info(__MODULE__.ProbeRouter, "GET", path, "localhost")

        assert %{phoenix_live_view: {ProbeLive, :show, _, session}} = info
        assert session.name == :phoenix_kit_authenticated

        assert Enum.any?(session.extra.on_mount, fn hook ->
                 hook.id == {PhoenixKitWeb.Users.Auth, :phoenix_kit_ensure_authenticated_scope}
               end)
      end

      refute __MODULE__.ProbeRouter.__mix_recompile__?()
      Application.put_env(:phoenix_kit, :profile_settings_tabs, [])
      assert __MODULE__.ProbeRouter.__mix_recompile__?()
    end

    test "a tab with a live_view gets a route, one without does not" do
      put_tabs([
        %{id: "routed", label: "Routed", live_view: __MODULE__},
        %{id: "hosted", label: "Hosted"}
      ])

      routes = PhoenixKitWeb.Integration.compile_profile_settings_tab_routes(PhoenixKitWeb.Router)

      assert [route] = routes

      assert Macro.to_string(route) =~
               ~s[live("/profile/settings/routed", #{inspect(__MODULE__)}, :index)]
    end
  end
end
