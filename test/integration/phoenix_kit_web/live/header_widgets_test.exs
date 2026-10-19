defmodule PhoenixKitWeb.Live.HeaderWidgetsTest do
  @moduledoc """
  A module's header widgets (`PhoenixKit.Module.header_widgets/0`) in the admin layout of a
  real, connected LiveView: rendered as sticky nested LiveViews before the notifications
  bell, only for enabled modules, and the optional dock column (`#pk-dock`) only while a
  rendered widget declares it.

  What the layout looks like with no widget at all is pinned by
  test/phoenix_kit_web/components/layout_wrapper_header_widgets_snapshot_test.exs.
  """
  use PhoenixKitWeb.ConnCase, async: false

  import Phoenix.Component, only: [sigil_H: 2]

  alias Phoenix.LiveView.JS
  alias PhoenixKit.ModuleRegistry
  alias PhoenixKit.Settings
  alias PhoenixKitWeb.Components.AdminDock
  alias PhoenixKitWeb.Test.HeaderWidgetProbeLive

  @path "/phoenix_kit/admin/__test/admin-edit-probe"

  defmodule PlainModule do
    def enabled?, do: true

    def header_widgets do
      [{HeaderWidgetProbeLive, "pk-test-widget", &__MODULE__.session/1}]
    end

    def session(assigns) do
      %{
        "label" => "plain",
        "user_uuid" => assigns.phoenix_kit_current_user.uuid,
        "locale" => assigns[:current_locale_base],
        "impersonating" => to_string(assigns[:impersonating?])
      }
    end
  end

  # A widget that keeps the dock open from its own state: the open class is on its root
  # element, which sits in the header.
  defmodule OpenDockModule do
    def enabled?, do: true

    def header_widgets do
      [{HeaderWidgetProbeLive, "pk-test-open-widget", &__MODULE__.session/1, dock: true}]
    end

    def session(_assigns), do: %{"label" => "open", "open" => true}
  end

  # "No widget for this user": the session function says so with nil.
  defmodule NilSessionModule do
    def enabled?, do: true

    def header_widgets do
      [{HeaderWidgetProbeLive, "pk-test-nil-widget", fn _assigns -> nil end, dock: true}]
    end
  end

  defmodule DockModule do
    def enabled?, do: true

    def header_widgets do
      [
        {HeaderWidgetProbeLive, "pk-test-dock-widget", &PlainModule.session/1, dock: true}
      ]
    end
  end

  # Its session function reads nothing from the assigns, so a widget that is rendered when it
  # should not be cannot be hidden by the registry dropping it for a raising session function.
  defmodule BareDockModule do
    def enabled?, do: true

    def header_widgets do
      [{HeaderWidgetProbeLive, "pk-test-bare-widget", &__MODULE__.session/1, dock: true}]
    end

    def session(_assigns), do: %{"label" => "bare"}
  end

  defmodule OffModule do
    def enabled?, do: false

    def header_widgets do
      [
        {HeaderWidgetProbeLive, "pk-test-off-widget", &PlainModule.session/1, dock: true}
      ]
    end
  end

  defp with_registered(modules, fun) do
    Enum.each(modules, &ModuleRegistry.register/1)

    try do
      fun.()
    after
      Enum.each(modules, &ModuleRegistry.unregister/1)
    end
  end

  defp admin_live(conn, path \\ @path) do
    {admin, _} = create_admin_user()
    {:ok, view, html} = live(log_in_user(conn, admin), path)
    {admin, view, html}
  end

  @owner_scope %PhoenixKit.Users.Auth.Scope{
    user: %PhoenixKit.Users.Auth.User{
      uuid: "0193a5e4-0000-7000-8000-0000000000d1",
      email: "head@example.com"
    },
    authenticated?: true,
    cached_roles: ["Owner"],
    cached_permissions: MapSet.new(PhoenixKit.Users.Permissions.all_module_keys())
  }

  # The admin layout rendered outside a connected LiveView, with the given socket and scope.
  defp render_layout(socket, scope) do
    assigns = %{socket: socket, scope: scope}

    rendered_to_string(~H"""
    <PhoenixKitWeb.Components.LayoutWrapper.app_layout
      flash={%{}}
      socket={@socket}
      current_path="/admin"
      page_title="Dashboard"
      project_title="Acme"
      phoenix_kit_current_scope={@scope}
    >
      body
    </PhoenixKitWeb.Components.LayoutWrapper.app_layout>
    """)
  end

  defp class_tokens(view, selector) do
    view
    |> element(selector)
    |> render()
    |> LazyHTML.from_fragment()
    |> LazyHTML.attribute("class")
    |> List.first()
    |> String.split()
  end

  defp page(conn) do
    {admin, _} = create_admin_user()

    conn
    |> log_in_user(admin)
    |> get(@path)
    |> html_response(200)
    |> LazyHTML.from_document()
  end

  defp matches?(document, selector), do: LazyHTML.query(document, selector) |> Enum.any?()

  # `[SELECTOR_&]:block` is "SELECTOR ancestor of the element"; return SELECTOR.
  defp ancestor_selectors(document) do
    document
    |> LazyHTML.query("#pk-dock")
    |> LazyHTML.attribute("class")
    |> List.first()
    |> String.split()
    |> Enum.flat_map(fn token ->
      case Regex.run(~r/^\[(.+)_&\]:block$/, token) do
        [_, selector] -> [String.replace(selector, "_", " ")]
        nil -> []
      end
    end)
  end

  # Where a marker sits in the document: widgets must come before the bell.
  defp position(html, marker) do
    case :binary.match(html, marker) do
      {at, _} -> at
      :nomatch -> flunk("#{marker} is not in the page")
    end
  end

  setup do
    # The bell renders only with notifications on; the widget is placed relative to it.
    Settings.update_boolean_setting("notifications_enabled", true)
    :ok
  end

  describe "with no module that declares a widget" do
    test "the layout has the bell, no widget and no dock", %{conn: conn} do
      {_admin, view, html} = admin_live(conn)

      assert html =~ ~s(id="pk-notifications-bell")
      refute html =~ "pk-test-widget"
      refute has_element?(view, "#pk-dock")
      assert has_element?(view, "#admin-drawer")
    end
  end

  describe "a widget without a dock" do
    test "is rendered as a sticky nested LiveView before the bell", %{conn: conn} do
      with_registered([PlainModule], fn ->
        {admin, view, html} = admin_live(conn)

        assert has_element?(view, ~s(header #pk-test-widget[data-phx-sticky]))

        assert position(html, ~s(id="pk-test-widget")) <
                 position(html, ~s(id="pk-notifications-bell"))

        # The session function got the layout's assigns, user included.
        child = find_live_child(view, "pk-test-widget")
        assert render(child) =~ ~s(data-user="#{admin.uuid}")
        assert render(child) =~ "widget plain"
      end)
    end

    test "the session function gets the same locale base as the bell", %{conn: conn} do
      with_registered([PlainModule], fn ->
        {_admin, view, _html} = admin_live(conn, @path <> "?locale=en")

        child = find_live_child(view, "pk-test-widget")

        [locale] =
          child
          |> render()
          |> LazyHTML.from_fragment()
          |> LazyHTML.query("[data-locale]")
          |> LazyHTML.attribute("data-locale")

        assert locale not in [nil, ""]
      end)
    end

    test "does not add the dock column", %{conn: conn} do
      with_registered([PlainModule], fn ->
        {_admin, view, html} = admin_live(conn)

        refute has_element?(view, "#pk-dock")
        refute html =~ "pk-dock"
      end)
    end
  end

  describe "a module that is switched off" do
    test "contributes neither the widget nor the dock", %{conn: conn} do
      with_registered([OffModule], fn ->
        {_admin, view, html} = admin_live(conn)

        refute html =~ "pk-test-off-widget"
        refute has_element?(view, "#pk-dock")
      end)
    end
  end

  describe "a widget that declares the dock" do
    test "adds #pk-dock to the drawer, closed", %{conn: conn} do
      with_registered([DockModule], fn ->
        {_admin, view, html} = admin_live(conn)

        assert has_element?(view, "header #pk-test-dock-widget[data-phx-sticky]")
        assert has_element?(view, "#admin-drawer > #{"#" <> AdminDock.container_id()}")

        # Closed: the layout does not set the open class, the widget's command does.
        refute has_element?(view, "#admin-drawer.#{AdminDock.open_class()}")
        assert "hidden" in class_tokens(view, "#pk-dock")
        assert html =~ ~s(id="pk-dock")
      end)
    end

    test "keeps the layout tokens that make it a column of the grid, sized by the variable", %{
      conn: conn
    } do
      with_registered([DockModule], fn ->
        {_admin, view, _html} = admin_live(conn)
        tokens = class_tokens(view, "#pk-dock")

        for token <- [
              "col-start-3",
              "w-[var(--pk-dock-width,25rem)]",
              "max-lg:fixed",
              "max-lg:inset-x-0",
              "max-lg:top-16"
            ] do
          assert token in tokens, "#pk-dock lost #{token}"
        end
      end)
    end
  end

  # The dock is opened by CSS alone: the layout's classes on #pk-dock are selectors, and they
  # only work if the element that carries the open class is where they look. These tests
  # evaluate those selectors against the page the browser would get, with the widget in the
  # header and #pk-dock in #admin-drawer, which are siblings.
  describe "where the open class has to be for the dock to show" do
    test "the dock's open-class selectors hold for a widget that carries the class in the header",
         %{conn: conn} do
      with_registered([OpenDockModule], fn ->
        document = page(conn)

        assert matches?(document, "header #pk-test-open-widget .pk-dock-open")
        assert matches?(document, "#admin-drawer #pk-dock")

        # Some selector of #pk-dock matches this page: the class on the widget opens it.
        selectors = ancestor_selectors(document)
        assert selectors != []

        assert Enum.any?(selectors, fn selector -> matches?(document, selector <> " #pk-dock") end),
               "no selector of #pk-dock matches with the open class on the widget: " <>
                 inspect(selectors)
      end)
    end

    test "the closed dock matches none of its selectors", %{conn: conn} do
      with_registered([DockModule], fn ->
        document = page(conn)

        refute Enum.any?(ancestor_selectors(document), fn selector ->
                 matches?(document, selector <> " #pk-dock")
               end)
      end)
    end

    test "the element the commands address is an ancestor of the widget and of the dock",
         %{conn: conn} do
      with_registered([DockModule], fn ->
        document = page(conn)
        [[_, %{to: target}]] = AdminDock.open().ops

        assert matches?(document, "#{target} header #pk-test-dock-widget")
        assert matches?(document, "#{target} #pk-dock")
        # ... and the class on it is one of the selectors of #pk-dock (an ancestor with it).
        assert ".pk-dock-open" in ancestor_selectors(document)
      end)
    end
  end

  describe "a widget whose session function returns nil" do
    test "is not rendered, and does not bring the dock", %{conn: conn} do
      with_registered([NilSessionModule], fn ->
        {_admin, view, html} = admin_live(conn)

        refute html =~ "pk-test-nil-widget"
        refute has_element?(view, "#pk-dock")
      end)
    end
  end

  describe "the impersonation flag" do
    test "reaches the session function; false for a plain session", %{conn: conn} do
      with_registered([PlainModule], fn ->
        {_admin, view, _html} = admin_live(conn)

        child = find_live_child(view, "pk-test-widget")
        assert render(child) =~ ~s(data-impersonating="false")
      end)
    end
  end

  describe "a dock widget in a layout without the data" do
    test "a layout rendered with no socket and no user gets neither widget nor dock" do
      with_registered([DockModule], fn ->
        assigns = %{}

        html =
          rendered_to_string(~H"""
          <PhoenixKitWeb.Components.LayoutWrapper.app_layout
            flash={%{}}
            socket={nil}
            current_path="/admin"
            page_title="Dashboard"
            project_title="Acme"
            phoenix_kit_current_scope={
              %PhoenixKit.Users.Auth.Scope{
                user: nil,
                authenticated?: true,
                cached_roles: ["Owner"],
                cached_permissions: MapSet.new(PhoenixKit.Users.Permissions.all_module_keys())
              }
            }
          >
            body
          </PhoenixKitWeb.Components.LayoutWrapper.app_layout>
          """)

        refute html =~ "pk-dock"
        refute html =~ "pk-test-dock-widget"
      end)
    end
  end

  describe "the layout's guards" do
    test "a signed-in user but no socket: no widget, no dock, no crash" do
      with_registered([BareDockModule], fn ->
        html = render_layout(nil, @owner_scope)

        assert html =~ ~s(id="admin-drawer")
        refute html =~ "pk-test-bare-widget"
        refute html =~ "pk-dock"
      end)
    end

    test "a socket but no user: no widget, no dock, no crash" do
      with_registered([BareDockModule], fn ->
        html = render_layout(%Phoenix.LiveView.Socket{}, %{@owner_scope | user: nil})

        assert html =~ ~s(id="admin-drawer")
        refute html =~ "pk-test-bare-widget"
        refute html =~ "pk-dock"
      end)
    end
  end

  describe "PhoenixKitWeb.Components.AdminDock commands" do
    test "open, close and toggle address the class on body, the ancestor that survives a live redirect" do
      for {js, op} <- [
            {AdminDock.open(), "add_class"},
            {AdminDock.close(), "remove_class"},
            {AdminDock.toggle(), "toggle_class"}
          ] do
        assert [[^op, %{to: "body", names: ["pk-dock-open"]}]] = js.ops
      end
    end

    test "they chain onto an existing command" do
      js = JS.push("opened") |> AdminDock.open()

      assert [["push", _], ["add_class", _]] = js.ops
    end
  end
end
