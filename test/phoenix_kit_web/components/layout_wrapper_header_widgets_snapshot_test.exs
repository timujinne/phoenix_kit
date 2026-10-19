defmodule PhoenixKitWeb.Components.LayoutWrapperHeaderWidgetsSnapshotTest do
  @moduledoc """
  The admin layout with no header widget registered is the layout it was before header
  widgets and the dock column existed (`PhoenixKit.Module.header_widgets/0`).

  The fixture `test/fixtures/admin_layout_without_widgets.html` is the render of a fixed
  admin page from before that change. Whitespace between tags and the CSRF token are not
  compared; the markup is. When a later change to the admin layout is meant to alter it, regenerate the fixture
  with `UPDATE_SNAPSHOTS=1 mix test <this file>` and review the diff.

  DB-free, like the rest of the layout tests: the scope is a literal struct and every
  setting the layout reads is passed in as an assign.
  """
  use ExUnit.Case, async: false

  import Phoenix.Component, only: [sigil_H: 2]
  import Phoenix.LiveViewTest, only: [rendered_to_string: 1]

  alias PhoenixKit.Users.Auth.Scope
  alias PhoenixKit.Users.Auth.User
  alias PhoenixKit.Users.Permissions
  alias PhoenixKitWeb.Components.LayoutWrapper

  @fixture Path.expand("../../fixtures/admin_layout_without_widgets.html", __DIR__)

  defp owner_scope do
    %Scope{
      user: %User{uuid: "0193a5e4-0000-7000-8000-0000000000d1", email: "head@example.com"},
      authenticated?: true,
      cached_roles: ["Owner"],
      cached_permissions: MapSet.new(Permissions.all_module_keys())
    }
  end

  defp render_admin_page do
    assigns = %{scope: owner_scope()}

    ~H"""
    <LayoutWrapper.app_layout
      flash={%{}}
      socket={nil}
      current_path="/admin"
      page_title="Dashboard"
      project_title="Acme"
      show_admin_panel_label={true}
      show_page_descriptions={false}
      dev_environment={false}
      current_locale="en"
      phoenix_kit_current_scope={@scope}
    >
      <span id="pk-test-body">body</span>
    </LayoutWrapper.app_layout>
    """
    |> rendered_to_string()
  end

  # The CSRF token differs from one render to the next, and so does the key order of the
  # JSON in the `phx-*` JS commands (`JS.dispatch` and friends): it is the order a small map
  # has, which follows the atom table of the VM, so a cold compile can flip it. Neither is
  # compared; the markup is.
  defp normalize(html) do
    html
    |> String.replace(~r/(name="csrf-token" content|data-csrf)="[^"]*"/, ~s(\\1="CSRF"))
    |> canonical_js_commands()
    |> String.replace(~r/>\s+</, "><")
    |> String.replace(~r/\s+/, " ")
    |> String.trim()
  end

  # `="[[&quot;dispatch&quot;,{...}]]"`: the attribute value of a JS command, HTML-escaped.
  defp canonical_js_commands(html) do
    Regex.replace(~r/="(\[\[&quot;[^"]*)"/, html, fn _all, escaped ->
      json =
        escaped
        |> String.replace("&quot;", ~s("))
        |> String.replace("&#39;", "'")
        |> String.replace("&lt;", "<")
        |> String.replace("&gt;", ">")
        |> String.replace("&amp;", "&")

      case Jason.decode(json) do
        {:ok, term} -> "=" <> inspect(term, custom_options: [sort_maps: true], limit: :infinity)
        {:error, _} -> "=\"" <> escaped <> "\""
      end
    end)
  end

  test "the comparison ignores the key order of JS command JSON" do
    one =
      ~s(<a phx-click="[[&quot;dispatch&quot;,{&quot;event&quot;:&quot;x&quot;,&quot;detail&quot;:{&quot;a&quot;:1,&quot;b&quot;:2}}]]">)

    other =
      ~s(<a phx-click="[[&quot;dispatch&quot;,{&quot;detail&quot;:{&quot;b&quot;:2,&quot;a&quot;:1},&quot;event&quot;:&quot;x&quot;}]]">)

    changed =
      ~s(<a phx-click="[[&quot;dispatch&quot;,{&quot;event&quot;:&quot;y&quot;,&quot;detail&quot;:{&quot;a&quot;:1,&quot;b&quot;:2}}]]">)

    assert normalize(one) == normalize(other)
    refute normalize(one) == normalize(changed)
  end

  test "without a header widget the admin layout is the layout it was" do
    html = render_admin_page()

    if System.get_env("UPDATE_SNAPSHOTS") == "1" do
      File.write!(@fixture, html)
    end

    assert normalize(html) == normalize(File.read!(@fixture))
  end

  test "and it has neither a dock column nor the dock's open class" do
    html = render_admin_page()

    assert html =~ ~s(id="admin-drawer")
    refute html =~ "pk-dock"
  end
end
