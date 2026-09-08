defmodule PhoenixKitWeb.AdminEditHelper do
  @moduledoc """
  Public API for an "Edit" link from a public page into its matching admin page.

  A host viewing a public page (a host LiveView, or a module's own public
  controller/LiveView) calls `assign_admin_edit/3` to declare where that
  page's admin counterpart lives. The visitor gets nothing unless they can
  reach the admin area at all, and — when the caller names a `:permission`
  module key — unless they also hold access to that specific module, so an
  admin scoped to Publishing never sees an Edit link into Ecommerce.

  Renders via `PhoenixKitWeb.Components.Core.AdminEditLink.admin_edit_link/1`,
  which reads the `:admin_edit_url`/`:admin_edit_label` assigns this module
  sets and renders nothing when no URL was assigned.

  ## Host LiveView example

      def handle_params(%{"slug" => slug}, _uri, socket) do
        post = Blog.get_post_by_slug!(slug)

        socket =
          AdminEditHelper.assign_admin_edit(socket, "/admin/posts/\#{post.id}/edit")

        {:noreply, assign(socket, :post, post)}
      end

  ## Module controller example

  A module's own public controller can declare the same edit target,
  guarding the call the way `phoenix_kit_publishing` guards every optional
  core API it depends on — so it still compiles and runs against a core
  release that predates this helper:

      if Code.ensure_loaded?(PhoenixKitWeb.AdminEditHelper) and
           function_exported?(PhoenixKitWeb.AdminEditHelper, :assign_admin_edit, 3) do
        conn =
          PhoenixKitWeb.AdminEditHelper.assign_admin_edit(
            conn,
            "/admin/publishing/posts/\#{post.id}/edit",
            permission: "publishing"
          )
      end
  """
  use Gettext, backend: PhoenixKitWeb.Gettext

  alias PhoenixKit.Users.Auth.Scope

  @doc """
  Assigns `:admin_edit_url` and `:admin_edit_label` when the current scope
  may see the edit link; otherwise returns the conn/socket unchanged (the
  assigns are absent, not `nil`).

  `label_or_opts` (default `"Edit"`, gettext-translated) is either:

    * a plain string — used as the label as-is; every existing caller keeps
      working unchanged.
    * a keyword list:
      * `:label` — the link's label (default: gettext "Edit").
      * `:permission` — a module permission key (the same string used as a
        module's `permission_metadata/0` `:key` or a `PhoenixKit.Dashboard.Tab`
        `:permission`). When given, the scope must also hold
        `Scope.has_module_access?/2` for that key.

  In all cases the scope must be non-`nil` and
  `Scope.can_access_admin_area?/1` must be true.
  """
  def assign_admin_edit(conn_or_socket, path, label_or_opts \\ "Edit")

  def assign_admin_edit(%Plug.Conn{} = conn, path, label_or_opts) do
    {label, permission} = normalize(label_or_opts)

    if allowed?(conn.assigns[:phoenix_kit_current_scope], permission) do
      conn
      |> Plug.Conn.assign(:admin_edit_url, path)
      |> Plug.Conn.assign(:admin_edit_label, label)
    else
      conn
    end
  end

  def assign_admin_edit(%Phoenix.LiveView.Socket{} = socket, path, label_or_opts) do
    {label, permission} = normalize(label_or_opts)

    if allowed?(socket.assigns[:phoenix_kit_current_scope], permission) do
      socket
      |> Phoenix.Component.assign(:admin_edit_url, path)
      |> Phoenix.Component.assign(:admin_edit_label, label)
    else
      socket
    end
  end

  defp normalize(label) when is_binary(label), do: {label, nil}

  defp normalize(opts) when is_list(opts) do
    label = Keyword.get(opts, :label, gettext("Edit"))
    permission = Keyword.get(opts, :permission)
    {label, permission}
  end

  defp allowed?(scope, permission) do
    scope != nil and Scope.can_access_admin_area?(scope) and
      (is_nil(permission) or Scope.has_module_access?(scope, permission))
  end
end
