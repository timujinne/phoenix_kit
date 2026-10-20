defmodule PhoenixKitWeb.Users.SessionRefMountTest do
  @moduledoc """
  How a LiveView rendered beside the page (a sticky `live_render`, e.g. a widget in the
  core layout) learns which browser session it runs in: in its own connected mount it
  reads the session map, where LiveView merges the cookie session's `"user_token"`, and
  keeps only the id of the token row and its user (`SessionRef.from_session/1`), plus
  whether the active account is borrowed (`MultiSession.impersonated?/1`). The host page
  does not take part: it hands the nested LiveView a session without any token. Neither
  value is a secret; the raw token never leaves the cookie session. LiveView merges the
  cookie session into the nested LiveView's session in the static render too (the
  parent's conn session), so the reference is there as well; callers still act on it
  only in the connected mount.
  """
  use PhoenixKitWeb.ConnCase, async: false

  alias PhoenixKit.Users.Auth
  alias PhoenixKit.Users.Auth.SessionRef
  alias PhoenixKitWeb.Users.MultiSession

  defmodule Probe do
    @moduledoc false
    use Phoenix.LiveView

    alias PhoenixKit.Users.Auth.SessionRef
    alias PhoenixKitWeb.Users.MultiSession

    def mount(_params, session, socket) do
      {token_uuid, user_uuid} =
        case SessionRef.from_session(session) do
          {:ok, {token_uuid, user_uuid}} -> {token_uuid, user_uuid}
          :error -> {"none", "none"}
        end

      {:ok,
       Phoenix.Component.assign(socket,
         token_uuid: token_uuid,
         user_uuid: user_uuid,
         impersonated: MultiSession.impersonated?(session)
       )}
    end

    def render(assigns) do
      ~H"""
      <div
        id="session-ref-probe"
        data-token-uuid={@token_uuid}
        data-user-uuid={@user_uuid}
        data-impersonated={to_string(@impersonated)}
      >
      </div>
      """
    end
  end

  # A page that hosts the sticky LiveView. It passes a session without any token: the
  # nested LiveView must find the reference itself.
  defmodule Host do
    @moduledoc false
    use Phoenix.LiveView

    def mount(_params, _session, socket), do: {:ok, socket}

    def render(assigns) do
      ~H"""
      <div id="host-page">
        {live_render(@socket, PhoenixKitWeb.Users.SessionRefMountTest.Sticky,
          id: "sticky-assistant",
          sticky: true,
          session: %{"x" => "1"}
        )}
      </div>
      """
    end
  end

  # The sticky LiveView: it asks for the reference only in its connected mount.
  defmodule Sticky do
    @moduledoc false
    use Phoenix.LiveView

    alias PhoenixKit.Users.Auth.SessionRef
    alias PhoenixKitWeb.Users.MultiSession

    def mount(_params, session, socket) do
      {token_uuid, user_uuid} =
        case SessionRef.from_session(session) do
          {:ok, {token_uuid, user_uuid}} -> {token_uuid, user_uuid}
          :error -> {"none", "none"}
        end

      # Lets a test see the static mount, whose result no rendered page keeps.
      if pid = Process.whereis(:session_ref_mount_test_probe) do
        send(
          pid,
          {:sticky_mount, connected?(socket), token_uuid, MultiSession.impersonated?(session)}
        )
      end

      {:ok,
       Phoenix.Component.assign(socket,
         token_uuid: token_uuid,
         user_uuid: user_uuid,
         impersonated: MultiSession.impersonated?(session),
         connected: connected?(socket)
       )}
    end

    def render(assigns) do
      ~H"""
      <div
        id="sticky-probe"
        data-token-uuid={@token_uuid}
        data-user-uuid={@user_uuid}
        data-impersonated={to_string(@impersonated)}
        data-connected={to_string(@connected)}
      >
      </div>
      """
    end
  end

  defp user! do
    {:ok, user} =
      Auth.register_user(%{
        email: "session_ref_#{System.unique_integer([:positive])}@example.com",
        password: "ValidPassword123!"
      })

    # Confirmed: an unconfirmed account's session cannot act while confirmation is
    # required (`SessionRef.scope_for_session/2`).
    user
    |> Ecto.Changeset.change(confirmed_at: DateTime.truncate(DateTime.utc_now(), :second))
    |> PhoenixKit.RepoHelper.repo().update!()
  end

  defp probe(conn, session) do
    {:ok, view, _html} =
      conn
      |> init_test_session(session)
      |> live_isolated(Probe)

    view
  end

  test "a signed-in session gives the token row's id and the user, not the token", %{
    conn: conn
  } do
    user = user!()
    token = Auth.generate_user_session_token(user)
    token_uuid = Auth.get_session_token_record(token).uuid

    view = probe(conn, %{"user_token" => token})

    assert has_element?(view, "#session-ref-probe[data-token-uuid='#{token_uuid}']")
    assert has_element?(view, "#session-ref-probe[data-user-uuid='#{user.uuid}']")
    assert has_element?(view, "#session-ref-probe[data-impersonated='false']")

    assert {:ok, scope} = SessionRef.scope_for_session(token_uuid, user.uuid)
    assert scope.user.uuid == user.uuid
  end

  test "a session whose active account is not the root of its stack is borrowed", %{
    conn: conn
  } do
    operator = user!()
    target = user!()
    root = Auth.generate_user_session_token(operator)
    borrowed = Auth.generate_user_session_token(target)

    view =
      probe(conn, %{"user_token" => borrowed, "pk_session_accounts" => [root, borrowed]})

    assert has_element?(view, "#session-ref-probe[data-user-uuid='#{target.uuid}']")
    assert has_element?(view, "#session-ref-probe[data-impersonated='true']")
  end

  test "a sticky LiveView finds the reference itself in a connected mount", %{conn: conn} do
    operator = user!()
    target = user!()
    root = Auth.generate_user_session_token(operator)
    borrowed = Auth.generate_user_session_token(target)
    borrowed_uuid = Auth.get_session_token_record(borrowed).uuid

    {:ok, host, _html} =
      conn
      |> init_test_session(%{"user_token" => borrowed, "pk_session_accounts" => [root, borrowed]})
      |> live_isolated(Host)

    sticky = find_live_child(host, "sticky-assistant")

    assert has_element?(sticky, "#sticky-probe[data-connected='true']")
    assert has_element?(sticky, "#sticky-probe[data-token-uuid='#{borrowed_uuid}']")
    assert has_element?(sticky, "#sticky-probe[data-user-uuid='#{target.uuid}']")
    assert has_element?(sticky, "#sticky-probe[data-impersonated='true']")
  end

  test "a static render of a sticky LiveView carries the reference too", %{conn: conn} do
    Process.register(self(), :session_ref_mount_test_probe)
    operator = user!()
    target = user!()
    root = Auth.generate_user_session_token(operator)
    borrowed = Auth.generate_user_session_token(target)
    borrowed_uuid = Auth.get_session_token_record(borrowed).uuid

    {:ok, _host, _html} =
      conn
      |> init_test_session(%{"user_token" => borrowed, "pk_session_accounts" => [root, borrowed]})
      |> live_isolated(Host)

    # live_isolated renders the page statically first, then connects.
    assert_receive {:sticky_mount, false, ^borrowed_uuid, true}
    assert_receive {:sticky_mount, true, ^borrowed_uuid, true}
  end

  test "an anonymous or logged-out session gives no reference", %{conn: conn} do
    user = user!()
    token = Auth.generate_user_session_token(user)
    :ok = Auth.delete_user_session_token(token)

    assert has_element?(probe(conn, %{}), "#session-ref-probe[data-token-uuid='none']")

    assert has_element?(
             probe(conn, %{"user_token" => token}),
             "#session-ref-probe[data-token-uuid='none']"
           )

    refute MultiSession.impersonated?(%{})
  end
end
