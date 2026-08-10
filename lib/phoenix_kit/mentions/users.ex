defmodule PhoenixKit.Mentions.Users do
  @moduledoc """
  The `@` side of mentions: finding a person to ping.

  Separate from the `#` fan-out because a ping is always a person, and
  people are core's — there is no module to ask and no permission model to
  federate. What there IS is a decision about who may be pinged at all, and
  the rule shipped here is deliberately narrow:

    * only **active, confirmed** accounts (a pending invite cannot be
      pinged into existence, and a deactivated account is not a colleague);
    * only accounts that can reach the admin area at all, since every
      surface a mention currently appears on lives there — pinging a
      customer about an internal note would be the leak, not the feature.

  Matching is on username, then name, then email — email last and only on a
  prefix, so the typeahead cannot be used to confirm whether an address has
  an account by pasting it in.
  """

  import Ecto.Query

  alias PhoenixKit.RepoHelper
  alias PhoenixKit.Users.Auth.{Scope, User}

  @default_limit 8

  # How many rows to pull per requested result before the in-memory
  # permission filter. Bounded so a site with thousands of non-admin
  # accounts can't turn one keystroke into a full scan.
  @overfetch 8

  defp repo, do: RepoHelper.repo()

  @doc """
  People matching `query`, shaped for the typeahead.

  An empty query returns a short list of candidates rather than nothing:
  opening the picker with `@` and seeing who is around beats a blank box.
  """
  @spec search(String.t(), keyword()) :: [map()]
  def search(query, opts \\ []) do
    limit = Keyword.get(opts, :limit, @default_limit)

    User
    # Confirmation is a column, so it belongs in the query. The admin-area
    # check is not — it walks roles and permissions per user.
    |> where([u], u.is_active == true and not is_nil(u.confirmed_at))
    |> maybe_match(String.trim(query))
    |> order_by([u], asc: u.username, asc: u.email)
    # Over-fetch, because the remaining filter runs in memory: taking
    # `limit` rows first and filtering after returns an EMPTY list whenever
    # the first N happen to be non-admins, which looks exactly like "nobody
    # matches" and is how this was first written.
    |> limit(^(limit * @overfetch))
    |> repo().all()
    |> Enum.filter(&pingable?/1)
    |> Enum.take(limit)
    |> Enum.map(&to_result/1)
  end

  defp maybe_match(queryable, ""), do: queryable

  defp maybe_match(queryable, query) do
    contains = "%#{escape_like(query)}%"
    prefix = "#{escape_like(query)}%"

    where(
      queryable,
      [u],
      ilike(u.username, ^contains) or ilike(u.first_name, ^contains) or
        ilike(u.last_name, ^contains) or ilike(u.email, ^prefix)
    )
  end

  # `%` and `_` in user input are wildcards to LIKE. Without escaping, a
  # single `%` matches every account in the system.
  defp escape_like(value) do
    value
    |> String.replace("\\", "\\\\")
    |> String.replace("%", "\\%")
    |> String.replace("_", "\\_")
  end

  # Confirmation is the line between "this address was typed into a form"
  # and "a person holds this account".
  defp pingable?(%User{confirmed_at: nil}), do: false

  defp pingable?(%User{} = user) do
    user
    |> Scope.for_user()
    |> Scope.can_access_admin_area?()
  rescue
    _ -> false
  catch
    :exit, _ -> false
  end

  defp to_result(%User{} = user) do
    %{
      kind: :user,
      type: "user",
      uuid: user.uuid,
      title: display_name(user),
      # NOT the email. The title deliberately degrades to a local part, and
      # printing the full address underneath it gives back exactly what that
      # was protecting — in a menu, next to a name, ready to copy.
      subtitle: nil
    }
  end

  @doc """
  The label a mention of this user carries — what the author saw when they
  picked, and the fallback when the account is later deleted.
  """
  @spec display_name(User.t()) :: String.t()
  def display_name(%User{} = user), do: User.display_name(user)

  @doc """
  Resolves mentioned user uuids to `%{uuid => %{title, path}}` — the
  `resolve_comment_resources/1` shape, so `@` mentions render through the
  same `ResourceLinks` path `#` does.
  """
  @spec resolve(list()) :: map()
  def resolve(uuids) do
    User
    |> where([u], u.uuid in ^uuids)
    |> repo().all()
    |> Map.new(fn user ->
      {user.uuid, %{title: display_name(user), full_title: display_name(user), path: nil}}
    end)
  rescue
    _ -> %{}
  end
end
