defmodule PhoenixKit.Users.CommentResources do
  @moduledoc """
  Resolves `"user"` comment resources for the comments moderation admin.

  A comment attached to a user (`resource_type: "user"`, `resource_uuid:
  user_uuid`) resolves to the user's display name + admin detail page
  (`/admin/users/view/:uuid`), with their avatar as the chip thumbnail — so the
  moderation list links to the user instead of showing a bare uuid.

  Registered as the `"user"` handler by `phoenix_kit_comments`'
  `resolve_comment_resources/1` dispatch (gated on this module being loaded).
  Mirrors `PhoenixKit.Annotations.resolve_comment_resources/1` (the `"file"`
  handler).
  """

  import Ecto.Query, only: [from: 2]

  alias PhoenixKit.Modules.Storage.URLSigner
  alias PhoenixKit.RepoHelper
  alias PhoenixKit.Users.Auth.User

  @spec resolve_comment_resources([binary()]) :: %{binary() => map()}
  def resolve_comment_resources(resource_uuids) when is_list(resource_uuids) do
    from(u in User, where: u.uuid in ^resource_uuids)
    |> RepoHelper.all()
    |> Map.new(fn user ->
      # Raw path — the comments module applies Routes.path/1 once when rendering
      # the chip (pre-applying it here would double-prefix under a url_prefix).
      info = %{
        title: display_name(user),
        path: "/admin/users/view/#{user.uuid}"
      }

      info =
        case avatar_thumb(user) do
          nil -> info
          url -> Map.put(info, :thumb_url, url)
        end

      {user.uuid, info}
    end)
  rescue
    _ -> %{}
  end

  # This module is the registered `ResourceLinks` handler for the "user"
  # type, so it names every `@` mention everywhere — including public issue
  # boards. The old `|| user.email` fallback therefore published a full
  # address for any commenter who had not set a name.
  defp display_name(user), do: User.display_name(user)

  # Same avatar precedence the `user_avatar` component uses: an uploaded avatar
  # (storage thumbnail), then an OAuth avatar URL, else none (chip shows a badge).
  defp avatar_thumb(%{custom_fields: %{"avatar_file_uuid" => file_id}})
       when is_binary(file_id) and file_id != "" do
    URLSigner.signed_url(file_id, "thumbnail")
  end

  defp avatar_thumb(%{custom_fields: %{"oauth_avatar_url" => url}})
       when is_binary(url) and url != "" do
    url
  end

  defp avatar_thumb(_user), do: nil
end
