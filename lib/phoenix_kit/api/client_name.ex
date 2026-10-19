defmodule PhoenixKit.API.ClientName do
  @moduledoc """
  The name an MCP client gives a server of this site: the project title as a slug.

  The admin API guide appends `-admin` to it and the shop guide gives it as is, so the
  two servers of one site sit side by side in one client.
  """

  alias PhoenixKit.Utils.Slug

  @max_length 32
  @fallback "shop"

  @doc """
  The slug of a project title: lowercase `[a-z0-9-]`, romanized, at most 32 characters,
  never ending in a dash. A title with nothing to slug (an unromanizable script, blank,
  `nil`) gives `"shop"`.
  """
  @spec slug(String.t() | nil) :: String.t()
  def slug(title) do
    case Slug.slugify(title, max_length: @max_length) do
      "" -> @fallback
      slug -> slug
    end
  end
end
