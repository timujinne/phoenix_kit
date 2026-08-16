defmodule PhoenixKitWeb.Components.Core.CrawlerMetas do
  @moduledoc """
  Head metas owned by the Crawlers module: the global `noindex, nofollow`
  directive and search-engine verification tags.

  Self-contained on purpose — it reads the settings itself (ETS-cached), so it
  works in ANY root layout with zero assigns, exactly like
  `phoenix_kit_favicon`. That matters because most installs render the head in
  the HOST app's root layout, where core's assigns don't reach: an assign-based
  meta in core's own layout files renders only on installs using core's shells.
  Embed in a host root layout's `<head>`:

      <PhoenixKitWeb.Components.Core.CrawlerMetas.crawler_metas />

  The noindex directive renders whenever it is set, **not** gated on the
  module toggle: it is a safety switch, and the long-standing contract (pinned
  by `auth_crawlers_no_index_test`) is that a set directive is honored — a
  disabled module must not silently expose a staging site to indexing.
  (`disable_module/0` clears the directive through the API; this covers state
  written around it.) The verification metas ARE module-gated — they are new
  behavior, and module off means off. Never raises — with no database
  (installer context) it degrades to empty.
  """

  use Phoenix.Component

  alias PhoenixKit.Modules.Crawlers

  @doc """
  Robots directive and verification meta tags, from current Crawlers settings.
  """
  def crawler_metas(assigns) do
    {no_index, verifications} = read_state()

    assigns =
      assigns
      |> assign(:no_index, no_index)
      |> assign(:verifications, verifications)

    ~H"""
    <%= if @no_index do %>
      <meta name="robots" content="noindex,nofollow" />
      <meta name="googlebot" content="noindex,nofollow" />
    <% end %>
    <meta :for={{name, content} <- @verifications} name={name} content={content} />
    """
  end

  defp read_state do
    verifications = if Crawlers.module_enabled?(), do: Crawlers.verification_metas(), else: []
    {Crawlers.no_index_enabled?(), verifications}
  rescue
    _ -> {false, []}
  catch
    :exit, _ -> {false, []}
  end
end
