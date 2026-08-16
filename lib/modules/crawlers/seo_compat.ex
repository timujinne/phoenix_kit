defmodule PhoenixKit.Modules.SEO do
  @moduledoc """
  Deprecated alias for `PhoenixKit.Modules.Crawlers`.

  The built-in SEO module was renamed in V172 — everything it held was bot
  policy (noindex directive, crawler guidance), and the SEO name now belongs
  to the external `phoenix_kit_seo` package. This shim keeps host code that
  called the old module compiling and working; new code should call
  `PhoenixKit.Modules.Crawlers`.

  Deliberately NOT a `PhoenixKit.Module` — registering it would put a second
  module behind the `crawlers` key and reintroduce the registry shadowing the
  rename removed.
  """

  alias PhoenixKit.Modules.Crawlers

  @deprecated "Use PhoenixKit.Modules.Crawlers.module_enabled?/0"
  defdelegate module_enabled?, to: Crawlers

  @deprecated "Use PhoenixKit.Modules.Crawlers.enable_module/0"
  defdelegate enable_module, to: Crawlers

  @deprecated "Use PhoenixKit.Modules.Crawlers.disable_module/0"
  defdelegate disable_module, to: Crawlers

  @deprecated "Use PhoenixKit.Modules.Crawlers.no_index_enabled?/0"
  defdelegate no_index_enabled?, to: Crawlers

  @deprecated "Use PhoenixKit.Modules.Crawlers.enable_no_index/0"
  defdelegate enable_no_index, to: Crawlers

  @deprecated "Use PhoenixKit.Modules.Crawlers.disable_no_index/0"
  defdelegate disable_no_index, to: Crawlers

  @deprecated "Use PhoenixKit.Modules.Crawlers.update_no_index/1"
  defdelegate update_no_index(enabled?), to: Crawlers

  @deprecated "Use PhoenixKit.Modules.Crawlers.get_config/0"
  defdelegate get_config, to: Crawlers
end
