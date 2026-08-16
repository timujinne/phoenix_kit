defmodule PhoenixKit.Modules.Crawlers.LlmsTxt do
  @moduledoc """
  Builds the `/llms.txt` document — a markdown summary telling AI assistants
  what this site is about ([llmstxt.org](https://llmstxt.org/)).

  Where `robots.txt` is about *keeping bots out*, `llms.txt` is the opposite
  half of bot policy: making the site legible to the AI tools the operator
  *wants* reading it. The generated document is:

      # <project title>

      <operator-provided extra markdown, verbatim>

  The head is generated from Settings so a fresh install serves something
  truthful with zero configuration; the tail is the operator's, edited on the
  Crawlers settings page and stored as a setting. There is deliberately no
  generated `> summary` blockquote — llmstxt.org allows one, but core has no
  setting that says what the site *is*, and a fabricated line is worse than
  none. Serving happens in
  `PhoenixKit.Modules.Crawlers.Web.Controller`, at the site root and under the
  kit prefix — the root is where tools look, same reasoning as `/sitemap.xml`.
  """

  alias PhoenixKit.Modules.Crawlers
  alias PhoenixKit.Settings

  @doc """
  Build the llms.txt contents from current settings.
  """
  @spec build() :: String.t()
  def build do
    build_for(Settings.get_project_title(), Crawlers.llms_txt_extra())
  end

  @doc """
  Pure variant used by tests: build from explicit title and extra markdown.
  """
  @spec build_for(String.t() | nil, String.t() | nil) :: String.t()
  def build_for(title, extra) do
    title = presence(title) || "This site"
    extra = String.trim(extra || "")

    head = "# #{title}\n"

    tail =
      case extra do
        "" -> ""
        markdown -> "\n" <> markdown <> "\n"
      end

    head <> tail
  end

  defp presence(nil), do: nil

  defp presence(value) when is_binary(value) do
    case String.trim(value) do
      "" -> nil
      trimmed -> trimmed
    end
  end
end
