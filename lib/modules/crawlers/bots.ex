defmodule PhoenixKit.Modules.Crawlers.Bots do
  @moduledoc """
  The curated bot registry behind the Crawlers module's per-group access
  controls.

  Bots are grouped by *why they visit*, because that is the axis operators
  actually decide on — allow search engines, block AI training scrapers,
  decide separately about AI assistants:

  | Group | Who | Default |
  |---|---|---|
  | `:search` | Search engine indexers (Googlebot, Bingbot, …) | allowed |
  | `:ai_training` | LLM training-data scrapers (GPTBot, ClaudeBot, CCBot, …) | allowed |
  | `:ai_assistants` | AI search / on-demand fetchers (PerplexityBot, OAI-SearchBot, …) | allowed |
  | `:seo_tools` | SEO backlink/audit crawlers (AhrefsBot, SemrushBot, …) | allowed |
  | `:archivers` | Web archives (Internet Archive) | allowed |

  Everything defaults to **allowed** so that enabling the module changes
  nothing until the operator decides otherwise.

  ## Tokens vs user-agents

  Each bot carries two identities, and they are deliberately separate fields:

    * `:token` — the name robots.txt addresses (`User-agent:` line).
    * `:ua` — a substring found in the bot's actual request `User-Agent`
      header, used by the best-effort application-level blocker. **`nil` for
      robots.txt-only tokens**: `Google-Extended` and `Applebot-Extended` are
      opt-out signals read from robots.txt by crawlers that fetch under their
      main UA (Googlebot / Applebot), so there is no request to block — a UA
      match on them would either never fire or, worse, catch the search
      crawler the operator meant to allow.

  The list is curated, not exhaustive — a registry of every bot on the
  internet goes stale weekly. These are the ones operators ask about.
  """

  @type group :: :search | :ai_training | :ai_assistants | :seo_tools | :archivers

  @type bot :: %{token: String.t(), ua: String.t() | nil}

  @groups [
    %{
      key: :search,
      label: "Search engines",
      description: "Indexers that put the site in search results",
      bots: [
        %{token: "Googlebot", ua: "googlebot"},
        %{token: "Bingbot", ua: "bingbot"},
        %{token: "DuckDuckBot", ua: "duckduckbot"},
        %{token: "YandexBot", ua: "yandexbot"},
        %{token: "Applebot", ua: "applebot"},
        %{token: "Baiduspider", ua: "baiduspider"}
      ]
    },
    %{
      key: :ai_training,
      label: "AI training scrapers",
      description: "Collect pages as training data for AI models",
      bots: [
        %{token: "GPTBot", ua: "gptbot"},
        %{token: "ClaudeBot", ua: "claudebot"},
        %{token: "CCBot", ua: "ccbot"},
        # robots.txt-only opt-out tokens — the crawl arrives under the main
        # search UA, so there is nothing to block at the application layer.
        %{token: "Google-Extended", ua: nil},
        %{token: "Applebot-Extended", ua: nil},
        %{token: "Meta-ExternalAgent", ua: "meta-externalagent"},
        %{token: "Bytespider", ua: "bytespider"},
        %{token: "Amazonbot", ua: "amazonbot"}
      ]
    },
    %{
      key: :ai_assistants,
      label: "AI assistants & AI search",
      description: "Fetch pages to answer a user's question or cite sources",
      bots: [
        %{token: "OAI-SearchBot", ua: "oai-searchbot"},
        %{token: "ChatGPT-User", ua: "chatgpt-user"},
        %{token: "PerplexityBot", ua: "perplexitybot"},
        %{token: "Perplexity-User", ua: "perplexity-user"},
        %{token: "Claude-SearchBot", ua: "claude-searchbot"},
        %{token: "Claude-User", ua: "claude-user"},
        %{token: "DuckAssistBot", ua: "duckassistbot"}
      ]
    },
    %{
      key: :seo_tools,
      label: "SEO tool crawlers",
      description: "Backlink and site-audit bots run by SEO platforms",
      bots: [
        %{token: "AhrefsBot", ua: "ahrefsbot"},
        %{token: "SemrushBot", ua: "semrushbot"},
        %{token: "MJ12bot", ua: "mj12bot"},
        %{token: "DotBot", ua: "dotbot"},
        %{token: "DataForSeoBot", ua: "dataforseobot"}
      ]
    },
    %{
      key: :archivers,
      label: "Web archives",
      description: "Preserve copies of the public web",
      bots: [
        %{token: "ia_archiver", ua: "ia_archiver"},
        %{token: "archive.org_bot", ua: "archive.org_bot"}
      ]
    }
  ]

  @group_keys Enum.map(@groups, & &1.key)

  @doc "All groups, in display order."
  @spec groups() :: [map()]
  def groups, do: @groups

  @doc "The group keys, in display order."
  @spec group_keys() :: [group()]
  def group_keys, do: @group_keys

  @doc "Look up one group by its key (atom or string). Returns nil for unknown keys."
  @spec group(group() | String.t()) :: map() | nil
  def group(key) when is_atom(key), do: Enum.find(@groups, &(&1.key == key))

  def group(key) when is_binary(key) do
    Enum.find(@groups, &(Atom.to_string(&1.key) == key))
  end

  @doc """
  Lowercase UA substrings for the given groups — the match list for the
  application-level blocker. robots.txt-only tokens (`ua: nil`) are excluded.
  """
  @spec ua_fragments([group()]) :: [String.t()]
  def ua_fragments(group_keys) when is_list(group_keys) do
    @groups
    |> Enum.filter(&(&1.key in group_keys))
    |> Enum.flat_map(& &1.bots)
    |> Enum.map(& &1.ua)
    |> Enum.reject(&is_nil/1)
  end
end
