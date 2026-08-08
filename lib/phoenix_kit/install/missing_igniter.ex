defmodule PhoenixKit.Install.MissingIgniter do
  @moduledoc """
  Stand-in for the `mix phoenix_kit.*` tasks that cannot exist without igniter.

  Igniter is an optional dependency (see `mix.exs`), and every task that drives
  it is wrapped in `if Code.ensure_loaded?(Igniter.Mix.Task)`. Without a
  fallback the guard's `else` branch defines nothing at all, so the task simply
  vanishes and Mix reports:

      ** (Mix) The task "phoenix_kit.update" could not be found

  which names neither PhoenixKit nor igniter, and leaves a host stranded on an
  old schema with nothing to search for. This module defines a task that exists
  purely to explain the situation and print the one line to add.

  ## Why the dep is optional at all

  A stock `mix phx.new` app declares `{:igniter, "~> 0.6", only: [:dev, :test]}`.
  A non-optional dep here resolves for all environments, and Mix refuses to
  converge the two — which broke `mix igniter.install phoenix_kit` on every
  freshly generated project. Optional means the host's own declaration wins.

  The cost is this case: a host that never declared igniter itself was getting
  it transitively, and an upgrade drops it. That is what the message covers.
  """

  @doc """
  The guidance printed when a task is invoked without igniter available.
  """
  @spec message(String.t()) :: String.t()
  def message(task) do
    """
    `mix #{task}` needs the :igniter dependency, which is not available in this project.

    PhoenixKit declares igniter as an OPTIONAL dependency so that it converges with
    the `{:igniter, "~> 0.6", only: [:dev, :test]}` that `mix phx.new` generates.
    The trade-off is that a project which never declared igniter itself does not
    get it from PhoenixKit either.

    Add it to your mix.exs deps and re-run:

        {:igniter, "~> 0.7", only: [:dev, :test]}

    then:

        mix deps.get
        mix #{task}

    Everything that does not generate or patch code — `mix phoenix_kit.status`,
    `mix phoenix_kit.gen.migration`, `mix phoenix_kit.assets.rebuild` — works
    without igniter and is unaffected.
    """
  end

  @doc """
  Defines the body of a stand-in task. The caller supplies its own
  `@moduledoc` — generating one from here would hide it from static analysis.
  """
  defmacro __using__(opts) do
    task = Keyword.fetch!(opts, :task)
    helper = __MODULE__

    quote do
      use Mix.Task

      @shortdoc "Unavailable — requires the optional :igniter dependency"

      @impl Mix.Task
      def run(_args), do: Mix.raise(unquote(helper).message(unquote(task)))
    end
  end
end
