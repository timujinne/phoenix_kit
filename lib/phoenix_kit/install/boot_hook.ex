# Igniter-only helper: every caller is a `mix phoenix_kit.*` igniter task,
# which is itself guarded the same way. Igniter is an OPTIONAL dependency
# (see mix.exs), so a host that scopes it to `only: [:dev, :test]` compiles
# :prod without it — unguarded, this module emitted
# "Igniter.X is undefined" warnings on every production build.
if Code.ensure_loaded?(Igniter) do
  defmodule PhoenixKit.Install.BootHook do
    @moduledoc """
    Wires `PhoenixKit.boot/1` into the parent app's `Application.start/2`.

    `PhoenixKit.boot/1` rescans for late-loading `:phoenix_kit_<x>` deps and
    runs registered modules' `migrate_legacy/0`. It must be called after
    `Supervisor.start_link/2` succeeds.

    Idempotent — if `PhoenixKit.boot` is already present in the file, this
    helper is a no-op. Called from both `mix phoenix_kit.install` and
    `mix phoenix_kit.update`.

    ## Standard form

    Matches the canonical Phoenix generator output:

        Supervisor.start_link(children, opts)

    and rewrites it to:

        Supervisor.start_link(children, opts) |> PhoenixKit.boot()

    Non-standard shapes (custom variable names, piped form, calls wrapped
    in `case`/`with`) are left untouched and surface as an Igniter warning
    with manual-edit instructions.
    """
    use PhoenixKit.Install.IgniterCompat

    alias PhoenixKit.Install.IgniterHelpers

    @standard_call ~r/Supervisor\.start_link\(children,\s*opts\)/

    @doc """
    Add the `PhoenixKit.boot/1` call to the parent app's `Application.start/2`.

    Returns the igniter unchanged when:
      * The parent app has no `lib/<app>/application.ex` (unusual setup)
      * `PhoenixKit.boot` is already in the file (idempotent re-run)
    """
    def add_boot_hook(igniter) do
      app_name = IgniterHelpers.get_parent_app_name(igniter)
      app_file = "lib/#{app_name}/application.ex"

      cond do
        not File.exists?(app_file) ->
          igniter

        already_wired?(app_file) ->
          igniter

        true ->
          wire_in(igniter, app_file)
      end
    end

    defp already_wired?(app_file) do
      app_file
      |> File.read!()
      |> String.contains?("PhoenixKit.boot")
    end

    defp wire_in(igniter, app_file) do
      content = File.read!(app_file)

      if Regex.match?(@standard_call, content) do
        igniter
        |> Igniter.update_file(app_file, fn source ->
          rewritten =
            Regex.replace(
              @standard_call,
              Rewrite.Source.get(source, :content),
              "Supervisor.start_link(children, opts) |> PhoenixKit.boot()",
              global: false
            )

          Rewrite.Source.update(source, :content, rewritten)
        end)
      else
        Igniter.add_warning(igniter, manual_instructions(app_file))
      end
    end

    defp manual_instructions(app_file) do
      """
      PhoenixKit could not automatically wire `PhoenixKit.boot/1` into
      #{app_file} — your `Supervisor.start_link/2` call uses a non-standard form.

      Please add `|> PhoenixKit.boot()` at the end of `start/2` manually:

          def start(_type, _args) do
            children = [...]
            opts = [strategy: :one_for_one, name: MyApp.Supervisor]
            Supervisor.start_link(children, opts) |> PhoenixKit.boot()
          end

      Without this call, late-loading `:phoenix_kit_<x>` modules may not appear
      in the admin Modules page until you restart the server (and even then,
      only intermittently).
      """
    end
  end
end
