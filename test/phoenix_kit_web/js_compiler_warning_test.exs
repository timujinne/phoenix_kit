defmodule PhoenixKitWeb.JsCompilerWarningTest do
  @moduledoc """
  The warning that fires when installed modules ship JS hooks the host will
  never load.

  A module declares its bundle with `js_sources/0`, and the only thing that
  consumes that declaration is the `:phoenix_kit_js_sources` compiler. Without
  it in the host's `:compilers` the hooks are simply absent — no error
  anywhere, the module's pages render, and only the half that needed
  JavaScript is missing, so it reads as a broken module rather than as JS that
  never loaded. `phoenix_kit_boards` shipped exactly that state twice before
  anyone traced it.

  Two things are worth pinning, and they pull against each other: it has to
  speak up in that state, and stay silent in every other. A warning that fires
  on correctly-configured hosts gets muted, which puts everyone back where
  they started.
  """
  use ExUnit.Case, async: true

  import ExUnit.CaptureIO

  alias PhoenixKitWeb.Integration

  defp warning(modules, compiler_configured?) do
    capture_io(:stderr, fn ->
      assert Integration.warn_missing_js_compiler(modules, compiler_configured?) == :ok
    end)
  end

  describe "the host is missing the compiler" do
    test "names the modules whose hooks will not load" do
      output = warning([SomeModule.WithHooks, Another.Module], false)

      assert output =~ "will not be loaded"
      assert output =~ "SomeModule.WithHooks"
      assert output =~ "Another.Module"
    end

    test "says what to do about it" do
      # A warning naming a problem and not its fix is a warning people learn
      # to scroll past.
      output = warning([SomeModule.WithHooks], false)

      assert output =~ ":phoenix_kit_js_sources"
      assert output =~ "compilers:"
      assert output =~ "vendor/phoenix_kit_modules.js"
    end

    test "says what the failure looks like, because it looks like nothing" do
      # The reason this is worth a warning at all: there is no error to find
      # later. Someone reading it should recognise the symptom they will hit.
      output = warning([SomeModule.WithHooks], false)

      assert output =~ "no further error"
    end
  end

  describe "silence" do
    test "when the compiler is configured" do
      refute warning([SomeModule.WithHooks], true) =~ "will not be loaded"
    end

    test "when nothing declares a bundle" do
      # A host with no JS-bearing modules has nothing to be warned about,
      # compiler or not.
      assert warning([], false) == ""
      assert warning([], true) == ""
    end
  end

  describe "it stays a warning" do
    test "does not register a compiler diagnostic" do
      # `IO.warn/1` does, and a diagnostic is a build failure on any host
      # compiling with `--warnings-as-errors` — so the check that exists to
      # save people a silent misconfiguration would instead break their CI on
      # upgrade, over a mix.exs condition that is not a regression in their
      # code. Everything else here is guarded against failing a host's
      # compile; this is the same promise.
      {_captured, diagnostics} =
        Code.with_diagnostics(fn ->
          capture_io(:stderr, fn ->
            Integration.warn_missing_js_compiler([SomeModule.WithHooks], false)
          end)
        end)

      assert diagnostics == []
    end
  end

  describe "discovery" do
    test "never fails the host's compile" do
      # This runs while the host's router compiles. Whatever module discovery
      # finds, or fails to find, a warning is not worth taking a build down
      # for.
      assert Integration.warn_missing_js_compiler() == :ok
    end

    test "a throw or exit from a module's js_sources/0 is contained too" do
      # `rescue` alone let a `throw` or an `exit` (a compile-time call into
      # an unstarted process exits) escape the macro expansion and abort the
      # host's compile — precisely what the guarantee above promises cannot
      # happen. Pinned at the source level because the discovery seam is
      # private and dep-driven: what matters is that the containment clause
      # exists next to the rescue.
      source = File.read!("lib/phoenix_kit_web/integration.ex")

      [_, body] =
        Regex.run(
          ~r/defp modules_declaring_js_sources do(.*?)\n  end/s,
          source
        )

      assert body =~ "rescue"

      assert body =~ "catch",
             "modules_declaring_js_sources rescues raises only — a throw/exit " <>
               "from a discovered module's js_sources/0 fails the host's compile"
    end
  end

  describe "a module package compiling its own router" do
    # `phoenix_kit_boards` running its own test suite expands
    # `phoenix_kit_routes()`: discovery finds the package's own beam, and
    # `Mix.Project.config/0` answers for the package — whose mix.exs
    # legitimately has no `:phoenix_kit_js_sources` compiler, because it is
    # not a host. Every compile printed the fix-your-mix.exs warning for a
    # correct configuration. The tell is compile provenance: a host never
    # compiles a js_sources module from its own source tree; a package
    # always does.
    test "its own modules are recognized as locally compiled" do
      # This library's modules ARE the current project while this suite runs.
      assert Integration.compiled_from_current_project?(PhoenixKitWeb.Integration)
    end

    test "dep-compiled modules are not" do
      refute Integration.compiled_from_current_project?(Phoenix.Router)
    end

    test "junk never raises out of the provenance check" do
      refute Integration.compiled_from_current_project?(:not_a_real_module_at_all)
    end
  end
end
