# Igniter-only helper: every caller is a `mix phoenix_kit.*` igniter task,
# which is itself guarded the same way. Igniter is an OPTIONAL dependency
# (see mix.exs), so a host that scopes it to `only: [:dev, :test]` compiles
# :prod without it — unguarded, this module emitted a wall of
# "Igniter.X is undefined" warnings on every production build.
if Code.ensure_loaded?(Igniter) do
  defmodule PhoenixKit.Install.EndpointIntegration do
    @moduledoc """
    Endpoint integration for PhoenixKit installation.

    Previously, this module added the `phoenix_kit_socket()` macro to the parent app's
    endpoint. This is no longer needed as the Sync websocket is now handled automatically
    via `phoenix_kit_routes()` in the router.

    This module now removes any existing deprecated `phoenix_kit_socket()` calls from
    endpoints during installation/updates.
    """
    use PhoenixKit.Install.IgniterCompat

    alias Igniter.Code.{Common, Function}
    alias Igniter.Project.Application
    alias Igniter.Project.Deps
    alias Igniter.Project.Module, as: IgniterModule
    alias PhoenixKit.Install.IgniterHelpers

    # PDF.js viewer assets are vendored in phoenix_kit_catalogue's
    # `priv/static/pdfjs/` and the host endpoint must serve them at
    # `/_pdfjs/` for the catalogue PDF viewer to load. Mounted only when the
    # catalogue module is a dependency.
    @pdfjs_static_mount """
    plug Plug.Static,
      at: "/_pdfjs",
      from: {:phoenix_kit_catalogue, "priv/static/pdfjs"},
      gzip: false\
    """

    @doc """
    Removes deprecated `phoenix_kit_socket()` and its import from the endpoint.

    The `phoenix_kit_socket()` macro is deprecated. Sync websocket is now handled
    automatically via `phoenix_kit_routes()` in the router.

    ## Parameters
    - `igniter` - The igniter context

    ## Returns
    Updated igniter with deprecated socket code and import removed.
    """
    def add_endpoint_integration(igniter) do
      igniter =
        case find_endpoint(igniter) do
          {igniter, nil} ->
            # No endpoint found, nothing to clean up
            igniter

          {igniter, endpoint_module} ->
            igniter
            |> remove_deprecated_socket(endpoint_module)
            |> remove_deprecated_import(endpoint_module)
        end

      add_pdfjs_static_mount(igniter)
    end

    @doc """
    Ensures the host endpoint serves phoenix_kit_catalogue's vendored PDF.js
    viewer at `/_pdfjs/` via a `Plug.Static` mount.

    Only added when `:phoenix_kit_catalogue` is a dependency (the mount
    references that app's `priv`, so adding it without the dep would break
    boot). Idempotent — skips when an `at: "/_pdfjs"` mount already exists.
    Called by both `mix phoenix_kit.install` and `mix phoenix_kit.update`.
    """
    def add_pdfjs_static_mount(igniter) do
      with true <- Deps.has_dep?(igniter, :phoenix_kit_catalogue),
           {igniter, endpoint_module} when not is_nil(endpoint_module) <- find_endpoint(igniter),
           {igniter, source, _zipper} <- IgniterModule.find_module!(igniter, endpoint_module),
           false <- source |> Rewrite.Source.get(:content) |> String.contains?(~s(at: "/_pdfjs")) do
        IgniterModule.find_and_update_module!(igniter, endpoint_module, fn zipper ->
          case move_to_endpoint_use(zipper) do
            {:ok, use_zipper} ->
              {:ok, Common.add_code(use_zipper, @pdfjs_static_mount, placement: :after)}

            :error ->
              {:ok, zipper}
          end
        end)
      else
        # No catalogue dep, no endpoint, or mount already present.
        _ -> igniter
      end
    end

    # Locate `use Phoenix.Endpoint, otp_app: ...` so the static mount can be
    # inserted right after it (early in the plug pipeline).
    defp move_to_endpoint_use(zipper) do
      Function.move_to_function_call(zipper, :use, 2, fn call_zipper ->
        case Function.move_to_nth_argument(call_zipper, 0) do
          {:ok, arg_zipper} -> Common.nodes_equal?(arg_zipper, Phoenix.Endpoint)
          :error -> false
        end
      end)
    end

    # Find endpoint module
    defp find_endpoint(igniter) do
      case Application.app_name(igniter) do
        :phoenix_kit ->
          {igniter, nil}

        _app_name ->
          endpoint_module = IgniterHelpers.get_parent_app_module_web_endpoint(igniter)

          case IgniterModule.module_exists(igniter, endpoint_module) do
            {true, igniter} ->
              {igniter, endpoint_module}

            {false, igniter} ->
              {igniter, nil}
          end
      end
    end

    # Remove phoenix_kit_socket() if it exists
    defp remove_deprecated_socket(igniter, endpoint_module) do
      IgniterModule.find_and_update_module!(igniter, endpoint_module, fn zipper ->
        case Function.move_to_function_call(zipper, :phoenix_kit_socket, 0) do
          {:ok, socket_zipper} ->
            # Remove the deprecated phoenix_kit_socket() call
            zipper_after_removal = Sourceror.Zipper.remove(socket_zipper)
            {:ok, zipper_after_removal}

          :error ->
            # phoenix_kit_socket() not found, nothing to remove
            {:ok, zipper}
        end
      end)
    end

    # Remove import PhoenixKitWeb.Integration if it exists
    defp remove_deprecated_import(igniter, endpoint_module) do
      IgniterModule.find_and_update_module!(igniter, endpoint_module, fn zipper ->
        case find_integration_import(zipper) do
          {:ok, import_zipper} ->
            # Remove the deprecated import
            zipper_after_removal = Sourceror.Zipper.remove(import_zipper)
            {:ok, zipper_after_removal}

          :error ->
            # Import not found, nothing to remove
            {:ok, zipper}
        end
      end)
    end

    # Find import PhoenixKitWeb.Integration
    defp find_integration_import(zipper) do
      Function.move_to_function_call(zipper, :import, 1, fn call_zipper ->
        case Function.move_to_nth_argument(call_zipper, 0) do
          {:ok, arg_zipper} -> Common.nodes_equal?(arg_zipper, PhoenixKitWeb.Integration)
          :error -> false
        end
      end)
    end
  end
end
