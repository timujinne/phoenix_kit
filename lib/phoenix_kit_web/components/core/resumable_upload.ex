defmodule PhoenixKitWeb.Components.Core.ResumableUpload do
  @moduledoc """
  The wrapper that makes a `live_file_input` resumable.

  See `PhoenixKitWeb.ResumableUploads` for the rules a host must follow
  (required `scope`, form with `id` and `phx-change`, untrusted `context`,
  at-least-once delivery, an explicit outcome for every file).

  Renders the element that carries the `ResumableUpload` hook, and — when the
  hook found files that need a person's decision — a "Resume upload" row with
  buttons. The hook watches the file inputs inside this element; with
  `watch="parent"` it watches the element's parent instead and the slot stays
  empty (for a template where the inputs are rendered elsewhere in the
  surrounding block).
  """
  use Phoenix.Component
  use Gettext, backend: PhoenixKitWeb.Gettext

  require Logger

  attr :upload, Phoenix.LiveView.UploadConfig, required: true

  attr :resumable, :map,
    required: true,
    doc: "the `@resumable_uploads` assign set by `allow_resumable_upload/4`"

  attr :scope, :string,
    required: true,
    doc: "what the files belong to; never the URL (e.g. \"photos|<record uuid>\")"

  attr :user, :string, required: true, doc: "uuid of the signed-in user"
  attr :context, :string, default: "", doc: "opaque host token read when a file is picked"
  attr :fresh_ms, :integer, default: 1_800_000, doc: "0 turns automatic continuation off"
  attr :watch, :string, default: "self", values: ["self", "parent"]
  attr :class, :string, default: nil
  slot :inner_block

  def resumable_upload(assigns) do
    case Map.fetch(assigns.resumable, assigns.upload.name) do
      {:ok, %{ask: ask}} ->
        assigns
        |> assign(:ask, ask)
        |> assign(:dom_id, dom_id(assigns))
        |> render_hook()

      :error ->
        Logger.warning(
          "resumable_upload: #{inspect(assigns.upload.name)} was not set up with allow_resumable_upload/4"
        )

        ~H"""
        {render_slot(@inner_block)}
        """
    end
  end

  defp render_hook(assigns) do
    ~H"""
    <div
      id={@dom_id}
      phx-hook="ResumableUpload"
      data-upload={@upload.name}
      data-scope={@scope}
      data-user={@user}
      data-context={@context}
      data-fresh-ms={@fresh_ms}
      data-watch={@watch}
      class={@class}
    >
      {render_slot(@inner_block)}
      <div
        :if={@ask != []}
        id={@dom_id <> "-ask"}
        class="alert alert-warning flex flex-wrap items-center gap-2 text-sm"
      >
        <span class="flex-1 min-w-0">
          {gettext("Resume upload (%{count})", count: length(@ask))}
          <span :if={Enum.any?(@ask, &(not &1.has_bytes))} class="block text-xs opacity-70">
            {gettext("Some files were not kept — choose them again.")}
          </span>
        </span>
        <button
          type="button"
          id={@dom_id <> "-resume"}
          class="btn btn-xs btn-primary"
          phx-click="pk_upload_resume_click"
          phx-value-upload={@upload.name}
        >
          {gettext("Resume")}
        </button>
        <button
          type="button"
          id={@dom_id <> "-discard"}
          class="btn btn-xs btn-ghost"
          phx-click="pk_upload_discard"
          phx-value-upload={@upload.name}
        >
          {gettext("Discard")}
        </button>
      </div>
    </div>
    """
  end

  defp dom_id(assigns),
    do: "pk-resumable-#{assigns.upload.name}-#{:erlang.phash2(assigns.scope)}"
end
