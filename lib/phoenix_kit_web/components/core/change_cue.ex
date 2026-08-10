defmodule PhoenixKitWeb.Components.Core.ChangeCue do
  @moduledoc """
  Tells the reader that a choice they just made changed something they
  can't currently see.

  Long forms hide detail behind collapsed sections, and a choice in one
  place often rewrites another: picking a preset rewrites a checklist,
  enabling an extension adds a permission row. The change is real,
  correct, and invisible — it lands inside something nobody is looking at.

  Deliberately NOT called "flash": Phoenix already has flash messages,
  and the capability is "something over here changed", not an animation.

  ## Using it

  Mark the regions that can be cued — `<.accordion cue>` does this, or add
  `data-change-region` to any container yourself — give the things inside
  stable DOM ids, and push the ids that changed:

      # in the LiveView, after working out what actually changed
      {:noreply, ChangeCue.push(socket, ["ext-row-files", "authz-row-upload_files"],
        announce: gettext("Permissions updated"))}

  The server says WHAT changed. The client decides how to show it, because
  only the client knows what is on screen:

    * the region is open → the changed rows highlight;
    * the region is closed → the region highlights AND keeps a quiet
      "changed" marker. Opening it replays the row highlights and clears
      the marker.

  The marker is what makes this survive reality: a highlight that plays
  while the reader is scrolled elsewhere is simply lost, and a timer that
  forgets after N seconds turns "what changed here?" into a race. The
  marker persists until the region is opened.

  ## What it will not do

  Scroll the page, open a section, move focus, or raise a toast. A cue
  that moves the page under someone mid-form is worse than no cue.

  ## Accessibility

  A pulse tells a screen-reader user nothing, so a closed-region cue also
  writes to a polite live region — the region's own words (`:announce`),
  once per push, coalesced. Never assertive, never per-row, and never
  repeated when the deferred highlights replay.

  `prefers-reduced-motion` keeps the outline and the marker, drops the
  pulse.
  """

  use Phoenix.Component

  @event "pk:change-cue"
  @seen_event "pk_cue_seen"

  @doc """
  Cues the elements whose ids are given.

  Two forms:

      # ids alone — the client finds each one's region itself
      ChangeCue.push(socket, ["ext-row-files"])

      # grouped by the region that CONTAINS them
      ChangeCue.push(socket, %{"create-people" => ["authz-row-comment"]})

  Group them when a change can make the element **disappear**. A row that
  was removed cannot be found, and neither can the region around it, so a
  plain id yields no cue at all — precisely when something visibly
  vanished and the reader most needs telling. With a region named, the
  client falls back to cueing that.

  This is not the server deciding how to show the change: the client still
  chooses rows-versus-region from what is actually on screen. The region
  is provenance the DOM can no longer answer for itself.

  Options:

    * `:announce` — what a screen reader should hear when the change lands
      in a CLOSED region. Say the result ("Permissions updated"), not the
      mechanics. Omit it and nothing is announced.

  A push with nothing in it is a no-op, so callers can pipe an empty diff
  through without a conditional.
  """
  @spec push(Phoenix.LiveView.Socket.t(), [String.t()] | %{String.t() => [String.t()]}, keyword()) ::
          Phoenix.LiveView.Socket.t()
  def push(socket, ids, opts \\ [])

  def push(socket, [], _opts), do: socket

  def push(socket, ids, _opts) when is_map(ids) and map_size(ids) == 0, do: socket

  def push(socket, ids, opts) when is_map(ids) do
    ids
    |> Enum.flat_map(fn {region, target_ids} ->
      Enum.map(target_ids, &%{id: &1, region: region})
    end)
    |> do_push(socket, opts)
  end

  def push(socket, ids, opts) when is_list(ids) do
    ids
    |> Enum.map(&%{id: &1})
    |> do_push(socket, opts)
  end

  defp do_push(targets, socket, opts) do
    targets = Enum.uniq_by(targets, & &1.id)
    payload = %{targets: targets}

    payload =
      case Keyword.get(opts, :announce) do
        text when is_binary(text) and text != "" -> Map.put(payload, :announce, text)
        _ -> payload
      end

    if targets == [] do
      socket
    else
      Phoenix.LiveView.push_event(socket, @event, payload)
    end
  end

  @doc "The client event name, exposed so consumers can assert on it."
  @spec event() :: String.t()
  def event, do: @event

  @doc """
  The event a cued region pushes when the reader OPENS it, carrying
  `%{"region" => id}`.

  Handle it and reset that region's baseline:

      def handle_event(ChangeCue.seen_event(), %{"region" => region}, socket) do
        {:noreply, mark_region_seen(socket, region)}
      end

  Without it a marker means "something happened", which accumulates into a
  lie: flip a preset back and forth and every section ends up marked even
  though nothing differs from where you started. Diff against what the
  reader last SAW, and returning to the original state clears the marks by
  itself.
  """
  @spec seen_event() :: String.t()
  def seen_event, do: @seen_event

  @doc """
  Tells the client a region has nothing to show any more — its state went
  back to what the reader last saw. Clears the marker and any rows queued
  for replay.
  """
  @spec clear(Phoenix.LiveView.Socket.t(), [String.t()]) :: Phoenix.LiveView.Socket.t()
  def clear(socket, []), do: socket

  def clear(socket, regions) when is_list(regions) do
    Phoenix.LiveView.push_event(socket, @event, %{targets: [], clear: regions})
  end

  @doc """
  The marker shown on a closed region that changed while it was closed.

  Rendered inside the region's own summary by `<.accordion cue>`; it stays
  hidden until the client sets `data-changed` on the region, and the CSS
  lives in the same stylesheet as the highlight so a consumer adds nothing.
  """
  attr :label, :string, default: nil

  def change_marker(assigns) do
    assigns = assign_new(assigns, :label, fn -> "Updated" end)

    ~H"""
    <span data-change-marker class="badge badge-primary badge-sm ml-2 hidden">
      {@label}
    </span>
    """
  end
end
