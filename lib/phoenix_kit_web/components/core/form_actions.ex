defmodule PhoenixKitWeb.Components.Core.FormActions do
  @moduledoc """
  Form-footer action bar — Cancel link + Submit button, right-aligned.

  Replaces the repeated boilerplate:

      <div class="flex justify-end gap-3">
        <.link navigate={cancel_path} class="btn btn-ghost">Cancel</.link>
        <button type="submit" class="btn btn-primary" phx-disable-with="Saving…">
          {submit_label}
        </button>
      </div>

  with a single component call.

  ## Cancelling

  There are three ways to render Cancel, and exactly one is used per call —
  precedence is **`:cancel` slot → `cancel_click` → `cancel_to`**. An explicit
  order matters here: without it a form supplying two would render two Cancels,
  or one dead one.

  `cancel_to` was `required: true`, which meant a form inside a LiveComponent —
  where cancelling is a `phx-click` with a `phx-target`, not a navigation — could
  not use this component at all and hand-rolled the whole footer.

      <.form_actions cancel_to={~p"/admin/things"} submit_label="Save" />
      <.form_actions cancel_click="close" cancel_target={@myself} submit_label="Save" />

      <.form_actions submit_label="Save">
        <:cancel>
          <button type="button" phx-click={JS.exec("data-cancel", to: "#dialog")}>Discard</button>
        </:cancel>
      </.form_actions>

  ## Attributes

  - `cancel_to` — Path the Cancel link navigates to.
  - `submit_label` — Text on the submit button (e.g. `"Save"`, `"Create Endpoint"`).
    Required.
  - `submitting_label` — `phx-disable-with` text shown while the form is
    submitting. Defaults to `"Saving…"` (gettext-translated).
  - `submit_icon` — Optional Heroicon name rendered inside the submit
    button (e.g. `"hero-check"`).
  - `submit_class` — Class for the submit button. Default `"btn btn-primary"`.
  - `class` — Extra classes appended to the outer wrapper.

  ## Slots

  - `inner_block` — Optional extra controls rendered BEFORE Cancel + Submit
    (e.g. a secondary "Save and Return" button).

  ## Example

      <.form_actions
        cancel_to={Paths.endpoints()}
        submit_label={if @endpoint, do: gettext("Update"), else: gettext("Create")}
        submit_icon="hero-check"
      />
  """

  use Phoenix.Component
  use Gettext, backend: PhoenixKitWeb.Gettext

  import PhoenixKitWeb.Components.Core.Icon, only: [icon: 1]

  attr :cancel_to, :string,
    default: nil,
    doc: "Path the Cancel link navigates to. Lowest precedence of the three cancel forms."

  attr :cancel_click, :any,
    default: nil,
    doc: "`phx-click` value for Cancel, when cancelling is an event rather than a navigation."

  attr :cancel_target, :any,
    default: nil,
    doc: "`phx-target` for `cancel_click` — required to reach a LiveComponent."

  attr :submit_label, :string, required: true
  attr :submitting_label, :string, default: nil
  attr :submit_icon, :string, default: nil
  attr :submit_class, :string, default: "btn btn-primary"
  attr :class, :string, default: nil

  slot :inner_block, doc: "Extra controls rendered BEFORE Cancel + Submit."

  slot :cancel,
    doc: "Full control over the Cancel control. Highest precedence; suppresses the other two."

  def form_actions(assigns) do
    # `attr :submitting_label, default: nil` always assigns nil when the
    # consumer doesn't pass the attr, so `assign_new` won't fire. Use an
    # explicit `||` fallback to gettext'd default.
    assigns =
      assign(assigns, :submitting_label, assigns[:submitting_label] || gettext("Saving…"))

    ~H"""
    <div class={["flex justify-end gap-3", @class]}>
      {render_slot(@inner_block)}
      <%!-- Exactly one Cancel: slot, then event, then navigation. --%>
      <span :if={@cancel != []} class="[&>*]:btn [&>*]:btn-ghost">
        {render_slot(@cancel)}
      </span>
      <button
        :if={@cancel == [] and @cancel_click}
        type="button"
        class="btn btn-ghost"
        phx-click={@cancel_click}
        phx-target={@cancel_target}
      >
        {gettext("Cancel")}
      </button>
      <.link
        :if={@cancel == [] and is_nil(@cancel_click) and @cancel_to}
        navigate={@cancel_to}
        class="btn btn-ghost"
      >
        {gettext("Cancel")}
      </.link>
      <button type="submit" class={@submit_class} phx-disable-with={@submitting_label}>
        <.icon :if={@submit_icon} name={@submit_icon} class="w-4 h-4 mr-2" />
        {@submit_label}
      </button>
    </div>
    """
  end
end
