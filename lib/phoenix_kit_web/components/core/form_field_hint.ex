defmodule PhoenixKitWeb.Components.Core.FormFieldHint do
  @moduledoc """
  The help text under a form field — `<.input>`'s and `<.textarea>`'s `hint`.
  """
  use Phoenix.Component

  @doc """
  Renders the hint, with the id `"<id>-help"` the control points at. Renders
  nothing without a hint.
  """
  attr :id, :any, default: nil
  attr :hint, :string, default: nil

  def field_hint(assigns) do
    ~H"""
    <p :if={@hint} id={hint_id(@id)} class="mt-1 text-sm text-base-content/70 break-words">
      {@hint}
    </p>
    """
  end

  @doc """
  Adds the hint's id to the control's `aria-describedby`, after any the caller
  gave. `rest` is the control's global attributes; `assigns` holds `:id` and
  `:hint`. Without a hint (or an id) `rest` is returned as it is.
  """
  @spec describe_by_hint(map(), map()) :: map()
  def describe_by_hint(rest, %{hint: hint, id: id}) when is_binary(hint) and not is_nil(id) do
    Map.update(rest, :"aria-describedby", hint_id(id), &"#{&1} #{hint_id(id)}")
  end

  def describe_by_hint(rest, _assigns), do: rest

  defp hint_id(nil), do: nil
  defp hint_id(id), do: "#{id}-help"
end
