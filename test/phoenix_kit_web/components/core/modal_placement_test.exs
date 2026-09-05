defmodule PhoenixKitWeb.Components.Core.ModalPlacementTest do
  @moduledoc """
  Render tests for `<.modal>`'s `placement` (the `:end` drawer — a
  full-height sheet on the right edge for forms opened over their page)
  and the `phx-value-*` pass-through the `PkDialog` hook forwards with
  its close push.
  """
  use ExUnit.Case, async: true

  import Phoenix.LiveViewTest, only: [rendered_to_string: 1]
  import Phoenix.Component, only: [sigil_H: 2]
  import PhoenixKitWeb.Components.Core.Modal, only: [modal: 1]

  test "the default placement is the centered box with a capped content height" do
    assigns = %{}

    html =
      rendered_to_string(~H"""
      <.modal show={true} on_close="close">
        body
      </.modal>
      """)

    assert html =~ ~s(class="modal")
    refute html =~ "modal-end"
    assert html =~ "max-height: 70vh"
    refute html =~ "h-full"
  end

  test "placement=:end renders daisyUI's end sheet, full height, content scrolling inside" do
    assigns = %{}

    html =
      rendered_to_string(~H"""
      <.modal show={true} on_close="close" placement={:end} max_width="2xl">
        <:title>Add task</:title>
        body
      </.modal>
      """)

    assert html =~ ~s(class="modal modal-end")
    assert html =~ "h-full"
    assert html =~ "max-w-2xl"
    # No max-height cap: the sheet fills the viewport and the content
    # column scrolls (min-h-0 lets the flex child shrink).
    refute html =~ "max-height:"
    assert html =~ "min-h-0 overflow-y-auto"
  end

  test "phx-value attributes ride on the dialog for the hook's close push" do
    assigns = %{}

    html =
      rendered_to_string(~H"""
      <.modal show={true} on_close="close_top_modal" id="frame-7" phx-value-frame-ref="7">
        body
      </.modal>
      """)

    assert html =~ ~s(id="frame-7")
    assert html =~ ~s(phx-value-frame-ref="7")
    assert html =~ ~s(data-close-event="close_top_modal")
  end

  test "close_guard arms the hook's client-side input guard; absent by default" do
    assigns = %{}

    guarded =
      rendered_to_string(~H"""
      <.modal show={true} on_close="close" close_guard={:input}>body</.modal>
      """)

    plain =
      rendered_to_string(~H"""
      <.modal show={true} on_close="close">body</.modal>
      """)

    assert guarded =~ ~s(data-close-guard="input")
    refute plain =~ "data-close-guard"
  end
end
