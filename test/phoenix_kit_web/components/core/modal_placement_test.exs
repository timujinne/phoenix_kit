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

  test "close_guard defaults to the confirm guard; :input and nil are opt-ins" do
    assigns = %{}

    strict =
      rendered_to_string(~H"""
      <.modal show={true} on_close="close" close_guard={:input}>body</.modal>
      """)

    plain =
      rendered_to_string(~H"""
      <.modal show={true} on_close="close">body</.modal>
      """)

    off =
      rendered_to_string(~H"""
      <.modal show={true} on_close="close" close_guard={nil}>body</.modal>
      """)

    assert strict =~ ~s(data-close-guard="input")
    assert plain =~ ~s(data-close-guard="confirm")
    refute off =~ "data-close-guard"
  end

  describe "content max-height" do
    alias PhoenixKitWeb.Components.Core.Modal

    test "a vh height is also given in dvh, the height actually visible on a phone" do
      assert Modal.max_height_style("70vh") == "max-height: 70vh; max-height: 70dvh"
      assert Modal.max_height_style("62.5vh") == "max-height: 62.5vh; max-height: 62.5dvh"
    end

    test "other units pass through" do
      assert Modal.max_height_style("400px") == "max-height: 400px"
      assert Modal.max_height_style("calc(100% - 2rem)") == "max-height: calc(100% - 2rem)"
    end

    test "the default renders both declarations" do
      assigns = %{}

      html =
        rendered_to_string(~H"""
        <Modal.modal show on_close="close">body</Modal.modal>
        """)

      assert html =~ "max-height: 70vh; max-height: 70dvh"
    end
  end

  test "actions_class merges onto the actions row; without it the row is as before" do
    assigns = %{}

    html =
      rendered_to_string(~H"""
      <.modal show={true} on_close="close" actions_class="flex-wrap">
        body
        <:actions><button>Cancel</button></:actions>
      </.modal>
      """)

    assert html =~ ~s(class="modal-action flex-shrink-0 mt-4 flex-wrap")

    plain =
      rendered_to_string(~H"""
      <.modal show={true} on_close="close">
        body
        <:actions><button>Cancel</button></:actions>
      </.modal>
      """)

    assert plain =~ ~s(class="modal-action flex-shrink-0 mt-4")
  end
end
