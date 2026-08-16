defmodule PhoenixKitWeb.Components.Core.FileUploadTest do
  use ExUnit.Case, async: true

  import Phoenix.Component, only: [sigil_H: 2]
  import Phoenix.LiveViewTest, only: [rendered_to_string: 1]
  import PhoenixKitWeb.Components.Core.FileUpload

  defp render(template), do: rendered_to_string(template)

  defp entry(overrides \\ %{}) do
    Map.merge(
      %Phoenix.LiveView.UploadEntry{
        ref: "0",
        upload_ref: "phx-upload-1",
        client_name: "photo.jpg",
        client_size: 12_400_000,
        client_type: "image/jpeg",
        progress: 45
      },
      overrides
    )
  end

  # The UploadStats hook contract: the server renders the element with the
  # entry's size and patches only data-progress; everything else (speed, ETA,
  # the ticking "Processing on server…" phase) is computed in the browser.
  # These pins keep the markup the hook depends on from drifting.
  test "upload_entry_stats renders the UploadStats hook contract" do
    assigns = %{entry: entry()}

    html =
      render(~H"""
      <.upload_entry_stats entry={@entry} />
      """)

    assert html =~ ~s(phx-hook="UploadStats")
    assert html =~ ~s(id="pk-upload-stats-phx-upload-1-0")
    assert html =~ ~s(data-progress="45")
    assert html =~ ~s(data-size="12400000")
    assert html =~ ~s(data-label-processing=)
    assert html =~ ~s(data-label-left=)
    # Pre-mount fallback content: the file size (decimal units, like the
    # media listings).
    assert html =~ "12.4 MB"
  end

  test "upload_entry_stats ids stay unique across uploads and entries" do
    assigns = %{a: entry(), b: entry(%{ref: "1", upload_ref: "phx-upload-2"})}

    html =
      render(~H"""
      <.upload_entry_stats entry={@a} />
      <.upload_entry_stats entry={@b} />
      """)

    assert html =~ ~s(id="pk-upload-stats-phx-upload-1-0")
    assert html =~ ~s(id="pk-upload-stats-phx-upload-2-1")
  end

  test "both file_upload variants render stats for active entries" do
    upload = %Phoenix.LiveView.UploadConfig{
      ref: "phx-upload-1",
      name: :media_files,
      entries: [entry()],
      max_entries: 10
    }

    for variant <- ["full", "button"] do
      assigns = %{upload: upload, variant: variant}

      html =
        render(~H"""
        <.file_upload upload={@upload} variant={@variant} />
        """)

      assert html =~ ~s(phx-hook="UploadStats"), "variant #{variant} lost the stats hook"
      assert html =~ "12.4 MB"
    end
  end
end
