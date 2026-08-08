defmodule PhoenixKit.Modules.Storage.DetermineFileTypeTest do
  @moduledoc """
  The classifier behind the `file_type` column, which every media filter
  queries directly (`where file_type == "audio"`).

  It used to be copied into each upload surface — the media browser, the
  selector modal, the full-page selector, the upload controller — and the
  copies drifted: three had no `audio/` clause, so the same mp3 was stored as
  "document" or "other" depending on which dropzone it was dropped on, and the
  audio filter never saw it.
  """
  use ExUnit.Case, async: true

  alias PhoenixKit.Modules.Storage

  describe "determine_file_type/1" do
    test "classifies by mime type" do
      assert Storage.determine_file_type("image/png") == "image"
      assert Storage.determine_file_type("video/mp4") == "video"
      assert Storage.determine_file_type("audio/mpeg") == "audio"
      assert Storage.determine_file_type("text/plain") == "document"
      assert Storage.determine_file_type("application/pdf") == "document"
      assert Storage.determine_file_type("application/zip") == "archive"
      assert Storage.determine_file_type("application/x-thing") == "other"
    end

    test "an unknown mime type is 'other', never a crash on nil" do
      assert Storage.determine_file_type(nil) == "other"
      assert Storage.determine_file_type("") == "other"
    end
  end

  describe "determine_file_type/2 — filename fallback" do
    test "recognises audio the browser reports as application/octet-stream" do
      # What a browser hands LiveView for these two, and what MIME.from_path/1
      # returns for them as well. Both are in the audio picker's `accept` list,
      # so a gate that only reads the mime type refuses a file it just invited.
      assert Storage.determine_file_type("application/octet-stream", "recording.m4a") == "audio"
      assert Storage.determine_file_type("application/octet-stream", "track.flac") == "audio"
    end

    test "falls back to the filename when the browser reports no type at all" do
      assert Storage.determine_file_type(nil, "song.mp3") == "audio"
      assert Storage.determine_file_type("", "song.opus") == "audio"
    end

    test "the mime type still wins when it is meaningful" do
      assert Storage.determine_file_type("image/png", "song.mp3") == "image"
    end

    test "a filename with no known extension is still 'other'" do
      assert Storage.determine_file_type("application/octet-stream", "blob.xyz") == "other"
      assert Storage.determine_file_type("application/octet-stream", "blob") == "other"
    end

    test "extension matching ignores case" do
      assert Storage.determine_file_type("application/octet-stream", "RECORDING.M4A") == "audio"
    end
  end
end
