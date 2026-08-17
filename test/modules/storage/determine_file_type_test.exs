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

  describe "determine_mime_type/1 — the ext→mime fallback for callers with no observed mime" do
    test "knows audio types" do
      # The hand-rolled map this replaced had NO audio entries: every mp3 was
      # stored — and served — as application/octet-stream.
      assert Storage.determine_mime_type("mp3") == "audio/mpeg"
      assert Storage.determine_mime_type("wav") == "audio/wav"
    end

    test "covers the extensions the mime library itself answers octet-stream for" do
      # The same known-blind set @audio_extensions exists for on the classifier
      # side. If a future mime lib learns these, the assertions still hold —
      # the fallback map only fills holes.
      assert Storage.determine_mime_type("m4a") == "audio/mp4"
      assert Storage.determine_mime_type("flac") == "audio/flac"
      assert Storage.determine_mime_type("opus") == "audio/opus"
      assert Storage.determine_mime_type("weba") == "audio/webm"
    end

    test "tolerates the leading dot Path.extname/1-based callers pass" do
      assert Storage.determine_mime_type(".mp3") == "audio/mpeg"
      assert Storage.determine_mime_type(".jpg") == "image/jpeg"
    end

    test "ignores case and answers octet-stream for the truly unknown" do
      assert Storage.determine_mime_type("PNG") == "image/png"
      assert Storage.determine_mime_type("xyz") == "application/octet-stream"
    end
  end

  describe "display_file_type/1" do
    test "a generic claim contradicted by the row's own mime loses" do
      # The live corruption this exists for: an upload path hardcoded "image"
      # for everything its picker accepted, .mov included.
      assert Storage.display_file_type(%{
               file_type: "image",
               mime_type: "video/quicktime",
               original_file_name: "clip.mov"
             }) == "video"
    end

    test "an octet-stream mime falls through to the filename evidence" do
      assert Storage.display_file_type(%{
               file_type: "image",
               mime_type: "application/octet-stream",
               original_file_name: "song.mp3"
             }) == "audio"
    end

    test "the claim survives when the evidence agrees or is absent" do
      assert Storage.display_file_type(%{
               file_type: "image",
               mime_type: "image/png",
               original_file_name: "photo.png"
             }) == "image"

      # No verdict from mime or filename — the caller may know more than the
      # classifier, so "document" stands.
      assert Storage.display_file_type(%{
               file_type: "document",
               mime_type: "application/x-thing",
               original_file_name: "blob.xyz"
             }) == "document"
    end

    test "system types are never second-guessed" do
      # "tile" is chosen by internal machinery; mime evidence saying "image"
      # is exactly what a tile looks like and must not reclassify it.
      assert Storage.display_file_type(%{
               file_type: "tile",
               mime_type: "image/png",
               original_file_name: "0_0.png"
             }) == "tile"
    end

    test "a missing claim takes the evidence, or 'other' without any" do
      assert Storage.display_file_type(%{
               file_type: nil,
               mime_type: "audio/mpeg",
               original_file_name: "song.mp3"
             }) == "audio"

      assert Storage.display_file_type(%{
               file_type: nil,
               mime_type: nil,
               original_file_name: "blob"
             }) == "other"
    end

    test "accepts a File struct and the display maps' :filename / :file_name keys" do
      assert Storage.display_file_type(%PhoenixKit.Modules.Storage.File{
               file_type: "image",
               mime_type: "video/mp4",
               original_file_name: "movie.mp4"
             }) == "video"

      # The grid/list display maps carry :filename, not :original_file_name.
      assert Storage.display_file_type(%{
               file_type: "image",
               mime_type: "application/octet-stream",
               filename: "song.m4a"
             }) == "audio"

      assert Storage.display_file_type(%{
               file_type: "image",
               mime_type: "application/octet-stream",
               file_name: "abc123.flac"
             }) == "audio"
    end
  end
end
