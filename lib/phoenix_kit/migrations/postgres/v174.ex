defmodule PhoenixKit.Migrations.Postgres.V174 do
  @moduledoc """
  V174: repair misclassified media rows (file_type / mime_type).

  ## The corruption

  Two writer defects, both since fixed at the write boundary
  (`Storage.store_file_in_buckets/7`), left rows whose stored classification
  contradicts what the file demonstrably is:

    * **`file_type` poisoned by the caller.** The storage writer stored
      whatever `file_type` the call site claimed, unchecked. A live example:
      an external module's upload path hardcoded `"image"` while its picker
      accepted audio and video too — every `.mov` and `.mp3` dropped on a
      board landed as `file_type: "image"`, and the media page trusts that
      column everywhere (broken `<img>` tiles, invisible to the video/audio
      filters, image variant processing run against a QuickTime file).

    * **`mime_type` guessed from a map with no audio entries.** The writer
      discarded the mime the caller observed and re-derived it from the
      extension via a hand-rolled map that knew no audio type at all, so
      every mp3/m4a/wav was stored — and **served** (`file_controller`
      answers with the instance's mime) — as `application/octet-stream`.

  ## The repair

  Same evidence-over-claim rule the write boundary now applies, in SQL:

  1. Rows (files AND file instances) whose mime is blank/octet-stream but
     whose extension is in the known audio set get the real audio mime —
     mirrors `Storage`'s `@audio_mime_fallbacks`.
  2. Files whose (now-repaired) mime contradicts a *generic* `file_type`
     take the mime's classification — mirrors `Storage.determine_file_type/2`'s
     mime branch. Rows with no evidence (unknown mime) keep their claim, and
     non-generic system types (`"tile"`) are never touched: internal
     machinery chose those deliberately and the classifier knows nothing
     about them.

  Width/height/duration and missing variants are NOT backfilled here — the
  variant pipeline owns those, and re-queueing jobs is not a migration's
  business. A repaired row simply renders correctly from now on.

  ## Down

  Deliberately a no-op (marker stamp only). The pre-repair values were
  wrong, there is no record of which rows held them, and re-corrupting data
  is not a rollback anyone wants.
  """

  use Ecto.Migration

  # Mirrors `Storage`'s @audio_mime_fallbacks — the extensions the `mime`
  # library answers octet-stream for. `ltrim(lower(…))` because callers never
  # agreed on whether `ext` carries the leading dot.
  @audio_mime_case """
  CASE ltrim(lower(ext), '.')
    WHEN 'mp3' THEN 'audio/mpeg'
    WHEN 'wav' THEN 'audio/wav'
    WHEN 'ogg' THEN 'audio/ogg'
    WHEN 'oga' THEN 'audio/ogg'
    WHEN 'm4a' THEN 'audio/mp4'
    WHEN 'aac' THEN 'audio/aac'
    WHEN 'flac' THEN 'audio/flac'
    WHEN 'opus' THEN 'audio/opus'
    WHEN 'weba' THEN 'audio/webm'
    WHEN 'mid' THEN 'audio/midi'
    WHEN 'midi' THEN 'audio/midi'
  END
  """

  # Mirrors `Storage.determine_file_type/2`'s mime branch (`classify_mime/1`).
  # NULL when the mime carries no verdict — the WHERE clauses treat that as
  # "no evidence, leave the row alone".
  @classify_mime_case """
  CASE
    WHEN mime_type LIKE 'image/%' THEN 'image'
    WHEN mime_type LIKE 'video/%' THEN 'video'
    WHEN mime_type LIKE 'audio/%' THEN 'audio'
    WHEN mime_type LIKE 'text/%' THEN 'document'
    WHEN mime_type IN (
      'application/pdf',
      'application/msword',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    ) THEN 'document'
    WHEN mime_type LIKE '%zip%' OR mime_type LIKE '%archive%' THEN 'archive'
  END
  """

  def up(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    Enum.each(repair_statements(p), &execute/1)

    # Single-step runs rely on the migration stamping its own marker — the
    # runner only writes it for multi-step ranges.
    execute("COMMENT ON TABLE #{p}phoenix_kit IS '174'")
  end

  # Public (and idempotent) so the test suite can run the REAL statements
  # against seeded misclassified rows — the chain has already been applied to
  # empty tables by the time any test runs, so testing through the migrator
  # would assert nothing. `p` is the rendered prefix including the trailing
  # dot (`prefix_str/1`).
  @doc false
  def repair_statements(p) do
    [
      # 1a. Audio mime repair on file rows.
      """
      UPDATE #{p}phoenix_kit_files
      SET mime_type = #{@audio_mime_case}
      WHERE (mime_type IS NULL OR mime_type IN ('', 'application/octet-stream'))
        AND #{@audio_mime_case} IS NOT NULL
      """,
      # 1b. Same repair on instance rows — these are what `file_controller`
      # serves, so their octet-stream is the one a browser's <audio> tag saw.
      """
      UPDATE #{p}phoenix_kit_file_instances
      SET mime_type = #{@audio_mime_case}
      WHERE (mime_type IS NULL OR mime_type IN ('', 'application/octet-stream'))
        AND #{@audio_mime_case} IS NOT NULL
      """,
      # 2. Reclassify generic file_type claims the mime evidence contradicts.
      # Runs after the mime repair so a resurrected audio/* mime reclassifies
      # its row in the same pass.
      """
      UPDATE #{p}phoenix_kit_files
      SET file_type = #{@classify_mime_case}
      WHERE file_type IN ('image', 'video', 'audio', 'document', 'archive', 'other')
        AND #{@classify_mime_case} IS NOT NULL
        AND file_type IS DISTINCT FROM #{@classify_mime_case}
      """
    ]
  end

  def down(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    # Data repair only — nothing to reverse (see moduledoc). Rollback lands
    # on the version that precedes this one.
    execute("COMMENT ON TABLE #{p}phoenix_kit IS '173'")
  end

  defp prefix_str("public"), do: "public."
  defp prefix_str(prefix), do: "#{prefix}."
end
