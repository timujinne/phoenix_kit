# Storage / media commits of 2026-10-19 (direct on main)

**Commits:** `288eb3943` stream checksums from disk · `c3402eabc` HEIC tiles + `POST /api/upload` types ·
`cdbf0a97c` tone-map HDR video, short-clip posters · `d412948a4` HLG poster as an Ultra HDR photo
**Author:** Dmitri Don · **Reviewer:** Claude

Storage and integration suites run: 1289 tests + 2 doctests, 0 failures.

## `288eb3943` — FileHash (streamed checksums)

Correct: 1 MiB `:file.read` loop, raw+binary handle closed in `after`, several digests in
one pass, `!` forms keep `File.Error`. Every `File.read!` + `:crypto.hash` site found by
`rg` is converted.

- **BUG - MEDIUM (fixed)** — `FileHash.hashes/3` is typed `{:error, File.posix() | :badarg}`
  but an unknown algorithm made `:crypto.hash_init/1` raise `ErlangError {:badarg, …}`. The
  algorithm list is now checked up front and answers `{:error, :badarg}`; test added.

## `c3402eabc` — HEIC deep zoom (`TileSource`) and `POST /api/upload`

Checked the thing most likely to be wrong: orientation. The file row's `width`/`height` are
the *oriented* size (`ProcessFileJob.extract_image_metadata` → `oriented_info`), and
`ImageProcessor.full_jpeg/3` is `-auto-orient`, so `TileSource.same_size/2` compares like with
like for a portrait iPhone photo. The converted JPEG is a system-managed child of the
original (inherits its library/privacy, cascades with it, never served — the tile route
only addresses `level/col/row`). Cleanup of the temp files is in `after`.

- **IMPROVEMENT - MEDIUM (not changed)** — a conversion that *fails* is not remembered
  (the copy that fails to be *stored* is, by being retried). On a host whose ImageMagick has
  no HEIC delegate, every tile request of such a photo re-runs `identify` and logs a
  warning. It fails fast (the `identify` before the decode), serialized by the tile lock, so
  no amplification of consequence; a negative cache is not worth its invalidation rules yet.
- **IMPROVEMENT - MEDIUM (pre-existing, widened)** — `validate_file_type/1` trusts the
  client's multipart `content_type`, and the stored `mime_type` is that header. The allowlist
  now includes TIFF/BMP/HEIC/AVIF; `TileSource.convert?/1` keys on the stored mime, so a
  wrongly labelled file only picks the other (still safe: ImageMagick sniffs the bytes)
  path. Sniffing the bytes at the endpoint would close the class; left for its own change.
- **NITPICK** — the size cap is checked after Plug.Parsers spooled the body; README already
  says the host's multipart `:length` bounds the request first. Correct, just surprising
  next to a 500 MB default.

## `cdbf0a97c` — HDR video renditions, poster time

Sound. The tone-map falls back to the ordinary rendition with a warning; `yuv420p` is now
forced on H.264/VP9; `run_ffmpeg` turns "success with no file" into an error;
`poster_second/1` is `min(duration/2, 1.0)`.

- **NITPICK** — `VideoSource.probe/1` runs once per rendition (an `ffprobe` per size of
  one video). Cheap next to the encode; probing once in the caller would save N−1 spawns.

## `d412948a4` — HLG poster as an HDR photo (`VideoHdrPoster`)

Every failure path (no `vix`, no `uhdrsave`, bad PFM, a `uhdrsave` error, exception, exit)
answers `{:error, _}` and `:skip`s to the SDR poster; the `.pfm` temp file is removed in
`after`. `read_pfm/1` bounds the frame at 25 M pixels; the regex over a 4K frame
(≈ 100 MB) takes microseconds, so no need for binary pattern matching.

- **NITPICK** — `keep_hdr: true` is only in the *seed* of `video_thumbnail`, so an existing
  install keeps its poster size SDR until an admin ticks the box. That matches "applies to
  videos processed from now on", but the README says "on for the seeded `video_thumbnail`"
  without saying existing sizes are not touched.
