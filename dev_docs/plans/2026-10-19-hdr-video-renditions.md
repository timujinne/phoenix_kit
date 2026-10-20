# HDR video renditions, and a viewer that plays them

**Created:** 2026-10-19
**Status:** scope only, not started. A feasibility spike was run on the real HDR clip (below); no repository code was changed by it. Author: Claude, with Dmitri.

## Goal

Playing a video in Fotki uses a file that fits the viewer's browser, screen and connection, and
keeps HDR where the screen can show it: an iPhone or a Mac with an HDR display gets the HDR
picture, anything else gets an ordinary (SDR) one that plays everywhere, and nobody downloads a
multi-gigabyte original to watch a clip.

## The finding that shapes this plan

**The viewer plays the original file, not a rendition.** `MediaCanvasViewer`
(`media_canvas_viewer.html.heex`, used by Fotki's `PhotoViewer`) renders

    <video src={f.urls["original"]} controls preload="metadata" ...>

with no `poster` and no choice of source. The 360p/720p/1080p renditions are made, stored and
never played; only the poster (`video_thumbnail`) is shown, in the grid. So:

- **HDR already plays on an iPhone**, because the original is HEVC HLG and the phone plays it
  natively (what was seen on 2026-10-19 was the original, not a rendition).
- **Where the original does not play, nothing does**: a browser without HEVC support
  (Firefox on most systems, Chrome without a hardware decoder) cannot play an iPhone's `.mov`
  at all, and there is no H.264 fallback in the viewer.
- **Every view downloads the original** (tens or hundreds of MB, gigabytes for a long clip).
- So HDR *renditions* by themselves change nothing a person sees. The work that matters is
  **the viewer choosing a source**; HDR renditions are what make that choice good for an HDR
  screen on a slow connection.

## What exists (checked 2026-10-19)

- Video sizes `360p`, `720p`, `1080p` (H.264, SDR, `yuv420p`, tone-mapped from HDR since
  2026-10-19) and `video_thumbnail` (the poster, an HDR photo for an HLG video since
  2026-10-19), seeded per variant set.
- Alternative formats exist for **image** sizes only: a size lists `alternative_formats`
  (`webp`, ...) and the variant is named `<size>_<format>` (`medium_webp`,
  `VariantNaming`); `validate_alternative_formats` accepts image formats.
- `VideoSource.probe/1` tells whether a source is HDR and HLG; the encoder side already
  builds the ffmpeg arguments per size (`VariantGenerator.ffmpeg_args/4`).
- ffmpeg 7.1.5 in the container has `libx265` (and `libsvtav1`, `libaom`, `libvpx-vp9`).

## What the spike showed

On the real clip (`IMG_5288.MOV`, 8 s, 1080x1920 portrait, HEVC Main 10, HLG, Dolby Vision 8.4,
9.4 MB), re-encoded with `libx265 -pix_fmt yuv420p10le -tag:v hvc1` and the HLG/BT.2020
tags written through `-x265-params`, AAC audio, `+faststart`:

| Rendition | Time (16 cores) | Size |
|---|---|---|
| 1080 wide, CRF 26, preset `medium` | 30.6 s | 3.2 MB |
| 1080 wide, CRF 26, preset `fast` | 13.7 s | 3.0 MB |
| 720 wide, CRF 26, preset `medium` | 11.6 s | 1.8 MB |
| 1080 wide, CRF 24 / 28, `medium` | n/a | 4.2 MB / 2.5 MB |
| *for comparison* SDR H.264 1080p today (CRF 23) | about 5 s | 6.3 MB |

The HDR file is `Main 10`, `hvc1`, `yuv420p10le`, `bt2020nc`, `arib-std-b67`, `bt2020`: what
Safari/iOS/macOS play as HDR. About **half the size** of the SDR H.264 at the same height, but
**4 to 6 times slower to encode** at `medium` (a 1-minute clip would take about 4 minutes at
1080 wide); `fast` costs almost nothing in size and halves the time.

Not shown: playback in any browser, Dolby Vision, or the look on an HDR screen.

## Design

### A. The viewer picks a source (needed with or without HDR renditions)

1. `MediaCanvasViewer` gets a `poster=` (the file's `video_thumbnail` URL) and a list of
   `<source>`s instead of `src=original`: the renditions of the file, best fit first, the
   original last (it still plays wherever it did).
2. The choice depends on the browser, so it is a small JS hook (`VideoSource`) on the
   `<video>`: it reads the candidate list from `data-` attributes (each: URL, codec string,
   dynamic range, height), asks `video.canPlayType` for each codec, `matchMedia('(dynamic-range:
   high)')` for the screen, and `navigator.connection` / the element's width for a size. It sets
   `video.src` once, before play. Without JS the `<video>` falls back to the first `<source>`
   (the compatible SDR one).
3. The default order: HDR rendition when the screen is HDR and the codec plays; else the SDR
   H.264 rendition nearest the display size; else the original.
4. No new endpoint: the renditions already have URLs (`f.urls`, signed as the original is).

### B. An HDR rendition (HEVC, 10-bit, HLG)

1. **Naming.** Reuse the alternative-format mechanism: a video size lists `"hdr"` among its
   `alternative_formats`, giving `1080p_hdr`, `720p_hdr` (`VariantNaming` learns `hdr`;
   `validate_alternative_formats` accepts it for a video size). It is made **only for an HLG
   source**; for any other source nothing is made and nothing is missing.
2. **Encoding.** `libx265`, `-pix_fmt yuv420p10le`, `-tag:v hvc1`, HLG/BT.2020 tags through
   `-x265-params`, `+faststart`, the size's own scale filter and audio. CRF from the size's
   quality; **preset `fast`** (the spike's best time-for-size).
3. **Gate.** The same two switches as the HDR poster: the size's `keep_hdr` option and
   `config :phoenix_kit, hdr_renditions`. Off, nothing changes.
4. **Fallback.** If `libx265` is missing or the encode fails, no HDR rendition is made (a
   warning is logged); the SDR rendition is unaffected, since it is a separate variant.
5. **Cost.** Storage: the HDR rendition adds about half of the SDR one's size per size made.
   Encode time: about 2.5 times the SDR rendition at `fast`. Both only for HLG sources.

### C. What it does not do

- No adaptive streaming (HLS/DASH): a `<video>` with one chosen file, as today.
- No Dolby Vision output (the HLG base layer plays everywhere a DV file does).
- No PQ sources (as the poster): they keep the SDR rendition.
- No change to originals.

## Phases

1. **Viewer plays renditions + poster (A)**, SDR only. The largest user-visible gain and
   independent of HDR; includes a fallback to the original and tests of the hook's decision
   function (pure, in JS) and of the markup.
2. **HDR rendition (B)** behind `keep_hdr`, with the viewer's hook picking it for an HDR
   screen (A already knows the candidate shape).
3. Remake the existing HLG videos (two on the dev site); look at the result on the iPhone and
   a Mac, and in Chrome and Firefox (the fallback).

Size, roughly: phase 1 about 250 lines of JS and Elixir and a day with the browser checks;
phase 2 about 200 lines and half a day.

## Tests

- Real ffmpeg (skipped without it): an HLG clip gives `1080p_hdr` with `hvc1`, `yuv420p10le`,
  `arib-std-b67`; an SDR clip gives none; `keep_hdr` off or the site switch off give none;
  a missing encoder (simulated) leaves the SDR rendition and a warning.
- The hook's decision function: HDR screen + HEVC → HDR rendition; HDR screen without HEVC →
  SDR; SDR screen → SDR even if HEVC plays; nothing playable → original; the nearest height.
- A browser pass with Playwright's Chromium in this container can only check the fallback
  path (it has no HEVC or HDR); the HDR path is checked by eye on the iPhone and a Mac.
- Mutation checks for each condition, as for the poster.

## Risks and open questions

- **Browser support for HEVC HLG in `<video>`**: Safari (iOS, macOS) yes. Chrome plays HEVC on
  hardware that has a decoder, HDR on an HDR display on some systems; Firefox mostly not. The
  hook's `canPlayType` and `dynamic-range` checks are the guard, and the SDR H.264 is always
  there.
- **`canPlayType` is a hint**: it says "maybe", not whether the HDR will really be shown.
  Worst case is a correct picture, tone-mapped by the browser.
- **Encode time on a small server**: 4 to 6 times the SDR cost at `medium`; the plan uses
  `fast`. A long HDR video on a small machine is the case to watch; the job already runs
  per file in a queue.
- **Storage**: the HDR rendition is extra, not a replacement. A site that does not want it
  leaves `keep_hdr` off.
- **Signed URLs and own-bucket libraries**: renditions are served like the original (own-bucket
  libraries by a 300 s presigned redirect). A `<video>` that buffers past 300 s relies on the
  redirect answering Range requests, as the original does today.
- **Dolby Vision profile 5** sources are still left alone, as before.

## Decisions needed

| # | Question | Recommendation |
|---|---|---|
| R1 | Start with the viewer playing renditions (phase 1), before any HDR rendition? | **Yes.** It fixes real problems today (no playback without HEVC, the original downloaded on every view, no poster) and HDR renditions have nothing to be played by without it. |
| R2 | The rendition's name and place: `1080p_hdr` as an alternative format of the video size? | **Yes**, it reuses what image sizes already do. |
| R3 | Which sizes get an HDR rendition by default? | **`720p` and `1080p`**, not `360p` (a small preview does not need HDR). |
| R4 | Encoder preset? | **`fast`**: about the same size as `medium`, half the time. |
| R5 | Make HDR renditions for every HLG video, or only on demand? | **Every HLG video**, behind `keep_hdr` (as the poster), so a site can turn it off. |
