# HDR video poster: a gain-map JPEG made from an HDR video's frame

**Created:** 2026-10-19
**Status (2026-10-19):** **built**, see "As built" at the end. Decisions H1-H3 answered (on by default, remake the existing HDR posters, HLG only). Author: Claude, with Dmitri.

## Goal

The poster of an HDR video (the `video_thumbnail` rendition, the picture the grid and the
viewer show before play) is an **HDR photo**: a JPEG with a gain map, so an HDR screen shows
the highlights (the sun, a lamp) above normal white, the same way an HDR photo's renditions
already do. An SDR screen or browser shows the ordinary picture, which is the tone-mapped
SDR poster made today.

Not in scope: the video renditions themselves (they stay SDR, tone-mapped, as shipped on
2026-10-19); HDR for other still frames (a PDF page, an animation).

## Where things stand (checked 2026-10-19)

- An HDR video's poster is **SDR**, tone-mapped from the HLG/PQ frame (`VideoSource`,
  `VariantGenerator.ffmpeg_args/4`). Correct colours, no HDR.
- The photo pipeline's HDR (`Hdr`, `HdrResize`, `HdrXmp`) **only resizes a gain map the
  camera already wrote**. It reads the map from the file; it can not make one. A video frame
  has none, so the map has to be **computed**.
- A rendition keeps HDR when its size says so (`Dimension.keep_hdr?/1`, the `keep_hdr`
  option) and the site has `config :phoenix_kit, hdr_renditions` on (default true). In
  Fotki's database `large` and `medium` have `keep_hdr: true`; **`video_thumbnail` has
  `false`**.
- libvips 8.18.7 as bundled by `vix` has **`uhdrsave`** (an Ultra HDR writer that makes the
  gain map itself from linear scRGB pixels), `uhdrload` and `uhdr2scrgb`. `vix` is already an
  optional dependency of core (`mix.exs`) and a dependency of Fotki. No system package is
  needed. It has no PPM/PFM loader.

## What the spike showed

On the real HDR clip (`IMG_5288.MOV`, HEVC Main 10, HLG, BT.2020, Dolby Vision 8.4):

1. `ffmpeg -ss 1 -i clip -vframes 1 -vf "scale=w='min(640,iw)':h=-2,zscale=t=linear:npl=1000,format=gbrpf32le,zscale=p=bt709" -pix_fmt gbrpf32le frame.pfm`
   writes the frame as **linear-light float RGB in BT.709**, 1.0 = 1000 nits (median 0.12 =
   120 nits, 99th percentile 0.91, brightest red 1.46). The orientation (the rotation
   matrix) is applied by ffmpeg.
2. A PFM is a three-line text header (`PF`, `<w> <h>`, `-1.0`) and `w*h*3` little-endian
   floats, **bottom row first**. Parsing it by hand and `Image.new_from_binary/5` +
   `flip` gives the same pixels as reading the planar frame (the resulting JPEGs are
   byte-identical).
3. Multiplying by `1000/203` (so SDR white, 203 nits, is 1.0: ITU-R BT.2408) and calling
   `Operation.uhdrsave/3` (Q 85) wrote a **115 KB** Ultra HDR JPEG in **~50 ms**.
   (Today's SDR poster is 77-85 KB.)
4. `PhoenixKit.Modules.Storage.Hdr.read/1` recognises it: `gain_map: true`, `container:
   "jpeg"`, `kinds: ["iso21496"]`, a 17.5 KB gain map. (`headroom` is `nil`: `Hdr.read`
   only reports it for the `apple`/`ultrahdr` kinds.)
5. Decoded back (`uhdrload` + `uhdr2scrgb`) the picture has a **maximum of 6.2 and an
   average of 0.90** in units of SDR white: the highlights above white survived.

Not shown by the spike: how it **looks** on an HDR display (none in this container), a PQ
source, a Dolby Vision profile 5 source, or what Safari/Chrome do with the file. See
"Risks" and "Verification".

## Design

All in core, in the video branch of the variant generator, behind the same switches the
photos use.

1. **`PhoenixKit.Modules.Storage.VideoHdrPoster`** (new): `make(input_path, output_path,
   dimension, source) :: {:ok, path} | {:error, term}`.
   - runs ffmpeg once for the float frame (`.pfm`, the poster time from
     `VideoSource.poster_second/1`, the size from the dimension's width, the same `scale`
     filter as the SDR poster, **no tone-mapping**);
   - reads the PFM (a small private parser: header, trailing `w*h*12` bytes), `flip`s it;
   - multiplies by `peak_nits / 203` and tags it scRGB (`copy(interpretation:
     :VIPS_INTERPRETATION_scRGB)`);
   - `uhdrsave` at the dimension's quality;
   - returns `{:error, _}` for anything unexpected (no Vix, a libvips without `uhdrsave`, a
     malformed frame), never raises.
2. **When it runs.** `process_video_variant/4`, only for a still-frame dimension
   (`jpg`/`jpeg`) of an HDR source, when `Application.get_env(:phoenix_kit,
   :hdr_renditions, true)` and `Dimension.keep_hdr?(dimension)`. Otherwise today's path.
3. **Fallback is the SDR poster that exists today.** If `VideoHdrPoster.make/4` fails, log
   a warning and make the tone-mapped SDR poster, exactly as the HDR image path does ("an
   HDR rendition is a bonus, never a reason for a size to be missing").
4. **Peak.** HLG: `npl=1000` and 1.0 = 1000 nits is what the spike used and is the
   convention for HLG (a 1000-nit reference display). PQ (`smpte2084`) is absolute; it
   needs its own mapping (below). Both are constants in `VideoSource` next to the existing
   203-nit reference white.
5. **Metadata.** `uhdrsave` writes no EXIF; the poster has none, as the SDR one has none
   (`strip_metadata` is already the default for renditions).
6. **Configuration.** No new setting. `keep_hdr` on `video_thumbnail` is the switch (the
   size's options page already has it for image sizes; check it is offered for a video
   size's JPEG). Decide the default for new installs (see decisions).
7. **Existing videos** are not remade by a code change (the spec hash does not change). The
   HDR ones are remade once, by hand, with `VariantGenerator.generate_variants/1` (what the
   admin "regenerate" does); there are two on the dev site.

## Tasks

1. `VideoHdrPoster` with the PFM reader and the vips pipeline; unit-test the reader (header
   variants, bottom-up row order, a truncated file, a big-endian scale, a header whose
   comment contains newlines).
2. Wire it into `process_video_variant/4` behind the three conditions; the fallback.
3. `keep_hdr` for the `video_thumbnail` size: offered in the size form for a video JPEG;
   the seeded default.
4. Tests (below), CHANGELOG, `lib/modules/storage/README.md`.
5. Remake the HDR videos on the dev site; look at the result on a real HDR display.

Estimated size: a new module of about 150 lines, about 40 changed in `variant_generator.ex`,
about 250 lines of tests. Half a day, most of it the verification on real screens.

## Tests

- **Real ffmpeg + real libvips** (skipped without them, like the existing video output
  tests): a synthetic 10-bit HLG clip (`libx264 -x264-params colorprim=bt2020:
  transfer=arib-std-b67:colormatrix=bt2020nc`) gives a poster with `Hdr.read(path)` →
  `gain_map: true`, and decoded back through `uhdr2scrgb` a maximum above 1.0.
- An SDR clip, `keep_hdr` off, `hdr_renditions: false` and a one-second clip each give the
  ordinary SDR JPEG (no gain map).
- A failure in the HDR path (a missing `uhdrsave`, simulated) falls back to the SDR poster
  and a warning, and the variant still exists.
- Mutation checks as for the tone-mapping change: remove the `keep_hdr` condition, remove
  the scale to SDR white, remove the fallback: each makes a named test fail.

## Risks and open questions

- **How it looks.** The spike proves the file is a valid gain-map JPEG with highlights
  above white; it does not show it on an HDR screen. The SDR base picture is libuhdr's own
  tone-mapping, not the Hable curve of the current SDR poster, so the SDR look of the poster
  will differ slightly. To be judged by eye on the iPhone and a Mac before shipping.
- **Browser support.** The HDR gain-map JPEG shows as HDR where the browser supports it and
  as the SDR base elsewhere. That is the behaviour of the HDR photos already served; no
  extra work, but nothing is promised for a browser that ignores gain maps.
- **PQ sources** (`smpte2084`): `zscale=npl=` means something different for an absolute
  curve. Needs a synthetic PQ clip and a decision of the peak (10000-nit container, usually
  mastered to 1000-4000). Until verified, a PQ source can keep today's SDR poster (the HDR
  poster is made for HLG only), which is what every iPhone records.
- **Dolby Vision profile 5** (IPT-PQ-C2, no HLG/PQ base): neither the SDR tone-mapping nor
  this can decode it correctly. An iPhone records profile 8.4 (an HLG base), which is what
  the spike used. Detect profile 5 from the `DOVI configuration record` and treat it as
  non-HDR (plain pass-through) rather than produce wrong colours.
- **Memory.** A float frame is `w*h*12` bytes: 8.7 MB at 640 px wide, 130 MB at 4K wide.
  The poster is at most a few hundred pixels wide (the size's width), so it is small; the
  `scale` is before the conversion to float, as in the spike.
- **libvips version.** `uhdrsave` needs libvips 8.17 or later (Vix 0.42's precompiled
  library is 8.18.7). An older libvips gives the SDR fallback and a warning once.

## Decisions needed

| # | Question | Recommendation |
|---|---|---|
| H1 | Is the HDR poster on by default for the `video_thumbnail` size? | **Yes for new installs and for Fotki**: the photo sizes already default to `keep_hdr: true`, and the fallback makes it safe. An existing site keeps what its size says until an admin turns it on. |
| H2 | Remake the three existing HDR videos' posters? | **Yes, once, by hand**, after H1 and the visual check. |
| H3 | PQ sources in v1? | **No**: HLG only (every iPhone); PQ keeps the SDR poster until a PQ clip is available to verify with. |
| H4 | HDR video *renditions* (10-bit HEVC HLG) next to the SDR ones? | **Later, separately**: bigger and slower, and the poster is what the grid shows. |

## As built (2026-10-19)

- `VideoSource.probe/1` also says `hlg?` and treats Dolby Vision profile 5 as not HDR
  (`stream_side_data` read from ffprobe); `linear_filter/0`, `hlg_peak_nits/0`,
  `reference_white_nits/0`.
- `VideoHdrPoster` (`available?/0`, `from_pfm/3`, `read_pfm/1`); `VariantGenerator.hdr_frame_args/4`
  and `process_video_variant/4` (now `@doc false` public, for the tests) with the SDR fallback.
- `keep_hdr: true` in the `video_thumbnail` seed; the checkbox in the size form for a video
  JPEG size ("HDR video poster"). Fotki's two `video_thumbnail` rows were set through
  `Storage.update_dimension/2`; the two HDR videos were regenerated.
- The ffmpeg argument is `-c:v pfm` with a `.pfm` output name: `pfm` is an image codec, not a
  muxer (`-f pfm` fails).
- Tests: `video_hdr_poster_test` (the PFM reader, orientation, the written file),
  `video_hdr_poster_integration_test` (real ffmpeg and libvips: HDR, `keep_hdr` off, site
  switch off, SDR video, non-JPEG size, a failure falling back), and additions to the args and
  source tests. Each condition was mutated and a test failed.
- Not verified: how it looks on an HDR display (none in the container), PQ, Safari/Chrome.
