# PR #676 — Admin-UI cursors, a leaked import, media-selector audio + type lock, and CTA centring

**Author:** Max Don · **Merged:** 2026-08-01 (`5f776642`) · **Reviewed:** 2026-08-01

11 files, 4 commits — four unrelated fixes found while building against core from
the publishing module:

1. **`c88c0d33`** — `cursor-pointer` on the SearchPicker dropdown rows (server +
   hook-rendered) and the theme dropdown's options, after Tailwind v4's preflight
   stopped giving `button` a pointer; `EmailStatusBadge`'s blanket import narrowed
   to `only: [email_status_badge: 1]`; a shared rate-limit bucket in the
   registration-changeset tests given a unique address per test.
2. **`350c9d31`** — audio as a first-class type in `MediaSelectorModal` (grid
   query, `accept` list, server-side upload gate, copy, dropdown) plus
   `lock_file_type`, and `only_file_type` in `MediaBrowser`.
3. **`355d81a9`** — the CTA block rendered inside a centring wrapper, `inline-block`
   dropped so daisyUI's `.btn` keeps its own `inline-flex`, and the `"#"` default
   action replaced with no href.
4. **`5aff14a5`** — a stale comment in the remember-me handoff test.

**Verdict: three of the four are right, and the type-lock reasoning — refuse the
event on the server, not just hide the control — is exactly right.** The import
narrowing is a real ecosystem fix (`format_status/1` is about as generic as a name
gets, and it was being pushed into every LiveView in the tree), the cursor work was
measured rather than guessed, and hiding a control whose only options are refused
is the right call.

**What did not hold up is the audio work stopping at the surface it was written
on.** `file_type` is one column, four upload paths write it, and each carried its
own copy of `determine_file_type/1`. Only the modal's copy learned about audio —
so an mp3 uploaded through the media browser is still stored as `"document"` and
the new `file_type == "audio"` filter never sees it. The `only_file_type` lock has
the same shape of hole one level up: it filters the listing and hides the control
but not the upload, so in a locked browser you can still upload a PNG, which is
then hidden by the browser's own filter. And five new user-facing strings shipped
with no catalogue entries — where the standard extract command fuzzy-matches them
onto their *video* siblings, which is worse than leaving them English.

All findings below are fixed.

---

## BUG - HIGH — audio is now recognised on one of the four upload paths, so the audio filter mostly finds nothing

`lib/phoenix_kit_web/live/components/media_selector_modal.ex:706` (as merged)

The PR is right that `determine_file_type/1` "didn't recognise audio at all, so an
mp3 was classified `other`", and it fixed the copy sitting in the file it was
editing. There were four:

| Surface | Audio mime → | Catch-all |
|---|---|---|
| `MediaSelectorModal` | `"audio"` *(fixed by this PR)* | `"other"` |
| `MediaBrowser` (`/admin/users/media` and every embed) | `"document"` | `"document"` |
| `UploadController` (`POST /api/upload`) | `"other"` | `"other"` |
| `MediaSelector` (full-page picker) | `"other"` | `"other"` |

They are not display helpers — each one is passed straight to
`Storage.store_file_in_buckets/5,6` as the `file_type` argument, so whichever
dropzone the file was dropped on decides what the column says. And both new
features query that column literally: `scope_files_by_type(query, :audio)` is
`where f.file_type == "audio"`, and `only_file_type` reaches
`Storage.maybe_filter_file_type/2`, which is the same equality test.

Failure scenario: open the admin media browser, upload `podcast.mp3` (stored as
`"document"`), then open any picker with the new **Audio Only** filter — the file
is not there. Worse in a locked browser: upload the mp3 *into* the audio picker
itself and it vanishes the moment the page reloads, because the listing it lands
in is filtered to a type it was not given.

The tell that core already knew about this is `MediaBrowser`'s `audio_file?/1`,
which detects audio by mime **or** extension precisely because "an upload's generic
`application/octet-stream` mime classified them as a document" — the display layer
was compensating for a classifier the query layer trusts.

**Fixed** by promoting one classifier and deleting the copies:
`Storage.determine_file_type/2` (`lib/modules/storage/storage.ex`) is now public and
documented, and `MediaBrowser`, `MediaSelectorModal`, `MediaSelector` and
`UploadController` all call it. Storage's version was already the complete one
(audio, text, pdf, msword, zip → archive, else other), so unifying on it also gives
the browser the `"archive"` and `"other"` classifications its own `only_file_type`
docs list as valid values but which its local copy — everything unknown →
`"document"` — could never produce.

Note the one deliberate behaviour change: an unknown mime uploaded through
`MediaBrowser` is now `"other"` rather than `"document"`. `"other"` is in the
`File` schema's allowlist (`file.ex:228`), which is what the old copy's comment was
actually guarding against.

Locked in by `test/modules/storage/determine_file_type_test.exs`.

## BUG - MEDIUM — `only_file_type` gates the listing and the control, but not the upload

`lib/phoenix_kit_web/components/media_browser.ex:149`

The attr docs promise the other kinds "are simply not reachable", and the event
handler is properly re-checked on the server. Uploads were not: `setup_uploads/1`
allows `accept: :any`, and nothing between the dropzone and
`Storage.store_file_in_buckets/6` looks at `only_file_type`. So the file is stored
and then hidden by the very filter that was supposed to keep it out — the browser
accepts it, reports success, and shows nothing.

The reason it was missed is structural and worth recording: the upload config lives
on the **parent** LiveView (one `allow_upload` shared by every browser on the page),
so the lock cannot be expressed in `accept`. The component's own assigns only come
back into scope in `process_pending_upload/2`, which runs inside `update/2`.

**Fixed** there, mirroring the modal's `upload_type_allowed?/2`: an off-type entry
is dropped before storage and reported with the existing per-type error copy. The
attr docs now say uploads are gated too.

## BUG - MEDIUM — five new strings, no catalogue entries — and the standard merge fills them with the *video* translations

`media_selector_modal.ex` — `gettext("Audio Only")`, `"Audio files"`,
`"Click on an audio file to select it"`, `"Select one or more audio files"`,
`"Only audio files can be added here."`

None of these reached `priv/gettext`, so all five rendered in English for de, es,
et, fr, it, pl, ru — while their image/video siblings two lines above are
translated everywhere.

The trap is what happens next. `mix gettext.extract --merge` reports them as
**"0 new messages, 5 reworded (fuzzy)"** — it matches each new string to its video
sibling and copies that translation across, and per this repo's own hard-won note,
fuzzy entries *do* render. Left alone, ru would ship:

```
msgid "Only audio files can be added here."
msgstr "Сюда можно добавлять только видео."     # "…only video."
```

which is not a missing translation but a confidently wrong one, on an error message
whose entire job is to say what kind of file is wanted.

**Fixed:** extracted, then all five translated by hand in all seven locales with the
fuzzy flags dropped (`en` stays empty — it falls back to the msgid by design). No
fuzzy entries remain anywhere in `priv/gettext`.

## IMPROVEMENT - MEDIUM — the audio `accept` list invites `.m4a` and `.flac`, then the new gate refuses them

`lib/phoenix_kit_web/live/components/media_selector_modal.ex:248`

`upload_type_allowed?/2` classifies from `entry.client_type || MIME.from_path(...)`.
For two of the extensions the new accept list advertises, both sides come back
`application/octet-stream`:

```
{"a.m4a",  "application/octet-stream"}    # what an iPhone records
{"a.flac", "application/octet-stream"}
```

so the file passes the OS file-chooser filter, uploads, and is then rejected with
"Only audio files can be added here." — the exact "the mistake lands after the
effort" failure the commit message set out to remove, moved one step later. (Same
shape for a browser that reports no type at all: `entry.client_type` is `""`, which
is truthy in Elixir, so the `MIME.from_path` fallback never runs.)

**Fixed** in the shared classifier: `Storage.determine_file_type/2` takes the
filename and, when the mime type yields nothing, tries `MIME.from_path/1` and then
a known-audio extension list (mirroring `MediaBrowser`'s existing
`@audio_extensions`, which exists for exactly this reason). This also fixes
classification at *store* time — an `.m4a` uploaded anywhere now lands as
`"audio"` instead of `"other"`.

## IMPROVEMENT - MEDIUM — the test refactor quietly dropped the saved-user case it was named for

`test/phoenix_kit/users/user_org_changeset_test.exs:270`

Giving the block a unique address per test is right — the shared-bucket diagnosis
is correct and the failure really did read as "registration is broken". But one
test changed subject in the process:

```elixir
- changeset = User.registration_changeset(user, %{"username" => "maria_updated"})
+ changeset = User.registration_changeset(%User{}, %{"username" => "#{base}_updated"})
```

The describe block is *"username of a saved user"*, and the neighbouring test
covers the #671 regression where the generator renamed the holder of a name. An
explicit username on a **saved** user is the admin-edit path; on `%User{}` it is
the registration path, which the "brand new user" test already covers. Nothing was
left asserting that an admin renaming an existing user wins over the generator.

**Fixed:** restored to the saved `user` from `setup`, keeping the unique base.

## NITPICK — `.ogg` sat in the video accept list while everything else reads it as audio

`accept_for(:video)` advertised `.ogg`; `MIME.from_path/1` doesn't know it, the
shared classifier now reads it as audio, and `MediaBrowser.audio_file?/1` already
did. So a video picker invited it and the gate refused it (before this PR too —
it classified as `"other"`). Moved to `accept_for(:audio)`; `.ogv`, the actual Ogg
*video* extension, stays with video.

---

## Verified as correct — no change needed

- **`EmailStatusBadge` import narrowing.** The module exports exactly one component
  plus the two helpers; core's only consumer (`EmailActivityBadges`) already
  qualifies them, and no `.heex` in the tree calls either unqualified. Worth
  knowing this is technically breaking for a *host or module* LiveView that relied
  on the blanket import — a sweep of the sibling repos found none (the
  `status_class/1`s in `phoenix_kit_catalogue` / `phoenix_kit_billing` are their
  own private definitions, which is precisely the collision this fixes).
- **`cursor-pointer` on the safelist span.** The SearchPicker hook writes the class
  from JS, and the bundle in `priv/static/assets/phoenix_kit.js` is the only copy —
  there is no `assets/` source in core to keep in sync.
- **CTA.** `href={nil}` omits the attribute in HEEx, so a CTA with no action renders
  as an anchor that does nothing rather than jumping to the top of the page; the
  component is consumed only through the block registry, so the wrapper `<div>` has
  no core call site to disturb.
- **The lock's server-side re-check** in both `set_file_filter` and `filter_type` —
  clause ordering is correct and a locked component ignores the event rather than
  crashing on it.

## Gate

`mix precommit` — compile `--warnings-as-errors --all-warnings`,
`deps.unlock --check-unused`, `quality.ci` (format check, `credo --strict`,
dialyzer), `test.js` — **green**. `test/modules/storage/determine_file_type_test.exs`
(7 tests, DB-free) passes; integration tests are excluded here, no PostgreSQL in
this environment.
