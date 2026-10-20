# Public user libraries: a library the whole world can browse

**Created:** 2026-10-18
**Status (2026-10-18):** decisions D1–D3, D5, D6 and the address scheme answered; **phase 1 (core) built**, see "Phase 1 as built" below. Phases 2 and 3 not started. Author: Claude, with Dmitri.

## Goal

A user (or, later, an organization) can have a **Public** library. Anyone, signed in or
not, can browse the whole library, read-only, and everything built on top of it: the
timeline today, albums, a map and people later. The model is an organization showing its
entire collection to the world (an archive like NASA's), as well as a person with a public
gallery.

Every Fotki account is given two libraries when it signs up, named **Private** and
**Public** (decided 2026-10-18: short, no translation, the same words as the Visibility
badge). The Private one exists today (named "My library" until it is renamed).

Not in scope: comments, likes, following, search across public libraries, per-photo
sharing links.

## What is true today (checked in the code on 2026-10-18)

- **Visibility exists.** `phoenix_kit_storage_libraries.visibility` is `site` or
  `private`; the database allows both for any library. `Library.create_user_changeset/2`
  forces `private`, so a user library cannot be public today. Media (system) is `site`.
- **Serving needs nothing new for the bytes.** `Libraries.private_file?/1` decides: a
  private file gets an expiring token, any other file a permanent one
  (`FileController`, `URLSigner`). The files of a `site` library are already fetchable
  by anyone holding the URL.
- **Access says no to anonymous.** `Libraries.can?/3` needs a `Scope` with a user; for a
  file in a user library it grants the owner and members only. Nothing grants "anyone".
- **Site listings hide private libraries only.** `Libraries.exclude_private/1` is what
  the media browser, the pickers and the orphan cleanup use to keep user libraries out of
  site media. A public user library is not private, so it would **appear in everyone's
  site media and be treated as orphans' neighbours** unless that is changed.
- **The Photos timeline refuses anonymous.** `Timeline.reader/1` needs a user or a system
  role; `restrict/3` shows a library's files to its members, an uploader their own, and
  everyone else nothing.
- **Own-bucket libraries are already served from the owner's bucket, not through us.** An
  owned bucket is `signed` (a database check forbids a public one), and
  `Manager.bucket_access/4` answers a request with `{:signed_redirect, url}`: a 302 to a
  presigned URL that lives 300 seconds. The bytes (images, and video with Range requests)
  come straight from the bucket. What passes through us is the redirect, one per file
  request, sent `private, no-store` so a shared cache can never keep it. (An earlier draft
  of this plan said such a library "would be proxied through our server". That was wrong:
  only a bucket that cannot sign, or a non-inline type, is proxied.)
- **Renditions carry no EXIF or GPS.** Every rendition is made with ImageMagick and
  `strip_metadata`, which is on unless a size's options turn it off
  (`Dimension.strip_metadata?/1`; true for every size in Fotki's database today). The
  location is only in the database (`phoenix_kit_files.latitude/longitude` and
  `metadata["exif"]`, read from the original) and in the original file itself.

## Design

### Core (`phoenix_kit`)

1. **A user library can be created `site` ("public").** `create_user_library/3` takes
   `"visibility" => "private" | "public"` (default private). Chosen once, at creation, and
   final in v1: no private-to-public flip, because links, caches and expectations all depend
   on it. A later "publish" action must be explicit and warn.
2. **Who may.** A new sub-permission `storage.public_library` (base `storage` required, as
   the others), granted by the site; nobody has it until it is. The create dialog shows the
   choice only to holders, with the warning below.
3. **One predicate for reading.** `Libraries.public?/1` (user library, `site`, not trashed,
   not suspended) and `Libraries.can?/3` / `readable_by?/2` answer yes for a **nil or
   anonymous scope** on a public library's files, for `:read` only. Every feature asks this
   predicate; none writes its own check. Edit rights are unchanged (owner, manager).
4. **Keep public user libraries out of site media.** Replace `exclude_private/1`'s meaning
   with "exclude every user library, private or public" and audit every caller (media
   browser, pickers, search, stats, orphan cleanup). A test per caller.
5. **Takedown.** An admin can suspend a public library: it then answers as private
   (`settings.suspended`), with an audit entry, without deleting anything. Publishing and
   suspending are written to the audit log.
6. **Trash and purge** already remove the files; a public library's links die with it.

### Photos package (`phoenix_kit_photos`)

7. **Anonymous reads.** `Timeline.reader/1` accepts a nil scope only for a public library;
   `restrict/3` returns the whole library for it. `PhotoTimeline` and `PhotoViewer` get a
   read-only mode: no edit, annotate, burn or delete controls, no EXIF editing.
8. **Location and originals are the library's settings, off by default** (see decisions).
   *Locations* are a server-side gate, not a re-render: because renditions are stripped, no
   picture has to be regenerated when the switch changes. The viewer's EXIF panel, any
   metadata response and the map read `latitude`/`longitude` only when the library has
   "show locations" on, and an anonymous request for them is refused otherwise.
   *Originals*: the `original` variant is refused to anonymous readers unless the library
   allows downloads. An original keeps everything the camera wrote, location included, so
   turning downloads on says so in the dialog, whatever the locations setting is.
   Two things to verify while building: deep-zoom tiles and burned (annotated) copies must
   carry no EXIF, and a public library must only use a variant set whose sizes all strip
   metadata (a site admin can switch that off per size).

### Fotki

9. **Signup creates both** (`Fotki.PersonalLibraries`): Private and Public, in that order,
   Private the default. The existing accounts' "My library" is renamed Private and their
   Public is made by the backfill. Hidden Media: regular users do not see the site's Media
   in the Photos picker or the Media tab (an admin does).
10. **Public pages, outside login.** A route group in Fotki that does not require a session,
    its own light layout, rate limiting for anonymous visitors, and `noindex` until the
    owner opts in. The URL scheme is a decision (below).
11. **The upload destination must be unmistakable.** Anything uploaded to Public is world
    visible at once. The uploader shows a globe and "Public" beside the library name, and the
    first upload to a Public library asks for confirmation.

## Decisions needed (recommendation in bold)

| # | Question | Recommendation |
|---|---|---|
| D1 | Can the world download originals? | **Decided 2026-10-18: off by default**, a per-library setting. The renditions (large) are enough to view. |
| D2 | Is GPS public? | **Decided: a per-library switch, hidden by default**, with a plain warning when turning it on. It is a server-side gate (item 8), so it costs no re-rendering. |
| D3 | Who has a Public library in Fotki? | **Decided: every account, created at signup** (it is empty, so nothing is exposed), and the upload confirmation covers the risk. |
| D4 | URL scheme for public pages | **Decided: `/<username>/<library slug>/…`**, e.g. `/fotkin2/public/…`. One catch for phase 3: PhoenixKit mounts an unconstrained `/:locale/…` at the site root, which matches any first segment, so `/<username>/<slug>` can collide with `/en/photos`, `/en/admin` and every other two-segment PhoenixKit page. Fotki answers it with reserved usernames (route names, locale codes) and by routing a public page only when the username and the library exist, ahead of PhoenixKit's routes. |
| D5 | Search engines | **Decided: `noindex` by default**, an owner opt-in. |
| D6 | Public library on the user's own bucket | **Decided: deliver from their bucket, never through us.** That is how owned buckets are served today (see "What is true today"), so v1 needs nothing. Open improvement for later: a **public bucket mode** for public libraries (the owner makes the bucket, or a public domain on it, readable, and we hand out its plain URLs), which removes even the per-file redirect and lets a CDN cache everything. It means relaxing the owned-bucket "never public" check for public libraries only. |
| D7 | Abuse: reporting, takedown, terms | **Later, by decision.** Item 5 (admin suspend) stays in phase 1 because it is cheap; reporting and terms wait. Fotki should not open public sign-up to strangers before it is settled. |
| D8 | Private to public later | **No flip in v1.** |
| D9 | Organizations | Later: an organization account owns the library and its staff are contributors, which core's roles already model. |

## Phases

1. **Core**: items 1–6, the create-dialog choice (Private or Public with the warning), the
   permission, tests including the site-media exclusion for every listing.
2. **Photos package**: items 7–8.
3. **Fotki**: items 9–11; rename "My library" to Private; backfill Public.
4. **Later features** (albums, map, people) read through the predicate of item 3, so they are
   public the moment the library is.

## Risks

- **A public library leaking into site media** is the likeliest bug: item 4 and its tests.
- **Location data** (D2) and **hosting illegal content** (D7) are the two that can hurt people;
  neither ships without its answer.
- **Load and cache**: the site's files have permanent URLs a CDN can keep. An own-bucket
  library's every file request is a 302 we answer and nobody can cache; harmless at a
  gallery's size, a cost at an archive's, which is what D6's public bucket mode is for.
- **Deleting an account** must delete or hand over its public library; it already trashes the
  libraries the user owns.
- **Privacy law**: a public library holds personal data of whoever is in the pictures; the
  owner is the publisher, the site is the host.

## Phase 1 as built (core, 2026-10-18)

- **Creation.** `Libraries.create_user_library/3` takes `"visibility" => "private" | "public"`; `"public"` needs
  `storage.public_library` (new sub-permission of `storage`, label "Make libraries public"), anything else is
  `{:error, :not_allowed}`. It is stored as `visibility: "site"`. `Library.create_user_changeset/2` reads the request from
  its attrs, not from the changeset, because the struct's own default for the field is `"site"`. Publishing is written to
  the history (`storage.library_published`). The create dialog shows Private/Public to holders of the permission only, with
  the warning; a posted `visibility` from anyone else is ignored by the component and refused by `Libraries`.
- **Reading.** `Libraries.public?/1` (a user library, `site`, not trashed, not suspended; Media is not), `can?/3` with a
  `nil` or anonymous scope for `:read`, `can_read_library?/2`. Editing is unchanged.
- **Serving.** No change: a public library's files are not `private?`, so they already get ordinary links.
- **Site media.** `exclude_user_libraries/1` (the media browser, the pickers, the folder listing, the orphan cleanup);
  `exclude_private/1` is kept as the old name; `user_among/1` for the folder listing.
- **Suspension.** `settings.suspended` (and `suspended_reason`) on the library; a suspended library is `private?`, not
  `public?`, and the admin's Libraries tab shows Suspended with a Restore button. History: `storage.library_suspended`,
  `storage.library_unsuspended`.
- **Not done yet (phases 2–3):** the Photos package reading for anonymous visitors, the per-library "show locations" and
  "allow original downloads" settings (their enforcement belongs where the viewer and metadata responses are, in phase 2),
  public pages, the Public library at signup, hiding Media from regular users, `noindex`.
