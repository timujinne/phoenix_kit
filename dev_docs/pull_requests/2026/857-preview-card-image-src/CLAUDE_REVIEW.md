# PR #857 — PreviewCard: an image can be given by URL, not only as a Storage file

**Author:** timujinne · **Merged:** 2026-09-22 (057ceb9e) · **Reviewer:** Claude · **Released in:** 2.37.2

## Summary

`PreviewCard`'s `:images` entries may now be `%{src, name}` (optional
`:thumb_src` for the jump strip) as well as Storage `%{uuid, name}`. A new
public `image_url/2` picks the URL: `:thumb_src` for `"thumbnail"`, else
`:src`, else a signed Storage URL. Motivating caller: a host app's
`DocumentPreviewCard` (host-served document page thumbnails), which
feature-detects the support.

Verdict: sound, small, additive. `src` values go through HEEx attribute
escaping; every existing caller (catalogue `ProductCard.resolve_images/1`,
warehouse, a host app's sub-order card) passes plain `%{uuid, name}` maps and hits
the unchanged signed-URL clause.

## Findings

### IMPROVEMENT - MEDIUM — `img[:name]` broke struct image entries — FIXED

The alt text moved from `img.name` to `img[:name]` so a `:src` entry can
omit `:name`. Bracket access goes through `Access`, which structs do not
implement, so an entry passed as a struct (which `img.name` rendered fine
before) now raised `UndefinedFunctionError`. No current caller passes a
struct, but `:images` is a loose `:list` attr and a struct is a natural
thing to hand it. Switched to `Map.get(img, :name)` — optional for maps,
still works for structs. Test: "an image entry may be a struct (no
Access), and :name is optional".

### NITPICK — `:thumb_src` also overrides a Storage entry's thumbnail — not changed

The first `image_url/2` clause matches any map with a binary `:thumb_src`,
including a `%{uuid, thumb_src}` entry. The doc frames `:thumb_src` as a
URL-entry option. Harmless (a caller setting it wants it used), so left as is.

### NITPICK — an entry with neither `:src` nor `:uuid` raises `FunctionClauseError` — not changed

Previously a `KeyError` on `img.uuid`. Same class of caller bug, arguably a
clearer error; the component is pure render and callers resolve entries.
