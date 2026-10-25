# PR #978 — Dashboard overview: size the grids by their container, not the window

**Author:** timujinne · **Merged:** 2026-10-23 (4a1412db5) · **Reviewer:** Claude

## Summary

The overview grids used window breakpoints (`md:`, `lg:`, `xl:`), so beside the admin sidebar the tiles were squeezed at widths the window called "wide". The
root is now `@container` and the grids use container breakpoints (`@xl:`, `@3xl:`, `@7xl:` ...); tile text gets `min-w-0`, `break-words`, `hyphens-auto`, icons
`shrink-0`.

Verdict: correct for the supported stack. Container-query variants are core Tailwind v4 (this kit already requires daisyUI 5, i.e. Tailwind v4), and
`@7xl`/`@6xl` exist there; a host on Tailwind v3 would lose the column classes, but v3 is unsupported with daisyUI 5.

## Findings

- None.
