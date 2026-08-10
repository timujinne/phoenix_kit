"use strict";

// Unit tests for the pure sizing math behind the collapse scroll keeper in
// priv/static/assets/phoenix_kit.js — the body spacer that stops the page
// from getting shorter than the viewer's scroll position when a
// <details class="collapse"> closes. The bundle is browser code (IIFEs that
// assign onto `window`), so stub the globals it touches at load time; the
// DOM-using parts themselves are not invoked here.
//
// Run: mix test.js  (node --test needs the explicit file on Node 25)

const test = require("node:test");
const assert = require("node:assert/strict");

const noop = () => {};

function stubElement() {
  return {
    style: {},
    dataset: {},
    classList: { add: noop, remove: noop, toggle: noop, contains: () => false },
    setAttribute: noop,
    getAttribute: () => null,
    removeAttribute: noop,
    appendChild: noop,
    remove: noop,
    addEventListener: noop,
    removeEventListener: noop,
    querySelector: () => null,
    querySelectorAll: () => [],
  };
}

global.document = {
  documentElement: stubElement(),
  head: stubElement(),
  body: stubElement(),
  createElement: stubElement,
  createTextNode: () => ({}),
  getElementById: () => null,
  querySelector: () => null,
  querySelectorAll: () => [],
  addEventListener: noop,
  removeEventListener: noop,
  readyState: "complete",
};

const storage = {
  getItem: () => null,
  setItem: noop,
  removeItem: noop,
  key: () => null,
  length: 0,
};

global.window = {
  PhoenixKitHooks: {},
  addEventListener: noop,
  removeEventListener: noop,
  matchMedia: () => ({ matches: false, addEventListener: noop, removeEventListener: noop }),
  localStorage: storage,
  sessionStorage: storage,
  location: { href: "http://localhost/", reload: noop },
  navigator: { userAgent: "node" },
  document: global.document,
  setTimeout,
  clearTimeout,
};

global.localStorage = storage;
global.sessionStorage = storage;

const {
  extraSpaceNeeded,
  spacerAfterScrollUp,
} = require("../../priv/static/assets/phoenix_kit.js");

// Scenario used throughout: 1000px viewport. Sizes are px.

test("extraSpaceNeeded: viewer near the bottom gets exactly the clamped-off height", () => {
  // Document 3200 tall, scrolled to 2000 → viewing 2000..3000. Collapsing
  // 1200px leaves a 2000-tall document; 3000 - 2000 = 1000px would clamp.
  assert.equal(extraSpaceNeeded(2000, 1000, 3200, 1200), 1000);
});

test("extraSpaceNeeded: viewer high up needs nothing", () => {
  // Viewing 0..1000 of 3200; even after -1200 the document (2000) still
  // contains the viewport.
  assert.equal(extraSpaceNeeded(0, 1000, 3200, 1200), 0);
});

test("extraSpaceNeeded: exact fit is not an overshoot", () => {
  // Viewing 1000..2000; post-collapse height is exactly 2000.
  assert.equal(extraSpaceNeeded(1000, 1000, 3200, 1200), 0);
});

test("extraSpaceNeeded: fractional overshoot rounds up, never leaving a sub-pixel clamp", () => {
  assert.equal(extraSpaceNeeded(1000.5, 1000, 3200, 1200), 1);
});

test("spacerAfterScrollUp: still at the anchor, the whole spacer is needed", () => {
  // Installed 800px of space at scrollTop 2000; reader has not moved.
  assert.equal(spacerAfterScrollUp(800, 2000, 2000), 800);
});

test("spacerAfterScrollUp: scrolling up releases exactly the distance travelled", () => {
  // Up 300px → 300px of blank space is now fully below the fold.
  assert.equal(spacerAfterScrollUp(800, 2000, 1700), 500);
});

test("spacerAfterScrollUp: scrolling past the whole spacer clears it", () => {
  assert.equal(spacerAfterScrollUp(800, 2000, 1100), 0);
  assert.equal(spacerAfterScrollUp(800, 2000, 0), 0);
});

test("spacerAfterScrollUp: down-then-back-up does not re-claim released space", () => {
  // highestTop is the HIGHEST point reached (smallest scrollTop), so a detour
  // downward cannot hand back space the page already gave up. Reader went up
  // 300 (highestTop 1700) then back down to 1900 — still 500.
  assert.equal(spacerAfterScrollUp(800, 2000, 1700), 500);
});

test("spacerAfterScrollUp: scrolling DOWN from the anchor never grows the spacer", () => {
  // Scrolling into the blank area must not feed it — that would be an
  // endless runway of empty page.
  assert.equal(spacerAfterScrollUp(800, 2000, 2000), 800);
});

test("spacerAfterScrollUp: never negative", () => {
  assert.equal(spacerAfterScrollUp(0, 2000, 2000), 0);
});
