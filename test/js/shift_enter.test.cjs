"use strict";

// Unit tests for `shiftEnter` in priv/static/assets/phoenix_kit.js — the
// predicate behind PkShiftEnter (Shift+Enter clicks a named element so a
// form can tell "add" from "add and start the next").
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
  cookie: "",
};

const storage = { getItem: () => null, setItem: noop, removeItem: noop };

global.window = {
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

const { shiftEnter } = require("../../priv/static/assets/phoenix_kit.js");

test("Shift+Enter is the one", () => {
  assert.equal(shiftEnter({ key: "Enter", shiftKey: true }), true);
});

test("plain Enter stays the browser's implicit submission", () => {
  assert.equal(shiftEnter({ key: "Enter", shiftKey: false }), false);
});

test("other modifiers, other keys and IME composition do not count", () => {
  assert.equal(shiftEnter({ key: "Enter", shiftKey: true, metaKey: true }), false);
  assert.equal(shiftEnter({ key: "Enter", shiftKey: true, ctrlKey: true }), false);
  assert.equal(shiftEnter({ key: "a", shiftKey: true }), false);
  assert.equal(shiftEnter({ key: "Enter", shiftKey: true, isComposing: true }), false);
  assert.equal(shiftEnter(null), false);
});
