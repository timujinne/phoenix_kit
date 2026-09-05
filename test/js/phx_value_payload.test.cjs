"use strict";

// Unit tests for `phxValuePayload` in priv/static/assets/phoenix_kit.js —
// the `phx-value-*` attributes of an element as the payload PkDialog's
// close push carries (a stacked popup host stamps `phx-value-frame-ref`
// on its dialogs so a close can be matched against the top frame).
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

const { phxValuePayload } = require("../../priv/static/assets/phoenix_kit.js");

function elementWithAttributes(pairs) {
  return { attributes: pairs.map(([name, value]) => ({ name, value })) };
}

test("collects phx-value-* attributes, keyed without the prefix", () => {
  const el = elementWithAttributes([
    ["id", "pk-modal-close_top_modal-7"],
    ["phx-value-frame-ref", "7"],
    ["phx-value-kind", "task"],
    ["data-frame-ref", "7"],
  ]);
  assert.deepEqual(phxValuePayload(el), { "frame-ref": "7", kind: "task" });
});

test("an element without phx-value attributes yields the empty payload", () => {
  assert.deepEqual(phxValuePayload(elementWithAttributes([["id", "x"]])), {});
});

test("a missing element or one without attributes yields the empty payload", () => {
  assert.deepEqual(phxValuePayload(null), {});
  assert.deepEqual(phxValuePayload({}), {});
});
