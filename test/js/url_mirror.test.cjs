"use strict";

// Unit tests for `urlMirrorTarget` in priv/static/assets/phoenix_kit.js —
// the predicate behind PkUrlMirror (replaceState the address bar to the
// element's data-url when it is a different same-origin path).
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

const { urlMirrorTarget } = require("../../priv/static/assets/phoenix_kit.js");

test("a different same-origin path is mirrored", () => {
  assert.equal(urlMirrorTarget({ url: "/admin/p/1/tasks/board" }, "/admin/p/1"), "/admin/p/1/tasks/board");
});

test("the current path is left alone", () => {
  assert.equal(urlMirrorTarget({ url: "/admin/p/1" }, "/admin/p/1"), null);
});

test("nothing, an empty value or an absolute/foreign url never fires", () => {
  assert.equal(urlMirrorTarget({}, "/x"), null);
  assert.equal(urlMirrorTarget({ url: "" }, "/x"), null);
  assert.equal(urlMirrorTarget({ url: "https://evil.example/" }, "/x"), null);
  assert.equal(urlMirrorTarget(null, "/x"), null);
});

test("network-path references, control characters and fragments are refused", () => {
  assert.equal(urlMirrorTarget({ url: "//evil.example/" }, "/x"), null);
  assert.equal(urlMirrorTarget({ url: "/\\evil.example/" }, "/x"), null);
  assert.equal(urlMirrorTarget({ url: "/admin\u0000/p" }, "/x"), null);
  assert.equal(urlMirrorTarget({ url: "/admin/p#section" }, "/x"), null);
  // A query string is part of the address and is mirrored.
  assert.equal(urlMirrorTarget({ url: "/admin/p?tab=board" }, "/admin/p"), "/admin/p?tab=board");
});
