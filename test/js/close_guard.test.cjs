"use strict";

// Unit tests for `guardedInput` in priv/static/assets/phoenix_kit.js — the
// predicate behind PkDialog's `data-close-guard="input"`: an input event
// counts only when its target sits in a submittable form of THIS dialog.
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

const { guardedInput, guardedDirty } = require("../../priv/static/assets/phoenix_kit.js");

// A target whose `closest` answers from a fixed map: selector → element.
function target(map) {
  return { closest: (selector) => (selector in map ? map[selector] : null) };
}

const dialog = { id: "outer" };
const nested = { id: "inner" };
const submitForm = { id: "save-form" };

test("a keystroke in a submittable form of this dialog trips the guard", () => {
  const t = target({ dialog: dialog, "form[phx-submit]": submitForm });
  assert.equal(guardedInput(dialog, t), true);
});

test("a filter form (phx-change only) does not count", () => {
  const t = target({ dialog: dialog });
  assert.equal(guardedInput(dialog, t), false);
});

test("typing inside a nested dialog leaves the outer one alone", () => {
  const t = target({ dialog: nested, "form[phx-submit]": submitForm });
  assert.equal(guardedInput(dialog, t), false);
});

test("missing pieces never throw", () => {
  assert.equal(guardedInput(null, target({})), false);
  assert.equal(guardedInput(dialog, null), false);
  assert.equal(guardedInput(dialog, {}), false);
});

// ── guardedDirty: the decision, recomputed from the forms' fields ──

// A field with the DOM properties fieldDirty reads.
function field(attrs) {
  return Object.assign(
    { name: "f", disabled: false, type: "text", value: "", defaultValue: "", tagName: "INPUT",
      closest: () => null },
    attrs
  );
}

function dialogWith(forms) {
  const d = {
    id: "outer",
    querySelectorAll: (sel) => (sel === "form[phx-submit]" ? forms : []),
  };
  forms.forEach((f) => { f.closest = (sel) => (sel === "dialog" ? d : null); });
  return d;
}

test("a typed value that differs from the rendered one is dirty", () => {
  const d = dialogWith([{ elements: [field({ value: "draft", defaultValue: "" })] }]);
  assert.equal(guardedDirty(d), true);
});

test("a form the server re-rendered with the value — or reset — is clean again", () => {
  const same = dialogWith([{ elements: [field({ value: "draft", defaultValue: "draft" })] }]);
  assert.equal(guardedDirty(same), false);
  const reset = dialogWith([{ elements: [field({ value: "", defaultValue: "" })] }]);
  assert.equal(guardedDirty(reset), false);
});

test("checkboxes and selects count by checkedness / selection", () => {
  const box = field({ type: "checkbox", checked: true, defaultChecked: false });
  assert.equal(guardedDirty(dialogWith([{ elements: [box] }])), true);
  const sel = field({
    tagName: "SELECT", type: "select-one",
    options: [{ selected: true, defaultSelected: false }, { selected: false, defaultSelected: true }],
  });
  assert.equal(guardedDirty(dialogWith([{ elements: [sel] }])), true);
});

test("search fields, hidden inputs and disabled fields never count", () => {
  const search = field({ type: "search", value: "q", defaultValue: "" });
  const hidden = field({ type: "hidden", value: "x", defaultValue: "" });
  const off = field({ disabled: true, value: "x", defaultValue: "" });
  assert.equal(guardedDirty(dialogWith([{ elements: [search, hidden, off] }])), false);
  // A typed search box is not an unsaved edit either way.
  const t = target({ dialog: dialog, "form[phx-submit]": submitForm });
  t.type = "search";
  assert.equal(guardedInput(dialog, t), false);
});

test("a nested dialog's forms belong to the nested dialog", () => {
  const inner = { id: "inner" };
  const form = { elements: [field({ value: "draft", defaultValue: "" })], closest: (sel) => (sel === "dialog" ? inner : null) };
  const d = { id: "outer", querySelectorAll: () => [form] };
  assert.equal(guardedDirty(d), false);
});

test("guardedDirty never throws on missing pieces", () => {
  assert.equal(guardedDirty(null), false);
  assert.equal(guardedDirty({}), false);
});
