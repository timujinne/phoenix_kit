"use strict";

// Tests for PkDateInput in priv/static/assets/phoenix_kit.js, the hook behind
// <.date_input>: the pure parser/formatter/placement helpers, and the hook's
// state machine and event wiring on fake elements (no DOM here). What needs a
// browser stays a live check: popup placement and Cally rendering, focus,
// showPicker and screen readers.
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

const { parseDateText, checkDateText, formatDateIso, dateOrder, popupPlacement, calendarLocale } = require("../../priv/static/assets/phoenix_kit.js");

const FORMATS = ["Y-m-d", "m/d/Y", "d/m/Y", "d.m.Y", "d-m-Y", "F j, Y"];

test("formatter renders all six formats; F is the English month, day unpadded", () => {
  const want = {
    "Y-m-d": "2026-01-05",
    "m/d/Y": "01/05/2026",
    "d/m/Y": "05/01/2026",
    "d.m.Y": "05.01.2026",
    "d-m-Y": "05-01-2026",
    "F j, Y": "January 5, 2026",
  };
  for (const f of FORMATS) assert.equal(formatDateIso("2026-01-05", f), want[f], f);
  assert.equal(formatDateIso("2026-10-16", "F j, Y"), "October 16, 2026");
});

test("an unknown format falls back to Y-m-d like the server", () => {
  assert.equal(formatDateIso("2026-10-16", "d.m"), "2026-10-16");
  assert.equal(dateOrder("d.m"), "ymd");
});

test("formatter gives empty text for anything that is not ISO", () => {
  assert.equal(formatDateIso("", "d.m.Y"), "");
  assert.equal(formatDateIso(null, "d.m.Y"), "");
  assert.equal(formatDateIso("garbage", "d.m.Y"), "");
});

test("every format parses its own output back", () => {
  for (const f of FORMATS) {
    for (const iso of ["2026-01-05", "2026-10-16", "2024-02-29", "1999-12-31"]) {
      assert.equal(parseDateText(formatDateIso(iso, f), f), iso, `${f} ${iso}`);
    }
  }
});

test("field order follows the format", () => {
  assert.equal(parseDateText("16.10.2026", "d.m.Y"), "2026-10-16");
  assert.equal(parseDateText("10/16/2026", "m/d/Y"), "2026-10-16");
  assert.equal(parseDateText("16/10/2026", "d/m/Y"), "2026-10-16");
  assert.equal(parseDateText("2026-10-16", "Y-m-d"), "2026-10-16");
  // Ambiguous text reads in the site's order.
  assert.equal(parseDateText("03.04.2026", "d.m.Y"), "2026-04-03");
  assert.equal(parseDateText("03/04/2026", "m/d/Y"), "2026-03-04");
});

test("ISO is always accepted, whatever the format", () => {
  for (const f of FORMATS) assert.equal(parseDateText("2026-10-16", f), "2026-10-16", f);
});

test("any separator, 1-2 digit day and month", () => {
  assert.equal(parseDateText("1.2.2026", "d.m.Y"), "2026-02-01");
  assert.equal(parseDateText("1/2/2026", "d.m.Y"), "2026-02-01");
  assert.equal(parseDateText("1 2 2026", "d.m.Y"), "2026-02-01");
  assert.equal(parseDateText("1,2,2026", "d.m.Y"), "2026-02-01");
  assert.equal(parseDateText("  16-10-2026  ", "d.m.Y"), "2026-10-16");
});

const TODAY = "2026-10-16";

test("two-digit year takes the century nearest today (-50 .. +49 years)", () => {
  assert.equal(parseDateText("1.2.26", "d.m.Y", null, null, TODAY), "2026-02-01");
  assert.equal(parseDateText("02/01/26", "m/d/Y", null, null, TODAY), "2026-02-01");
  assert.equal(parseDateText("26-02-01", "Y-m-d", null, null, TODAY), "2026-02-01");
  assert.equal(parseDateText("12.05.85", "d.m.Y", null, null, TODAY), "1985-05-12");
  assert.equal(parseDateText("31.12.99", "d.m.Y", null, null, TODAY), "1999-12-31");
  assert.equal(parseDateText("01.01.30", "d.m.Y", null, null, TODAY), "2030-01-01");
  // 2026 + 49 = 2075 is the last future year, 2026 - 50 = 1976 the first past one.
  assert.equal(parseDateText("01.01.75", "d.m.Y", null, null, TODAY), "2075-01-01");
  assert.equal(parseDateText("01.01.76", "d.m.Y", null, null, TODAY), "1976-01-01");
  assert.equal(parseDateText("010175", "d.m.Y", null, null, TODAY), "2075-01-01");
  // The window moves with today.
  assert.equal(parseDateText("01.01.85", "d.m.Y", null, null, "2060-01-01"), "2085-01-01");
});

test("a three-digit or five-digit year is not a date", () => {
  assert.equal(parseDateText("1.2.202", "d.m.Y"), null);
  assert.equal(parseDateText("1.2.20266", "d.m.Y"), null);
});

test("digits only, in the format's order", () => {
  assert.equal(parseDateText("16102026", "d.m.Y"), "2026-10-16");
  assert.equal(parseDateText("161026", "d.m.Y"), "2026-10-16");
  assert.equal(parseDateText("10162026", "m/d/Y"), "2026-10-16");
  assert.equal(parseDateText("20261016", "Y-m-d"), "2026-10-16");
  assert.equal(parseDateText("261016", "Y-m-d"), "2026-10-16");
  assert.equal(parseDateText("1610202", "d.m.Y"), null);
  assert.equal(parseDateText("16102", "d.m.Y"), null);
});

test("F j, Y takes an English month name, full or three letters", () => {
  assert.equal(parseDateText("October 16, 2026", "F j, Y"), "2026-10-16");
  assert.equal(parseDateText("oct 16 2026", "F j, Y"), "2026-10-16");
  assert.equal(parseDateText("OCT 16, 26", "F j, Y"), "2026-10-16");
  assert.equal(parseDateText("10/16/2026", "F j, Y"), "2026-10-16");
  assert.equal(parseDateText("Octember 16, 2026", "F j, Y"), null);
  // Month names are only for that format.
  assert.equal(parseDateText("October 16, 2026", "d.m.Y"), null);
});

test("impossible dates are rejected", () => {
  assert.equal(parseDateText("31.02.2026", "d.m.Y"), null);
  assert.equal(parseDateText("29.02.2026", "d.m.Y"), null);
  assert.equal(parseDateText("29.02.2024", "d.m.Y"), "2024-02-29");
  assert.equal(parseDateText("00.10.2026", "d.m.Y"), null);
  assert.equal(parseDateText("16.13.2026", "d.m.Y"), null);
  assert.equal(parseDateText("32.01.2026", "d.m.Y"), null);
  assert.equal(parseDateText("31.04.2026", "d.m.Y"), null);
});

test("partial or junk text is rejected", () => {
  for (const t of ["", "  ", "16", "16.1", "16.10", "16.10.", "a.b.c", "16.10.2026.1", "16..", "1-2-3-4"]) {
    assert.equal(parseDateText(t, "d.m.Y"), null, JSON.stringify(t));
  }
  assert.equal(parseDateText(null, "d.m.Y"), null);
  assert.equal(parseDateText(undefined, "d.m.Y"), null);
});

test("min and max bound the result (inclusive, ISO strings)", () => {
  assert.equal(parseDateText("16.10.2026", "d.m.Y", "2026-10-16", "2026-10-16"), "2026-10-16");
  assert.equal(parseDateText("15.10.2026", "d.m.Y", "2026-10-16", null), null);
  assert.equal(parseDateText("17.10.2026", "d.m.Y", null, "2026-10-16"), null);
  assert.equal(parseDateText("17.10.2026", "d.m.Y", "", ""), "2026-10-17");
  assert.equal(parseDateText("17.10.2026", "d.m.Y", undefined, undefined), "2026-10-17");
});

test("the popup opens under the field, left-aligned with it", () => {
  const anchor = { top: 100, bottom: 132, left: 40 };
  assert.deepEqual(popupPlacement(anchor, { width: 280, height: 320 }, { width: 1200, height: 800 }), {
    top: 136,
    left: 40,
  });
});

test("it flips above when there is no room below and room above", () => {
  const anchor = { top: 600, bottom: 632, left: 40 };
  assert.deepEqual(popupPlacement(anchor, { width: 280, height: 320 }, { width: 1200, height: 800 }), {
    top: 600 - 4 - 320,
    left: 40,
  });
});

test("with no room either side it keeps as much on screen as fits", () => {
  const anchor = { top: 100, bottom: 132, left: 40 };
  assert.equal(popupPlacement(anchor, { width: 280, height: 320 }, { width: 1200, height: 300 }).top, 4);
  assert.equal(popupPlacement(anchor, { width: 280, height: 320 }, { width: 1200, height: 400 }).top, 76);
});

test("it is kept inside the viewport sideways", () => {
  const size = { width: 280, height: 320 };
  const view = { width: 400, height: 800 };
  assert.equal(popupPlacement({ top: 0, bottom: 30, left: 300 }, size, view).left, 400 - 280 - 4);
  assert.equal(popupPlacement({ top: 0, bottom: 30, left: -50 }, size, view).left, 4);
});

// ---------------------------------------------------------------------------
// The hook's state machine, on fake elements (no DOM here): what stays checked
// live is events, focus and the browser pickers.
// ---------------------------------------------------------------------------
const hookDef = window.PhoenixKitHooks.PkDateInput;

function fakeClassList() {
  const set = new Set();
  return {
    add: (c) => set.add(c),
    remove: (c) => set.delete(c),
    toggle: (c, on) => (on ? set.add(c) : set.delete(c)),
    contains: (c) => set.has(c),
  };
}

function makeHook({ iso = "", text, format = "d.m.Y", required = false, submitForm = false, extra = {} } = {}) {
  const attrs = {};
  const textEl = {
    value: text === undefined ? (iso ? formatDateIso(iso, format) : "") : text,
    defaultValue: "",
    required: false, // the server leaves it off; the hook sets it from data-required
    classList: fakeClassList(),
    validity: "",
    setCustomValidity(m) { this.validity = m; },
    setAttribute(k, v) { attrs[k] = v; },
    removeAttribute(k) { delete attrs[k]; },
    getAttribute(k) { return k in attrs ? attrs[k] : extra.attrs && k in extra.attrs ? extra.attrs[k] : null; },
    hasAttribute(k) { return k in attrs || (extra.attrs && k in extra.attrs); },
    disabled: !!extra.textDisabled,
    matches(sel) { return sel === ":disabled" && (this.disabled || !!extra.fieldsetDisabled); },
    readOnly: !!extra.textReadOnly,
    focus() { global.document.activeElement = textEl; },
  };
  textEl.defaultValue = extra.defaultText !== undefined ? extra.defaultText : textEl.value;
  const formListeners = [];
  const form = {
    hasAttribute: (k) => submitForm && k === "phx-submit",
    addEventListener(type, fn) { formListeners.push(["add", type, fn]); },
    removeEventListener(type, fn) { formListeners.push(["remove", type, fn]); },
  };
  const events = [];
  const dispatched = [];
  const valueAttrs = { required: "", ...(extra.valueAttrs || {}) };
  const valueEl = {
    value: iso,
    defaultValue: extra.defaultIso !== undefined ? extra.defaultIso : iso,
    disabled: false,
    attrs: valueAttrs,
    setAttribute(k, v) { valueAttrs[k] = v; },
    removeAttribute(k) { delete valueAttrs[k]; },
    getAttribute(k) {
      if (k === "value") return "serverValue" in extra ? extra.serverValue : this.defaultValue === "" ? null : this.defaultValue;
      return k in valueAttrs ? valueAttrs[k] : null;
    },
    validity: extra.validity,
    form,
    dispatchEvent(e) { events.push([e.type, this.value]); dispatched.push(e); },
    showPicker() { this.picked = true; },
  };
  const clearBtn = { classList: fakeClassList() };
  const hintEl = { textContent: "" };
  const listeners = [];
  const inside = new Set();
  const elAttrs = {};
  const el = {
    dataset: { format, today: TODAY, expected: "Expected 16.10.2026", ...(required ? { required: "true" } : {}), ...(extra.dataset || {}) },
    attrs: elAttrs,
    setAttribute(k, v) { elAttrs[k] = v; },
    addEventListener(type, fn) { listeners.push([type, fn]); },
    closest: () => null,
    contains: (node) => inside.has(node),
    isConnected: true,
    removeAttribute(k) { delete elAttrs[k]; },
    querySelector(sel) {
      return {
        "[data-date-text]": textEl,
        "[data-date-value]": valueEl,
        "[data-clear]": clearBtn,
        "[data-date-hint]": hintEl,
      }[sel] || null;
    },
  };
  const hook = Object.assign(Object.create(hookDef), { el });
  const jsCalls = [];
  hook.js = () => ({ setAttribute(node, k, v) { jsCalls.push([node, k, v]); node.setAttribute(k, v); } });
  global.document.activeElement = extra.focusValue ? valueEl : extra.active || null;
  hook.mounted();
  return { jsCalls, hook, el, textEl, valueEl, clearBtn, hintEl, events, attrs, dispatched, listeners, formListeners, inside };
}

const keydown = (key) => ({ key, isComposing: false, prevented: false, preventDefault() { this.prevented = true; } });

test("typed text is committed on blur: one input event, text normalised", () => {
  const h = makeHook({ iso: "2026-10-16" });
  h.hook.baseText = "16.10.2026";
  h.textEl.value = "1.2.26";
  h.hook.onTextBlur();
  assert.deepEqual(h.events, [["input", "2026-02-01"]]);
  assert.equal(h.textEl.value, "01.02.2026");
});

test("an unchanged text commits nothing on blur", () => {
  const h = makeHook({ iso: "2026-10-16" });
  h.hook.onTextBlur();
  assert.deepEqual(h.events, []);
});

test("rejected text: value unchanged, marked, and put back after a patch", () => {
  const h = makeHook({ iso: "2026-10-16" });
  h.textEl.value = "16.1";
  assert.equal(h.hook.commit(), false);
  assert.deepEqual(h.events, []);
  assert.equal(h.valueEl.value, "2026-10-16");
  assert.ok(h.textEl.classList.contains("input-error"));
  assert.equal(h.attrs["aria-invalid"], "true");
  assert.equal(h.textEl.validity, "Expected 16.10.2026");

  // A form patch rewrites the field from the server's unchanged date and
  // strips what the server did not render.
  h.textEl.value = "16.10.2026";
  h.textEl.classList.remove("input-error");
  delete h.attrs["aria-invalid"];
  h.textEl.setCustomValidity("");
  h.hook.updated();
  assert.equal(h.textEl.value, "16.1");
  assert.ok(h.textEl.classList.contains("input-error"));
  assert.equal(h.attrs["aria-invalid"], "true");
  assert.equal(h.textEl.validity, "Expected 16.10.2026");
});

test("a rejected mark survives a patch while the field is focused again", () => {
  const h = makeHook({ iso: "2026-10-16" });
  h.textEl.value = "16.1";
  h.hook.commit();
  global.document.activeElement = h.textEl;
  h.hook.updated();
  assert.equal(h.textEl.value, "16.1", "the user's text is not touched while focused");
  assert.ok(h.textEl.classList.contains("input-error"));
});

test("a server change of the date beats rejected text", () => {
  const h = makeHook({ iso: "2026-10-16" });
  h.textEl.value = "16.1";
  h.hook.commit();
  h.valueEl.value = "2026-11-01";
  h.textEl.value = "garbage from the patch";
  h.hook.updated();
  assert.equal(h.textEl.value, "01.11.2026");
  assert.ok(!h.textEl.classList.contains("input-error"));
  assert.equal(h.hook.rejected, null);
});

test("a server change while focused is synced on blur, not lost", () => {
  const h = makeHook({ iso: "2026-10-16" });
  global.document.activeElement = h.textEl;
  h.valueEl.value = "2026-10-20";
  h.hook.updated();
  assert.equal(h.textEl.value, "16.10.2026", "not touched while focused");
  h.hook.onTextBlur();
  assert.equal(h.textEl.value, "20.10.2026");
  assert.deepEqual(h.events, [], "the server's value is not sent back");
});

test("Enter after a server change while focused does not overwrite the server's date", () => {
  const h = makeHook({ iso: "2026-10-16" });
  global.document.activeElement = h.textEl;
  h.valueEl.value = "2026-10-20";
  h.hook.updated();
  assert.equal(h.hook.commit(), true);
  assert.equal(h.valueEl.value, "2026-10-20");
  assert.deepEqual(h.events, []);
});

test("text typed before connect: committed when the field is not focused", () => {
  const h = makeHook({ iso: "2026-10-16", text: "20.10.2026", extra: { defaultText: "16.10.2026" } });
  assert.deepEqual(h.events, [["input", "2026-10-20"]]);
});

test("text typed before connect is left to blur/Enter while the user is still typing", () => {
  const h = makeHook({ iso: "2026-10-16", text: "16.10.20", extra: { defaultText: "16.10.2026" } });
  // makeHook mounted unfocused and committed; redo it focused on the same field.
  const el = h.hook.el;
  const text = el.querySelector("[data-date-text]");
  const value = el.querySelector("[data-date-value]");
  value.value = "2026-10-16";
  h.events.length = 0;
  text.value = "16.10.20";
  global.document.activeElement = text;
  const hook2 = Object.assign(Object.create(hookDef), { el });
  hook2.mounted();
  assert.deepEqual(h.events, []);
  assert.equal(value.value, "2026-10-16");
  assert.equal(text.value, "16.10.20");
  assert.equal(hook2.baseText, "16.10.2026", "blur will commit what was typed");
});

test("opening the calendar commits pending text first", () => {
  const h = makeHook({ iso: "2026-10-16" });
  global.window.matchMedia = () => ({ matches: true });
  h.textEl.value = "20.10.2026";
  h.hook.open();
  global.window.matchMedia = () => ({ matches: false });
  assert.deepEqual(h.events, [["input", "2026-10-20"]]);
  assert.ok(h.valueEl.picked, "the phone path opens the native picker");
});

test("emptying a required field keeps the date and marks the field", () => {
  const h = makeHook({ iso: "2026-10-16", required: true });
  h.textEl.value = "";
  assert.equal(h.hook.commit(), false);
  assert.equal(h.valueEl.value, "2026-10-16");
  assert.deepEqual(h.events, []);
  assert.ok(h.textEl.classList.contains("input-error"));
});

test("emptying an optional field clears the value", () => {
  const h = makeHook({ iso: "2026-10-16" });
  h.textEl.value = "";
  assert.equal(h.hook.commit(), true);
  assert.deepEqual(h.events, [["input", ""]]);
});

test("Enter: prevented for invalid text and for a phx-change-only form, not for a valid phx-submit form", () => {
  let h = makeHook({ iso: "2026-10-16", submitForm: true });
  h.textEl.value = "16.1";
  let e = keydown("Enter");
  h.hook.onTextKeydown(e);
  assert.ok(e.prevented);

  h = makeHook({ iso: "2026-10-16", submitForm: true });
  h.textEl.value = "20.10.2026";
  e = keydown("Enter");
  h.hook.onTextKeydown(e);
  assert.ok(!e.prevented);
  assert.deepEqual(h.events, [["input", "2026-10-20"]], "committed before the submit");

  h = makeHook({ iso: "2026-10-16", submitForm: false });
  e = keydown("Enter");
  h.hook.onTextKeydown(e);
  assert.ok(e.prevented);
});

test("clearing forgets a refusal and leaves no mark", () => {
  const h = makeHook({ iso: "2026-10-16" });
  h.textEl.value = "16.1";
  h.hook.commit();
  h.hook.clear();
  assert.equal(h.hook.rejected, null);
  assert.ok(!h.textEl.classList.contains("input-error"));
  assert.deepEqual(h.events, [["input", ""]]);
});

test("the clear button follows the text", () => {
  const h = makeHook({ iso: "" });
  assert.ok(h.clearBtn.classList.contains("hidden"));
  h.textEl.value = "1";
  h.hook.toggleClear();
  assert.ok(!h.clearBtn.classList.contains("hidden"));
});

test("checkDateText tells a bad format from a date outside min/max", () => {
  assert.deepEqual(checkDateText("16.10.2026", "d.m.Y"), { iso: "2026-10-16" });
  assert.deepEqual(checkDateText("16.1", "d.m.Y"), { error: "format" });
  assert.deepEqual(checkDateText("31.02.2026", "d.m.Y"), { error: "format" });
  assert.deepEqual(checkDateText("", "d.m.Y"), { error: "format" });
  assert.deepEqual(checkDateText("15.10.2026", "d.m.Y", "2026-10-16", null), { error: "range" });
  assert.deepEqual(checkDateText("17.10.2026", "d.m.Y", null, "2026-10-16"), { error: "range" });
});

test("a date outside min/max is refused with the range message, bad text with the format hint", () => {
  const dataset = { min: "2026-10-01", max: "2026-10-31", rangeMessage: "Pick a date between 01.10.2026 and 31.10.2026" };
  let h = makeHook({ iso: "2026-10-16", extra: { dataset } });
  h.textEl.value = "05.11.2026";
  assert.equal(h.hook.commit(), false);
  assert.equal(h.textEl.validity, "Pick a date between 01.10.2026 and 31.10.2026");
  assert.equal(h.attrs.title, "Pick a date between 01.10.2026 and 31.10.2026");

  h = makeHook({ iso: "2026-10-16", extra: { dataset } });
  h.textEl.value = "5.11";
  assert.equal(h.hook.commit(), false);
  assert.equal(h.textEl.validity, "Expected 16.10.2026");
});

test("no showPicker: the calendar opens; with no calendar either, the text keeps the focus", () => {
  const h = makeHook({ iso: "2026-10-16" });
  delete h.valueEl.showPicker;
  let popups = 0;
  h.hook.popupEl = () => ({ showPopover() {} });
  h.hook.openPopup = (nativeOnFail) => { popups += 1; assert.equal(nativeOnFail, false); };
  h.hook.open();
  assert.equal(popups, 1);

  const g = makeHook({ iso: "2026-10-16" });
  delete g.valueEl.showPicker;
  g.hook.popupEl = () => null;
  g.hook.open();
  assert.equal(global.document.activeElement, g.textEl);
});

test("a showPicker that throws falls back to the calendar, or the text field", () => {
  const h = makeHook({ iso: "2026-10-16" });
  h.valueEl.showPicker = () => { throw new Error("NotAllowedError"); };
  global.window.matchMedia = () => ({ matches: true });
  let popups = 0;
  h.hook.popupEl = () => ({ showPopover() {} });
  h.hook.openPopup = () => { popups += 1; };
  h.hook.open();
  assert.equal(popups, 1);

  const g = makeHook({ iso: "2026-10-16" });
  g.valueEl.showPicker = () => { throw new Error("x"); };
  g.hook.popupEl = () => null;
  g.hook.open();
  global.window.matchMedia = () => ({ matches: false });
  assert.equal(global.document.activeElement, g.textEl);
});

// ---------------------------------------------------------------------------
// The wiring to LiveView and to the surrounding dialog: what the hook does
// through its registered listener (`handle`), not by calling its parts.
// ---------------------------------------------------------------------------
function domEvent(type, target, extra = {}) {
  return {
    type,
    target,
    key: undefined,
    isComposing: false,
    prevented: false,
    stopped: false,
    preventDefault() { this.prevented = true; },
    stopPropagation() { this.stopped = true; },
    ...extra,
  };
}

// An element-ish click target: `closest(sel)` answers for the given selectors.
const clickTarget = (...selectors) => ({
  closest: (sel) => (selectors.includes(sel) ? { sel } : null),
});

// The listener the hook registered on its element for `type`.
function listenerFor(h, type) {
  const found = h.listeners.find(([t]) => t === type);
  assert.ok(found, `no ${type} listener on the hook element`);
  return found[1];
}

// Stand-in for the popup: open/closed, and a record of closePopup calls.
function stubPopup(h, open = true) {
  const closes = [];
  h.hook.popupOpen = () => open;
  h.hook.closePopup = (refocus) => closes.push(refocus);
  return closes;
}

test("the hook listens for every event its wiring depends on, all through handle()", () => {
  const h = makeHook({ iso: "2026-10-16" });
  const types = h.listeners.map(([t]) => t).sort();
  assert.deepEqual(types, ["change", "click", "focusin", "focusout", "input", "keydown", "mousedown"]);

  // The registered listener is the hook's handler: an input event on the text
  // field sent through it is stopped.
  const e = domEvent("input", h.textEl);
  listenerFor(h, "input")(e);
  assert.ok(e.stopped);
});

test("a commit fires a bubbling input event on the value element", () => {
  const h = makeHook({ iso: "2026-10-16" });
  h.textEl.value = "20.10.2026";
  h.hook.commit();
  assert.equal(h.dispatched.length, 1);
  assert.equal(h.dispatched[0].type, "input");
  // LiveView listens on the window: a commit that does not bubble never reaches the server.
  assert.equal(h.dispatched[0].bubbles, true);
  // The same goes for a calendar pick and the clear button.
  h.hook.pick("2026-10-25");
  h.hook.clear();
  assert.equal(h.dispatched.length, 3);
  assert.ok(h.dispatched.every((e) => e.type === "input" && e.bubbles === true));
});

test("the visible text's input and change events never leave the component", () => {
  const h = makeHook({ iso: "2026-10-16" });
  for (const type of ["input", "change"]) {
    const e = domEvent(type, h.textEl);
    h.hook.handle(e);
    assert.ok(e.stopped, `${type} from the text field must be stopped`);
  }
  // The value element's own events are the ones LiveView must see.
  for (const type of ["input", "change"]) {
    const e = domEvent(type, h.valueEl);
    h.hook.handle(e);
    assert.ok(!e.stopped, `${type} from the value element must pass`);
  }
});

test("a native change on the value element (the phone picker) syncs the text", () => {
  const h = makeHook({ iso: "2026-10-16" });
  h.valueEl.value = "2026-11-02";
  h.hook.handle(domEvent("change", h.valueEl));
  assert.equal(h.textEl.value, "02.11.2026");
});

test("Escape closes an open calendar and stops there; with it closed it passes through", () => {
  const h = makeHook({ iso: "2026-10-16" });
  const closes = stubPopup(h, true);
  const e = domEvent("keydown", h.textEl, { key: "Escape" });
  h.hook.handle(e);
  assert.ok(e.prevented, "preventDefault");
  assert.ok(e.stopped, "stopPropagation: a surrounding dialog must not see it");
  assert.deepEqual(closes, [true], "closed, focus back on the field");

  const g = makeHook({ iso: "2026-10-16" });
  const none = stubPopup(g, false);
  const e2 = domEvent("keydown", g.textEl, { key: "Escape" });
  g.hook.handle(e2);
  assert.ok(!e2.prevented && !e2.stopped, "a closed calendar leaves Escape to the dialog");
  assert.deepEqual(none, []);
});

test("focus leaving the component closes the calendar; focus moving inside does not", () => {
  const h = makeHook({ iso: "2026-10-16" });
  const closes = stubPopup(h, true);
  h.hook.handle(domEvent("focusout", h.textEl, { relatedTarget: {} }));
  assert.deepEqual(closes, [false], "an outside relatedTarget closes it, without stealing focus back");

  const inner = {};
  h.inside.add(inner);
  closes.length = 0;
  h.hook.handle(domEvent("focusout", h.textEl, { relatedTarget: inner }));
  h.hook.handle(domEvent("focusout", h.textEl, { relatedTarget: null }));
  assert.deepEqual(closes, [], "focus moving inside the component, or nowhere, keeps it open");

  const g = makeHook({ iso: "2026-10-16" });
  const shut = stubPopup(g, false);
  g.hook.handle(domEvent("focusout", g.textEl, { relatedTarget: {} }));
  assert.deepEqual(shut, [], "nothing to close");
});

test("a day outside min/max is not taken from the calendar or from Today", () => {
  const dataset = { min: "2026-10-01", max: "2026-10-31" };
  const h = makeHook({ iso: "2026-10-16", extra: { dataset } });
  const closes = stubPopup(h, true);

  h.hook.pick("2026-11-05");
  h.hook.pick("2026-09-30");
  h.hook.pick("garbage");
  assert.deepEqual(h.events, []);
  assert.equal(h.valueEl.value, "2026-10-16");
  assert.deepEqual(closes, [], "a refused day leaves the calendar open");

  // The "Today" button with today outside the range does nothing either.
  const late = makeHook({ iso: "2026-10-16", extra: { dataset: { ...dataset, today: "2026-12-01" } } });
  late.hook.handle(domEvent("click", clickTarget("[data-popup-today]")));
  assert.deepEqual(late.events, []);

  // Inside the range both go through.
  h.hook.pick("2026-10-20");
  assert.deepEqual(h.events, [["input", "2026-10-20"]]);
  assert.deepEqual(closes, [true]);
  h.hook.handle(domEvent("click", clickTarget("[data-popup-today]")));
  assert.deepEqual(h.events, [["input", "2026-10-20"], ["input", TODAY]]);
});

test("the popup's Clear button clears the field and closes the calendar", () => {
  const h = makeHook({ iso: "2026-10-16" });
  const closes = stubPopup(h, true);
  h.hook.handle(domEvent("click", clickTarget("[data-popup-clear]")));
  assert.deepEqual(h.events, [["input", ""]]);
  assert.deepEqual(closes, [true]);
});

test("the form's reset puts the text back in step with the restored value", async () => {
  const h = makeHook({ iso: "2026-10-16" });
  const adds = h.formListeners.filter(([op, type]) => op === "add" && type === "reset");
  assert.equal(adds.length, 1, "a reset listener is registered on the value element's form");

  // The browser restores the value element's default; the text must follow.
  h.valueEl.value = "2026-10-01";
  h.textEl.value = "garbage";
  adds[0][2]();
  await new Promise((resolve) => setTimeout(resolve, 5));
  assert.equal(h.textEl.value, "01.10.2026");

  // destroyed() takes it off again.
  h.hook.destroyed();
  assert.ok(h.formListeners.some(([op, type, fn]) => op === "remove" && type === "reset" && fn === adds[0][2]));
});

// ---------------------------------------------------------------------------
// Progressive enhancement: the server renders a native date input; the hook
// turns it into the invisible value element behind the text field.
// ---------------------------------------------------------------------------
test("mounting enhances: the wrapper is flagged, the date input is hidden from the keyboard and screen readers", () => {
  const h = makeHook({ iso: "2026-10-16" });
  assert.ok("data-enhanced" in h.el.attrs);
  assert.equal(h.valueEl.attrs.tabindex, "-1");
  assert.equal(h.valueEl.attrs["aria-hidden"], "true");
});

test("required moves from the date input to the text field", () => {
  const h = makeHook({ iso: "2026-10-16", extra: { dataset: { required: "true" } } });
  assert.ok(!("required" in h.valueEl.attrs), "a required control that is not displayed would block the submit");
  assert.equal(h.textEl.required, true);

  const g = makeHook({ iso: "2026-10-16" });
  assert.equal(g.textEl.required, false);
});

test("text restored by the browser before connect is judged as a required field's text", () => {
  // Emptied text on a required field is refused, not committed as a clear: the
  // hook must know the field is required before it commits at mount.
  const h = makeHook({ iso: "2026-10-16", text: "", required: true, extra: { defaultText: "16.10.2026" } });
  assert.deepEqual(h.events, []);
  assert.equal(h.valueEl.value, "2026-10-16");
  assert.ok(h.textEl.classList.contains("input-error"));
});

test("a patch that puts the server's markup back is enhanced again", () => {
  const h = makeHook({ iso: "2026-10-16", extra: { dataset: { required: "true" } } });
  // The patch restores what the server rendered: no flag, required on the date input.
  delete h.el.attrs["data-enhanced"];
  delete h.valueEl.attrs.tabindex;
  delete h.valueEl.attrs["aria-hidden"];
  h.valueEl.attrs.required = "";
  h.textEl.required = false;
  h.hook.updated();
  assert.ok("data-enhanced" in h.el.attrs);
  assert.equal(h.valueEl.attrs.tabindex, "-1");
  assert.equal(h.valueEl.attrs["aria-hidden"], "true");
  assert.ok(!("required" in h.valueEl.attrs));
  assert.equal(h.textEl.required, true);
});

test("a date picked in the native input before the socket connected is carried over", () => {
  const h = makeHook({ iso: "2026-10-20", text: "16.10.2026", extra: { defaultIso: "2026-10-16", defaultText: "16.10.2026" } });
  assert.equal(h.textEl.value, "20.10.2026", "the text follows the date that was picked");
  assert.equal(h.dispatched.length, 1, "and the server is told");
  assert.equal(h.dispatched[0].type, "input");
  assert.equal(h.dispatched[0].bubbles, true);

  const g = makeHook({ iso: "2026-10-16" });
  assert.deepEqual(g.events, [], "an untouched date input sends nothing");
});

test("a server value that is not an ISO date is left alone: no pick, no event, the echoed text stays", () => {
  // The browser sanitises such a `value` to "" while `defaultValue` keeps the
  // attribute text; "" differs from it, but nothing was picked.
  for (const echoed of ["2026-10-16T10:00:00Z", "garbage", "2026-02-31"]) {
    const h = makeHook({ iso: "", text: echoed, extra: { defaultIso: echoed, defaultText: echoed } });
    assert.deepEqual(h.events, [], `${echoed}: nothing is sent to the server`);
    assert.equal(h.textEl.value, echoed, `${echoed}: the text is shown as given`);
    assert.equal(h.valueEl.value, "", echoed);

    // A pick after that still goes through.
    h.valueEl.value = "2026-10-20";
    h.hook.handle(domEvent("input", h.valueEl));
    assert.equal(h.textEl.value, "20.10.2026", echoed);
  }

  // A real default that the person then changes is still a pick.
  const p = makeHook({ iso: "2026-10-20", text: "03.05.2024", extra: { defaultIso: "2026-02-31", defaultText: "03.05.2024" } });
  assert.deepEqual(p.events, [["input", "2026-10-20"]]);
});

test("the native input focused at connect hands its focus to the text field", () => {
  const h = makeHook({ iso: "2026-10-20", text: "16.10.2026", extra: { focusValue: true, defaultIso: "2026-10-16", defaultText: "16.10.2026" } });
  assert.equal(global.document.activeElement, h.textEl, "keystrokes must not go to the invisible control");
  assert.equal(h.textEl.value, "20.10.2026", "the carried-over pick is shown");
  assert.equal(h.dispatched.length, 1, "told to the server once");

  // Focus anywhere else stays where it is.
  const other = {};
  const k = makeHook({ iso: "2026-10-16" });
  global.document.activeElement = other;
  k.hook.updated();
  assert.equal(global.document.activeElement, other);
});

test("autofocus on the text field is honoured at mount", () => {
  const h = makeHook({ iso: "2026-10-16", extra: { attrs: { autofocus: "" } } });
  assert.equal(global.document.activeElement, h.textEl);

  const g = makeHook({ iso: "2026-10-16" });
  assert.equal(global.document.activeElement, null, "no autofocus, no focus");

  // The page body holds the focus when nothing was clicked: that is "nothing".
  const b = makeHook({ iso: "2026-10-16", extra: { attrs: { autofocus: "" }, active: global.document.body } });
  assert.equal(global.document.activeElement, b.textEl);

  // The native date input holding it at connect is the field's own.
  const n = makeHook({ iso: "2026-10-16", extra: { attrs: { autofocus: "" }, focusValue: true } });
  assert.equal(global.document.activeElement, n.textEl);
});

test("autofocus never takes the focus from a field the person is already using", () => {
  const other = { name: "another text field" };
  const h = makeHook({ iso: "2026-10-16", extra: { attrs: { autofocus: "" }, active: other } });
  assert.equal(global.document.activeElement, other);
});

test("a stored value the date input cannot hold is marked at mount, not silently erased on save", () => {
  for (const echoed of ["2024-5-3x", "garbage"]) {
    const h = makeHook({ iso: "", text: echoed, extra: { defaultIso: echoed, defaultText: echoed } });
    assert.deepEqual(h.events, [], `${echoed}: nothing is sent`);
    assert.equal(h.textEl.value, echoed, `${echoed}: shown as given`);
    assert.ok(h.textEl.classList.contains("input-error"), echoed);
    assert.equal(h.attrs["aria-invalid"], "true", echoed);
    assert.equal(h.textEl.validity, "Expected 16.10.2026", `${echoed}: blocks a submit`);
    assert.equal(h.hintEl.textContent, "Expected 16.10.2026", echoed);
    assert.deepEqual(h.hook.rejected, { text: echoed, reason: "format" }, echoed);
  }

  // Correcting it clears the mark; a patch before that keeps the shown text.
  const h = makeHook({ iso: "", text: "garbage", extra: { defaultIso: "garbage", defaultText: "garbage" } });
  h.hook.updated();
  assert.equal(h.textEl.value, "garbage");
  assert.ok(h.textEl.classList.contains("input-error"));
  h.textEl.value = "04.05.2024";
  assert.equal(h.hook.commit(), true);
  assert.deepEqual(h.events, [["input", "2024-05-04"]]);
  assert.ok(!h.textEl.classList.contains("input-error"));
  assert.equal(h.textEl.validity, "");

  // An empty field, a real date and a typed-before-connect date are not marked.
  for (const m of [
    makeHook({ iso: "", text: "" }),
    makeHook({ iso: "2026-10-16" }),
    makeHook({ iso: "2026-10-16", text: "20.10.2026", extra: { defaultText: "16.10.2026" } }),
  ]) {
    assert.equal(m.hook.rejected, null);
    assert.ok(!m.textEl.classList.contains("input-error"));
  }
});

// ---------------------------------------------------------------------------
// The rejection hint (a live region the text input points at).
// ---------------------------------------------------------------------------
test("a rejected entry is said in the hint; a good one, a clear or a server date empties it", () => {
  const dataset = { min: "2026-10-01", max: "2026-10-31", rangeMessage: "Pick a date between 01.10.2026 and 31.10.2026" };
  const h = makeHook({ iso: "2026-10-16", extra: { dataset } });
  assert.equal(h.hintEl.textContent, "");

  h.textEl.value = "5.11";
  h.hook.commit();
  assert.equal(h.hintEl.textContent, "Expected 16.10.2026");

  h.textEl.value = "05.11.2026";
  h.hook.commit();
  assert.equal(h.hintEl.textContent, "Pick a date between 01.10.2026 and 31.10.2026");

  h.textEl.value = "20.10.2026";
  h.hook.commit();
  assert.equal(h.hintEl.textContent, "");

  h.textEl.value = "5.11";
  h.hook.commit();
  h.hook.clear();
  assert.equal(h.hintEl.textContent, "");
});

test("a patch does not rewrite an unchanged hint", () => {
  const h = makeHook({ iso: "2026-10-16" });
  h.textEl.value = "16.1";
  h.hook.commit();
  let writes = 0;
  let text = h.hintEl.textContent;
  Object.defineProperty(h.hintEl, "textContent", { get: () => text, set: (v) => { writes += 1; text = v; } });
  h.hook.updated();
  h.hook.updated();
  assert.equal(writes, 0, "rewriting a live region makes a screen reader say it again");
  assert.equal(text, "Expected 16.10.2026");
});

// ---------------------------------------------------------------------------
// The calendar popup's footer lives in a <template> LiveView does not patch.
// ---------------------------------------------------------------------------
function stubFooter() {
  const today = { disabled: false };
  const clear = { classList: fakeClassList() };
  clear.classList.add("hidden");
  return {
    today,
    clear,
    popup: { querySelector: (sel) => ({ "[data-popup-today]": today, "[data-popup-clear]": clear }[sel] || null) },
  };
}

test("Today is disabled when today lies outside min/max, read from the wrapper at each open", () => {
  const f = stubFooter();
  const h = makeHook({ iso: "2026-10-16", extra: { dataset: { max: "2026-10-10" } } });
  h.hook.syncFooter(f.popup);
  assert.equal(f.today.disabled, true);

  // The range follows another field and moves: the next open sees it.
  h.el.dataset.max = "2026-12-31";
  h.hook.syncFooter(f.popup);
  assert.equal(f.today.disabled, false);

  h.el.dataset.min = "2026-10-17";
  h.hook.syncFooter(f.popup);
  assert.equal(f.today.disabled, true);
});

test("the popup's Clear shows only for a clearable field", () => {
  const f = stubFooter();
  const h = makeHook({ iso: "2026-10-16" });
  h.hook.syncFooter(f.popup);
  assert.ok(f.clear.classList.contains("hidden"));

  h.el.dataset.clearable = "true";
  h.hook.syncFooter(f.popup);
  assert.ok(!f.clear.classList.contains("hidden"));
});

// ---------------------------------------------------------------------------
// What closes the popup, and the calendar's locale.
// ---------------------------------------------------------------------------
test("the popup closes on the page's or an ancestor's scroll, not on an unrelated panel's", () => {
  const h = makeHook({ iso: "2026-10-16" });
  const inPopup = {};
  const popup = { contains: (n) => n === inPopup };
  h.hook.popupEl = () => popup;
  const closes = [];
  h.hook.closePopup = (refocus) => closes.push(refocus);
  h.hook.bindClosers();

  const scroll = h.hook.closers.find(([target, type]) => target === global.window && type === "scroll")[2];
  scroll({ target: { contains: () => false } });
  scroll({ target: inPopup });
  assert.deepEqual(closes, [], "an unrelated panel and the calendar's own scrolling keep it open");

  scroll({ target: { contains: (n) => n === h.el } });
  scroll({ target: global.document });
  assert.deepEqual(closes, [false, false]);
});

test("the calendar is Gregorian whatever the language's default calendar is", () => {
  assert.equal(calendarLocale("de"), "de-u-ca-gregory");
  assert.equal(calendarLocale("th"), "th-u-ca-gregory");
  assert.equal(calendarLocale("ar-SA"), "ar-SA-u-ca-gregory");
  assert.equal(calendarLocale("th-u-ca-buddhist"), "th-u-ca-buddhist", "a tag that names a calendar is left alone");
  assert.equal(calendarLocale(undefined), "en-u-ca-gregory");
  // Intl takes the tags it produces (and the calendar really is Gregorian).
  for (const tag of ["de", "th", "ar-SA", "fa"]) {
    const resolved = new Intl.DateTimeFormat(calendarLocale(tag)).resolvedOptions();
    assert.equal(resolved.calendar, "gregory", tag);
  }
});

test("the calendar is built with the Gregorian locale, the week start and today", () => {
  const h = makeHook({ iso: "2026-10-16", extra: { dataset: { locale: "th", weekStart: "0" } } });
  const attrs = {};
  const cal = { setAttribute: (k, v) => { attrs[k] = v; }, addEventListener() {} };
  const popup = { appendChild() {}, querySelector: (sel) => (sel === "calendar-date" ? cal : null) };
  const query = h.el.querySelector;
  h.el.querySelector = (sel) => (sel === "[data-popup-template]" ? { content: { cloneNode: () => ({}) } } : query(sel));
  assert.equal(h.hook.buildPopup(popup), true);
  assert.equal(attrs.locale, "th-u-ca-gregory");
  assert.equal(attrs["first-day-of-week"], "0");
  assert.equal(attrs.today, TODAY);
});

test("opening the calendar sets its footer from the wrapper's current data", () => {
  const h = makeHook({ iso: "2026-10-16", extra: { dataset: { max: "2026-10-10", clearable: "true" } } });
  const f = stubFooter();
  const calAttrs = {};
  const cal = {
    setAttribute: (k, v) => { calAttrs[k] = v; },
    removeAttribute: (k) => { delete calAttrs[k]; },
    focus() {},
  };
  const popup = {
    style: {},
    showPopover() { this.open = true; },
    matches() { return !!this.open; },
    contains: () => false,
    querySelector: (sel) => (sel === "calendar-date" ? cal : f.popup.querySelector(sel)),
  };
  h.hook.popupEl = () => popup;
  const raf = global.requestAnimationFrame;
  global.requestAnimationFrame = () => 0;
  try {
    h.hook.showPopup();
  } finally {
    global.requestAnimationFrame = raf;
    h.hook.closers = null;
  }
  assert.ok(popup.open, "the popup opened");
  assert.equal(calAttrs.max, "2026-10-10");
  assert.equal(f.today.disabled, true, "today is past max");
  assert.ok(!f.clear.classList.contains("hidden"), "a clearable field shows Clear");
});

// ---------------------------------------------------------------------------
// Review fixes (PR #936): sticky swap, hand-off at mount only, connect-time
// picks, stored values, a stylesheet without the utilities, caller's title.
// ---------------------------------------------------------------------------
test("the enhanced flag is set through the DOM-patch-aware js() command, once, at mount", () => {
  const h = makeHook({ iso: "2026-10-16" });
  assert.equal(h.jsCalls.length, 1);
  assert.equal(h.jsCalls[0][0], h.el);
  assert.equal(h.jsCalls[0][1], "data-enhanced");
  h.hook.updated();
  h.hook.updated();
  assert.equal(h.jsCalls.length, 1, "a patch does not queue another command");
});

test("the focus hand-off from the date input happens at mount only, not on a patch", () => {
  const h = makeHook({ iso: "2026-10-16" });
  global.document.activeElement = h.valueEl; // showPicker() focused it
  h.hook.updated();
  assert.equal(global.document.activeElement, h.valueEl);
});

test("a half-edited native date at connect is not a pick", () => {
  const h = makeHook({ iso: "", text: "16.10.2026", extra: { defaultIso: "2026-10-16", defaultText: "16.10.2026", validity: { badInput: true } } });
  assert.deepEqual(h.events, []);
  assert.equal(h.textEl.value, "16.10.2026");
});

test("a native date emptied at connect on a required field keeps the server's date and is refused", () => {
  const h = makeHook({ iso: "", text: "16.10.2026", required: true, extra: { defaultIso: "2026-10-16", defaultText: "16.10.2026" } });
  assert.deepEqual(h.events, [], "no empty value reaches the server");
  assert.equal(h.valueEl.value, "2026-10-16", "the date input holds the server's date again");
  assert.equal(h.textEl.value, "16.10.2026");
  assert.ok(h.hook.rejected);

  // An optional field: emptying it is a real clear.
  const g = makeHook({ iso: "", text: "16.10.2026", extra: { defaultIso: "2026-10-16", defaultText: "16.10.2026" } });
  assert.deepEqual(g.events, [["input", ""]]);
});

test("a stored value in the site format is taken, not marked, and survives a patch", () => {
  const h = makeHook({ iso: "", text: "03.05.2024", extra: { defaultIso: "03.05.2024", defaultText: "03.05.2024" } });
  assert.equal(h.hook.rejected, null);
  assert.ok(!h.textEl.classList.contains("input-error"));
  assert.equal(h.valueEl.value, "2024-05-03", "the form submits the stored date");
  assert.deepEqual(h.events, [], "the server already has it");

  // A patch re-renders the same text; the browser sanitises the value again.
  h.valueEl.value = "";
  h.hook.updated();
  assert.equal(h.valueEl.value, "2024-05-03");
  assert.equal(h.textEl.value, "03.05.2024");
});

test("a server change of a stored value drops the remembered rejection", () => {
  const h = makeHook({ iso: "", text: "garbage", extra: { defaultIso: "garbage", defaultText: "garbage" } });
  assert.ok(h.hook.rejected);
  // The server re-renders another record's value, then an empty one.
  h.textEl.value = "another";
  h.valueEl.defaultValue = "another";
  h.hook.updated();
  assert.deepEqual(h.hook.rejected, { text: "another", reason: "format" });
  h.textEl.value = "";
  h.valueEl.defaultValue = "";
  h.hook.updated();
  assert.equal(h.hook.rejected, null);
  assert.equal(h.textEl.value, "");
  assert.ok(!h.textEl.classList.contains("input-error"));
});

test("a stored value the date input cannot hold is not marked on a disabled or readonly field", () => {
  for (const flag of ["textDisabled", "textReadOnly", "fieldsetDisabled"]) {
    const h = makeHook({ iso: "", text: "garbage", extra: { defaultIso: "garbage", defaultText: "garbage", [flag]: true } });
    assert.equal(h.hook.rejected, null, flag);
    assert.ok(!h.textEl.classList.contains("input-error"), flag);
  }
});

test("a stylesheet without the swap utilities leaves the browser's date input in charge", () => {
  const saved = window.getComputedStyle;
  const warn = console.warn;
  const warnings = [];
  console.warn = (m) => warnings.push(m);
  window.getComputedStyle = () => ({ display: "none" });
  try {
    const h = makeHook({ iso: "2026-10-16", extra: { dataset: { required: "true" } } });
    assert.ok(!("data-enhanced" in h.el.attrs), "flag removed");
    assert.equal(h.jsCalls.length, 0, "no sticky flag");
    assert.ok(!("tabindex" in h.valueEl.attrs));
    assert.ok(!("aria-hidden" in h.valueEl.attrs));
    assert.ok("required" in h.valueEl.attrs, "required stays on the displayed control");
    assert.equal(h.textEl.required, false);
    assert.equal(warnings.length, 1);
    h.hook.updated();
    assert.ok(!("data-enhanced" in h.el.attrs), "stays that way after a patch");
    assert.equal(warnings.length, 1, "warned once");
    makeHook({ iso: "2026-10-16" });
    assert.equal(warnings.length, 1, "once per page, not per field");
  } finally {
    window.getComputedStyle = saved;
    console.warn = warn;
  }
});

test("a caller's title survives the rejection mark and comes back after it", () => {
  const h = makeHook({ iso: "2026-10-16", extra: { attrs: {} } });
  h.attrs.title = "Birthday";
  h.hook.refresh();
  assert.equal(h.attrs.title, "Birthday", "valid: untouched");
  h.textEl.value = "99.99.9999";
  h.hook.commit();
  assert.equal(h.attrs.title, "Expected 16.10.2026");
  h.textEl.value = "20.10.2026";
  h.hook.commit();
  assert.equal(h.attrs.title, "Birthday");
});

test("the echo of the value the hook sent does not wipe a rejection typed while the reply was in flight", () => {
  const h = makeHook({ iso: "2026-10-16" });
  h.textEl.value = "20.10.2026";
  h.hook.commit();
  assert.deepEqual(h.events, [["input", "2026-10-20"]]);
  h.textEl.value = "99.99";
  h.hook.commit();
  assert.ok(h.hook.rejected);
  h.valueEl.defaultValue = "2026-10-20";
  h.hook.updated();
  assert.deepEqual(h.hook.rejected, { text: "99.99", reason: "format" });
  assert.equal(h.textEl.value, "99.99");
});
