// ResumableUpload: a picked file is kept in the browser (IndexedDB) until the
// host says it saved it, and a transfer cut short — the OS sent the browser to
// the background, the socket dropped, the page remounted — is carried on by
// itself, exactly once.
//
// What has to hold between this hook and the server (PhoenixKitWeb.ResumableUploads):
//   - the file key is the three fields the server's `client_key/1` reads;
//   - the events each side sends are the ones the other handles;
//   - the answer to `pk_upload_resume` names records by the `id` the hook sent.
//
//   node --test test/js/upload_resume.test.cjs

const fs = require("fs");
const path = require("path");
const assert = require("node:assert");
const { test } = require("node:test");

const root = path.join(__dirname, "..", "..");
const src = fs.readFileSync(path.join(root, "priv", "static", "assets", "phoenix_kit.js"), "utf8");
const server = fs.readFileSync(path.join(root, "lib", "phoenix_kit_web", "resumable_uploads.ex"), "utf8");

function section() {
  const start = src.indexOf("// ResumableUpload — keep picked files until the host has them");
  const end = src.indexOf("// FolderDropUpload Hook");
  assert.ok(start !== -1 && end > start, "could not find the ResumableUpload section");
  return src.slice(start, end);
}
const hook = section();

// ---------------------------------------------------------------------------
// The contract with the server, read off both sources.
// ---------------------------------------------------------------------------

test("the file key matches the server's client_key/1 field for field", () => {
  const start = hook.indexOf("function uploadStashKey(");
  const body = hook.slice(start, hook.indexOf("\n  }\n", start) + 4);
  const key = new Function(body + "\nreturn uploadStashKey;")();
  assert.strictEqual(key({ name: "a b.png", size: 1234, lastModified: 1700000000000 }), "a b.png|1234|1700000000000");
  assert.match(server,
    /def client_key\(entry\),\s*do: "#\{entry\.client_name\}\|#\{entry\.client_size\}\|#\{entry\.client_last_modified\}"/);
});

test("every event the hook sends is handled by the server, and vice versa", () => {
  for (const ev of ["pk_upload_pick", "pk_upload_resume", "pk_upload_resume_click", "pk_upload_discard"]) {
    assert.ok(server.includes(ev), `the server handles ${ev}`);
  }
  assert.ok(hook.includes('"pk_upload_pick"') && hook.includes('"pk_upload_resume"'));
  for (const ev of ["pk-upload-received", "pk-upload-stored", "pk-upload-rejected", "pk-upload-feed", "pk-upload-drop"]) {
    assert.ok(hook.includes(`handleEvent("${ev}"`), `the hook handles ${ev}`);
    assert.ok(server.includes(`"${ev}"`), `the server pushes ${ev}`);
  }
});

test("the scope never comes from the URL (a sticky LiveView lives on many pages)", () => {
  assert.ok(!/location\.(pathname|search|href)/.test(hook));
});

test("a file is stashed in the capture phase, before LiveView reads it", () => {
  assert.match(hook, /addEventListener\("input", this\._onPick, true\)/);
  assert.match(hook, /input\.hasAttribute\("data-phx-upload-ref"\)/);
  assert.match(hook, /input\.name !== self\._upload/, "only this hook's upload, not another input of the page");
});

test("a file is handed back through the hook's own upload(), not a DataTransfer", () => {
  assert.match(hook, /self\.upload\(self\._upload, files\)/);
  assert.ok(!hook.includes("DataTransfer"));
});

// ---------------------------------------------------------------------------
// The hook run for real, against a fake store, fake Web Locks and a fake clock.
// ---------------------------------------------------------------------------

function pageLoad({ locks = true, rows, clock } = {}) {
  clock = clock || { t: 1_000_000 };
  const timers = [];
  const store = { rows: rows || [], failBlobPut: false, deleted: [], oldDbDeleted: 0 };
  const held = new Set();
  const win = {
    PhoenixKitHooks: {},
    indexedDB: { deleteDatabase: () => { store.oldDbDeleted++; } },
    navigator: locks ? {
      storage: { persist: () => { store.persisted = (store.persisted || 0) + 1; } },
      locks: {
        request(name, opts, cb) {
          if (held.has(name)) {
            if (opts && opts.ifAvailable) return Promise.resolve(cb(null));
            return Promise.reject(new Error("not needed"));
          }
          held.add(name);
          return Promise.resolve(cb({ name })).then(() => { held.delete(name); });
        },
      },
    } : {},
  };
  const doc = { listeners: {}, hooks: [], addEventListener(type, fn) { this.listeners[type] = fn; },
    querySelector() { return this.hooks[0] || null; } };
  const code = hook + `
    function uploadStashAll() { return Promise.resolve(store.rows.slice()); }
    function uploadStashPut(rec) {
      if (store.failBlobPut && rec.blob) return Promise.resolve(false);
      store.rows = store.rows.filter((x) => x.id !== rec.id).concat([rec]);
      return Promise.resolve(true);
    }
    function uploadStashDelete(ids) {
      store.deleted.push(...ids);
      store.rows = store.rows.filter((x) => ids.indexOf(x.id) === -1);
      return Promise.resolve(true);
    }
    function uploadStashUpdate(ids, change) {
      store.rows.forEach((r) => { if (ids.indexOf(r.id) !== -1) change(r); });
      return Promise.resolve(true);
    }
    function uploadStashClear() { store.rows = []; store.cleared = true; return Promise.resolve(true); }
    function uploadStashClearUser(user) { store.rows = store.rows.filter((r) => r.user !== user); store.clearedUser = user; return Promise.resolve(true); }
    return window.PhoenixKitHooks.ResumableUpload;`;
  const Hook = new Function("window", "store", "Date", "setTimeout", "clearTimeout",
    "setInterval", "clearInterval", "document", "console", code)(
    win, store, { now: () => clock.t },
    (fn, ms) => { const t = { fn, ms }; timers.push(t); return t; },
    (t) => { if (t) t.cleared = true; },
    () => ({}), () => {}, doc, { warn: (m) => { (store.warnings = store.warnings || []).push(m); } });
  return { Hook, win, doc, store, timers, clock, held, tick: (ms) => { clock.t += ms; } };
}

// A hook instance mounted into a page load (mounted() really runs).
function mount(page, opts = {}) {
  const { user = "u1", scope = "rec|1", upload = "photos", context = "k1", freshMs, watch } = opts;
  const pushed = [];
  const uploaded = [];
  const handlers = {};
  const input = { tagName: "INPUT", type: "file", name: upload, files: [],
    hasAttribute: () => true, form: { id: "f", hasAttribute: () => true } };
  const ctx = Object.assign(Object.create(page.Hook), {
    el: {
      dataset: { upload, scope, user, context, freshMs, watch },
      addEventListener() {}, removeEventListener() {},
      querySelector: () => input,
    },
    handleEvent: (name, fn) => { handlers[name] = fn; },
    pushEvent: (name, payload, cb) => pushed.push({ name, payload, cb }),
    upload: (name, files) => uploaded.push({ name, files }),
  });
  ctx.mounted();
  const pick = (...files) => { input.files = files; ctx._onPick({ target: input }); };
  return { ctx, pushed, uploaded, handlers, input, pick };
}

const settle = async () => { for (let i = 0; i < 8; i++) await new Promise((r) => setImmediate(r)); };
const file = (name, extra) => Object.assign(new File(["12345"], name, { type: "image/png", lastModified: 7 }), extra);

async function runScan(page) {
  const scan = page.timers.filter((t) => !t.cleared && t.ms === 250).pop();
  assert.ok(scan, "mount schedules the first look for leftovers");
  scan.cleared = true;
  scan.fn();
  await settle();
}

const resumeCall = (m) => m.pushed.filter((p) => p.name === "pk_upload_resume").pop();
const rowsOf = (page) => page.store.rows;

function leftover(page, over) {
  const row = Object.assign({ scope: "rec|1", upload: "photos", user: "u1", key: "a.png|5|7", seq: "s1",
    name: "a.png", type: "image/png", size: 5, lastModified: 7, blob: new Blob(["12345"]), context: "k1",
    state: "pending", attempts: 0, touched: page.clock.t - 60_000, owner: "gone" }, over);
  row.id = row.id || [row.scope, row.upload, row.key, row.seq].join("\0");
  page.store.rows.push(row);
  return row;
}

test("a pick is stashed with its context, and the server hears the context at once", async () => {
  const page = pageLoad();
  const m = mount(page, { context: "kind-a" });
  m.pick(file("a.png"));
  await settle();
  const row = rowsOf(page)[0];
  assert.strictEqual(row.context, "kind-a");
  assert.strictEqual(row.scope, "rec|1");
  assert.strictEqual(row.upload, "photos");
  assert.strictEqual(row.user, "u1");
  assert.strictEqual(row.state, "pending");
  assert.ok(row.blob && row.seq);
  const pick = m.pushed.find((p) => p.name === "pk_upload_pick");
  assert.deepStrictEqual(pick.payload, { upload: "photos", items: [{ key: "a.png|5|7", seq: row.seq, context: "kind-a" }] });
  assert.ok(page.store.persisted, "asks the browser not to evict the stash");
});

test("the same file picked twice is two records, each with its own context; one pick is one record", async () => {
  const page = pageLoad();
  const m = mount(page, { context: "one" });
  const f = file("a.png");
  m.pick(f);
  m.pick(f);                      // `input` and `change` both fire for one pick
  m.ctx.el.dataset.context = "two";
  m.pick(file("a.png"));
  await settle();
  assert.strictEqual(rowsOf(page).length, 2);
  assert.deepStrictEqual(rowsOf(page).map((r) => r.context).sort(), ["one", "two"]);
  assert.notStrictEqual(rowsOf(page)[0].seq, rowsOf(page)[1].seq);
});

test("a quota failure keeps the record without the bytes", async () => {
  const page = pageLoad();
  page.store.failBlobPut = true;
  const m = mount(page);
  m.pick(file("a.png"));
  await settle();
  assert.strictEqual(rowsOf(page).length, 1);
  assert.strictEqual(rowsOf(page)[0].blob, null);
  m.ctx.reconnected();
  m.ctx.disconnected();
  m.ctx.reconnected();
  await settle();
  assert.strictEqual(resumeCall(m).payload.items[0].has_bytes, false);
});

test("a form without an id and phx-change is warned about", async () => {
  const page = pageLoad();
  const m = mount(page);
  m.input.form = { id: "", hasAttribute: () => false };
  m.pick(file("a.png"));
  assert.match(page.store.warnings[0], /id and phx-change/);
});

test("the record is owned by a Web Lock per record, given up when the socket drops", async () => {
  const page = pageLoad();
  const m = mount(page);
  m.pick(file("a.png"));
  await settle();
  const name = "pk-upload:" + rowsOf(page)[0].id;
  assert.ok(page.held.has(name), "held while the transfer is in flight");

  // Another tab cannot take it …
  const other = mount(page);
  await runScan(page);
  assert.strictEqual(resumeCall(other), undefined);

  // … until the socket drops (the hook is not destroyed; its transfer is dead).
  m.ctx.disconnected();
  await settle();
  assert.ok(!page.held.has(name));
  other.ctx.reconnected();
  await settle();
  assert.ok(resumeCall(other), "now the record is free to take over");
});

test("without Web Locks a lease decides: a fresh owner keeps it, a stale one loses it", async () => {
  const page = pageLoad({ locks: false });
  leftover(page, { owner: "other", touched: page.clock.t - 1000 });
  const m = mount(page);
  await runScan(page);
  assert.strictEqual(resumeCall(m), undefined, "touched a second ago: its owner is alive");

  page.tick(20_000);
  m.ctx.reconnected();
  await settle();
  assert.ok(resumeCall(m), "untouched for longer than the lease: free");
});

test("a destroyed instance frees its records at once under the lease", async () => {
  const page = pageLoad({ locks: false });
  const a = mount(page);
  a.pick(file("a.png"));
  await settle();
  a.ctx.destroyed();
  await settle();
  assert.strictEqual(rowsOf(page)[0].touched, 0);
  const b = mount(page);
  await runScan(page);
  assert.ok(resumeCall(b));
});

test("after a remount the server is offered what is left, and carries on from the stash", async () => {
  const page = pageLoad();
  const a = mount(page, { context: "folder-7" });
  a.pick(file("clip.mp4"));
  await settle();
  a.ctx.destroyed();               // the LiveView died with the page
  await settle();

  const b = mount(page, { context: "folder-other" });
  await runScan(page);
  const call = resumeCall(b);
  const item = call.payload.items[0];
  assert.strictEqual(item.context, "folder-7", "the context of the pick, not of the page now");
  assert.strictEqual(item.state, "pending");
  assert.strictEqual(item.has_bytes, true);
  assert.strictEqual(item.fresh, true);
  assert.strictEqual(item.attempts, 0);

  call.cb({ auto: [item.id], queued: [], ask: [], drop: [] });
  await settle();
  assert.strictEqual(b.uploaded.length, 1);
  assert.strictEqual(b.uploaded[0].name, "photos");
  const sent = b.uploaded[0].files[0];
  assert.deepStrictEqual([sent.name, sent.size, sent.lastModified], ["clip.mp4", 5, 7], "same key as the original");
  assert.strictEqual(rowsOf(page)[0].attempts, 1);
});

test("a reconnect of the same instance also carries on; the answer is never lost to a second drop", async () => {
  const page = pageLoad();
  const m = mount(page);
  m.pick(file("a.png"));
  await settle();
  m.ctx.disconnected();
  m.ctx.reconnected();
  await settle();
  const first = resumeCall(m);
  assert.ok(first);
  // The socket drops again before the reply arrives.
  m.ctx.disconnected();
  m.pushed.length = 0;
  m.ctx.reconnected();
  await settle();
  const second = resumeCall(m);
  assert.ok(second, "offered again on the next reconnect");
  second.cb({ auto: [second.payload.items[0].id], queued: [], ask: [], drop: [] });
  await settle();
  assert.strictEqual(m.uploaded.length, 1, "fed once");
});

test("queued records wait for a slot and are offered again after each received/rejected", async () => {
  const page = pageLoad();
  leftover(page, { seq: "s1", key: "a.png|5|7", name: "a.png" });
  leftover(page, { seq: "s2", key: "b.png|5|7", name: "b.png" });
  const m = mount(page);
  await runScan(page);
  const call = resumeCall(m);
  const [first, second] = call.payload.items;
  call.cb({ auto: [first.id], queued: [second.id], ask: [], drop: [] });
  await settle();
  assert.strictEqual(m.uploaded[0].files.length, 1);

  m.pushed.length = 0;
  m.handlers["pk-upload-received"]({ upload: "photos", key: first.key });
  await settle();
  const again = resumeCall(m);
  assert.deepStrictEqual(again.payload.items.map((i) => i.id), [second.id], "only what still waits");
  again.cb({ auto: [second.id], queued: [], ask: [], drop: [] });
  await settle();
  assert.strictEqual(m.uploaded.length, 2);
});

test("ask waits for the button; drop deletes", async () => {
  const page = pageLoad();
  const asked = leftover(page, { seq: "s1", key: "a.png|5|7" });
  const dropped = leftover(page, { seq: "s2", key: "b.png|5|7" });
  const m = mount(page);
  await runScan(page);
  const call = resumeCall(m);
  call.cb({ auto: [], queued: [], ask: [asked.id], drop: [dropped.id] });
  await settle();
  assert.strictEqual(m.uploaded.length, 0);
  assert.deepStrictEqual(rowsOf(page).map((r) => r.id), [asked.id]);

  m.handlers["pk-upload-feed"]({ upload: "photos", ids: [asked.id] });
  await settle();
  assert.strictEqual(m.uploaded.length, 1);
  assert.strictEqual(m.uploaded[0].files[0].name, "a.png");
});

test("a pushed event for another upload of the page is ignored", async () => {
  const page = pageLoad();
  const row = leftover(page, { state: "received" });
  const m = mount(page);
  m.handlers["pk-upload-stored"]({ upload: "other", key: row.key });
  await settle();
  assert.strictEqual(rowsOf(page).length, 1);
});

test("received keeps the bytes; only stored or rejected delete", async () => {
  const page = pageLoad();
  const m = mount(page);
  m.pick(file("a.png"), file("b.png"));
  await settle();

  m.handlers["pk-upload-received"]({ upload: "photos", key: "a.png|5|7" });
  await settle();
  const a = rowsOf(page).find((r) => r.name === "a.png");
  assert.strictEqual(a.state, "received");
  assert.ok(a.blob, "the host has not said it saved the file");
  assert.ok(!page.held.has("pk-upload:" + a.id), "a received record needs no owner");

  m.handlers["pk-upload-stored"]({ upload: "photos", key: "a.png|5|7" });
  m.handlers["pk-upload-rejected"]({ upload: "photos", key: "b.png|5|7" });
  await settle();
  assert.deepStrictEqual(rowsOf(page), []);
  assert.deepStrictEqual(page.held.size, 0);
});

test("received without stored comes back as a received record, which the server asks about", async () => {
  const page = pageLoad();
  const m = mount(page);
  m.pick(file("a.png"));
  await settle();
  m.handlers["pk-upload-received"]({ upload: "photos", key: "a.png|5|7" });
  await settle();
  m.ctx.disconnected();
  m.pushed.length = 0;
  m.ctx.reconnected();
  await settle();
  assert.strictEqual(resumeCall(m).payload.items[0].state, "received");
});

test("freshness: an old record is reported as not fresh; 0 turns automatic continuation off", async () => {
  const page = pageLoad();
  leftover(page, { touched: page.clock.t - 31 * 60_000 });
  const m = mount(page);
  await runScan(page);
  assert.strictEqual(resumeCall(m).payload.items[0].fresh, false);

  const page2 = pageLoad();
  leftover(page2);
  const m2 = mount(page2, { freshMs: "0" });
  await runScan(page2);
  assert.strictEqual(resumeCall(m2).payload.items[0].fresh, false);

  const page3 = pageLoad();
  leftover(page3, { touched: page3.clock.t - 31 * 60_000 });
  const m3 = mount(page3, { freshMs: String(2 * 3600_000) });
  await runScan(page3);
  assert.strictEqual(resumeCall(m3).payload.items[0].fresh, true);
});

test("scope and upload isolate records; another user's are never offered and are removed", async () => {
  const page = pageLoad();
  leftover(page, { scope: "rec|2", key: "x|5|7" });
  leftover(page, { upload: "docs", key: "y|5|7" });
  const theirs = leftover(page, { user: "u2", key: "z|5|7" });
  const m = mount(page);
  await runScan(page);
  assert.strictEqual(resumeCall(m), undefined);
  assert.ok(page.store.deleted.includes(theirs.id), "mounting under another user removes the previous user's records");
});

test("records older than 24 hours are removed, not offered", async () => {
  const page = pageLoad();
  const old = leftover(page, { touched: page.clock.t - 25 * 3600_000 });
  const m = mount(page);
  await runScan(page);
  assert.strictEqual(resumeCall(m), undefined);
  assert.ok(page.store.deleted.includes(old.id));
});

test("the stash of the first version is dropped", () => {
  const page = pageLoad();
  mount(page);
  assert.strictEqual(page.store.oldDbDeleted, 1);
});

function clickLogout(page, extra = {}) {
  let clicks = 0;
  let prevented = 0;
  const el = { click() { clicks++; page.doc.listeners.click({ button: 0, target: { closest: () => el }, preventDefault() {}, stopPropagation() {} }); } };
  page.doc.listeners.click(Object.assign({ button: 0, target: { closest: () => el },
    preventDefault() { prevented++; }, stopPropagation() {} }, extra));
  return { clicks: () => clicks, prevented: () => prevented };
}

test("signing out clears the signing-out user's stash before the request goes out, then replays the click once", async () => {
  const page = pageLoad();
  leftover(page);
  leftover(page, { user: "u2", key: "z|5|7" });
  page.doc.hooks.push({ dataset: { user: "u1" } });
  const c = clickLogout(page);
  assert.strictEqual(c.prevented(), 1, "the original navigation is held back");
  await settle();
  assert.strictEqual(page.store.clearedUser, "u1");
  assert.strictEqual(c.clicks(), 1);
  assert.deepStrictEqual(rowsOf(page).map((r) => r.user), ["u2"], "another signed-in user keeps his files");
});

test("a page with no hook cannot say whose files; everything goes", async () => {
  const page = pageLoad();
  leftover(page);
  clickLogout(page);
  await settle();
  assert.strictEqual(page.store.cleared, true);
});

test("a click that opens a new tab or window is left alone", async () => {
  const page = pageLoad();
  leftover(page);
  for (const extra of [{ ctrlKey: true }, { metaKey: true }, { shiftKey: true }, { button: 1 }]) {
    const c = clickLogout(page, extra);
    assert.strictEqual(c.prevented(), 0);
  }
  await settle();
  assert.strictEqual(rowsOf(page).length, 1);
});

test("received and stored of one file arrive together: the right record is deleted when the file is in the stash twice", async () => {
  const page = pageLoad();
  const stranded = leftover(page, { seq: "s0", state: "received", owner: null });
  const m = mount(page);
  m.pick(file("a.png"));                 // same key as the stranded one
  await settle();
  const picked = rowsOf(page).find((r) => r.id !== stranded.id);
  m.handlers["pk-upload-received"]({ upload: "photos", key: "a.png|5|7" });
  m.handlers["pk-upload-stored"]({ upload: "photos", key: "a.png|5|7" });
  await settle();
  assert.ok(!rowsOf(page).some((r) => r.id === picked.id), "the file that was just stored is gone");
  assert.strictEqual(rowsOf(page).length, 1, "the stranded one stays for its own decision");
});

test("a cancelled file is rejected by the server and deleted; it is not carried on later", async () => {
  const page = pageLoad();
  const m = mount(page);
  m.pick(file("a.png"));
  await settle();
  m.handlers["pk-upload-rejected"]({ upload: "photos", key: "a.png|5|7" });
  await settle();
  assert.deepStrictEqual(rowsOf(page), []);
  assert.strictEqual(page.held.size, 0);
  m.ctx.disconnected();
  m.ctx.reconnected();
  await settle();
  assert.strictEqual(resumeCall(m), undefined, "nothing to offer");
});

test("in lock mode the heartbeat does not rewrite records; under the lease it does", async () => {
  const locked = pageLoad();
  const a = mount(locked);
  a.pick(file("a.png"));
  await settle();
  const before = rowsOf(locked)[0].touched;
  locked.tick(6000);
  a.ctx._heartbeat();
  await settle();
  assert.strictEqual(rowsOf(locked)[0].touched, before);

  const leased = pageLoad({ locks: false });
  const b = mount(leased);
  b.pick(file("a.png"));
  await settle();
  leased.tick(6000);
  b.ctx._heartbeat();
  await settle();
  assert.strictEqual(rowsOf(leased)[0].touched, leased.clock.t);
});

test("a file picked while the socket is down is carried on after the reconnect, not left 'in flight'", async () => {
  const page = pageLoad();
  const m = mount(page);
  m.ctx.disconnected();
  m.pick(file("camera.jpg"));          // the camera returned before the socket did
  await settle();
  m.ctx.reconnected();
  await settle();
  const call = resumeCall(m);
  assert.ok(call, "offered to the server");
  call.cb({ auto: [call.payload.items[0].id], queued: [], ask: [], drop: [] });
  await settle();
  assert.strictEqual(m.uploaded.length, 1);
});

test("a server without handlers for the upload is left alone: nothing more is sent, files stay in the stash", async () => {
  const page = pageLoad();
  const m = mount(page);
  m.pick(file("a.png"));
  await settle();
  const pick = m.pushed.find((p) => p.name === "pk_upload_pick");
  pick.cb({ error: "not_attached" });

  m.pushed.length = 0;
  m.pick(file("b.png"));
  m.ctx.disconnected();
  m.ctx.reconnected();
  await settle();
  assert.deepStrictEqual(m.pushed, [], "no pick, no resume");
  assert.strictEqual(rowsOf(page).length, 2, "the files are still kept");
  assert.strictEqual(page.held.size, 0, "and owned by nobody");
});
