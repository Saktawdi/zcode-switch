#!/usr/bin/env node
/**
 * 日志页回归测试（node --test + happy-dom）。
 *
 * 盯的是三个真实出现过的缺陷——都不报错，只是让交互悄悄失效：
 *   1. `change="..."` 从未被代理 → 账号筛选选了没反应（死代码）；
 *   2. 每 2s 整页重建 → 往上翻日志被顶回顶部；
 *   3. 每轮轮询重建 <select> → 选了 A 账号，刷新后变回「全部账号」。
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { Window } from "happy-dom";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { pickAnchor, anchorScrollTop, isAtBottom } from "../src/log-scroll.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

// ───────────────────────── 纯滚动锚定逻辑 ─────────────────────────

test("锚点取视口内第一条可见行", () => {
  const rects = [
    { key: "a", top: -50, bottom: -10 }, // 已滚过
    { key: "b", top: 4, bottom: 40 },    // 第一条可见
    { key: "c", top: 44, bottom: 80 },
  ];
  assert.deepEqual(pickAnchor(rects, 0), { key: "b", top: 4 });
});

test("新日志插到顶部时，锚点行留在原视口位置", () => {
  // 用户停在中间：scrollTop=1500
  const anchor = { key: "row-x", top: 12 };
  // 重建后该行被新内容推低了 60px（3 条新日志）
  const rects = [{ key: "row-x", top: 72, bottom: 110 }];
  assert.equal(anchorScrollTop(1500, anchor, rects), 1560, "scrollTop 同步下移，视觉位置不变");
});

test("锚点行被淘汰时不清零滚动位置", () => {
  const anchor = { key: "gone", top: 12 };
  assert.equal(anchorScrollTop(1500, anchor, [{ key: "other", top: 0 }]), 1500);
  assert.equal(anchorScrollTop(1500, null, []), 1500);
});

test("贴底判定：贴底才跟随最新，否则锚定", () => {
  assert.ok(isAtBottom(2600, 3000, 400), "正好贴底");
  assert.ok(isAtBottom(2601, 3000, 400), "容差内算贴底");
  assert.ok(!isAtBottom(1500, 3000, 400), "停在中间 → 不跟随");
});

// ───────────────────────── 页面行为（真实 DOM） ─────────────────────────

function row(ts, account, model = "glm-5.3-flash") {
  return {
    ts, route: "/v1/chat/completions", format: "openai", model,
    account, provider: "zai", plan: "start-plan",
    status: 200, ms: 120, attempts: 1, error: null,
  };
}

/// 造窗口 + 假 invoke，然后把页面源码塞进去执行。
async function loadPage(initialLogs) {
  const window = new Window({ url: "http://localhost/" });
  const { document } = window;
  document.body.innerHTML = `<div id="app"></div>`;

  let store = initialLogs.slice();
  const calls = [];
  window.invoke = async (cmd, args) => {
    calls.push({ cmd, args });
    if (cmd === "gateway_logs") return store.slice();
    if (cmd === "get_state") return { language: "zh", gateway_debug_log: false };
    if (cmd === "gateway_clear_logs") { store = []; return null; }
    if (cmd === "gateway_export_logs") return { picked: true, count: 2, path: "x.csv", csv: true };
    return null;
  };

  // 页面 import 的同级模块用桩替换（被测逻辑不依赖它们的真实实现），
  // 但 installDelegation 必须用真货——change 代理就是被测对象之一。
  let src = readFileSync(join(root, "src/gateway-page.js"), "utf8");
  src = src.replace(/^import .*$/gm, "");
  const ui = readFileSync(join(root, "src/ui.js"), "utf8");
  const delegation = ui
    .slice(ui.indexOf("export function installDelegation"), ui.indexOf("export function openConfirmModal"))
    .replace("export function", "function");
  const scroll = readFileSync(join(root, "src/log-scroll.js"), "utf8").replace(/^export /gm, "");

  const prelude = `
    const { document, window } = globalThis;
    const invoke = window.invoke;
    const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;" }[c]));
    const t = (k) => k;
    const lang = () => "zh", localeTag = () => "zh-CN", stripErr = (e) => String(e);
    const init = () => {}, ic = () => "", toast = () => {};
    function runAttr(expr, event) {
      const open = expr.indexOf("(");
      if (open < 0 || !expr.trimEnd().endsWith(")")) return;
      let fn = window;
      for (const seg of expr.slice(0, open).trim().split(".")) fn = fn?.[seg];
      if (typeof fn !== "function") return;
      const s = expr.slice(open + 1, expr.trimEnd().length - 1).trim();
      const args = s ? s.split(/\\s*,\\s*/).map((a) => (a === "event" ? event : JSON.parse(a))) : [];
      fn(...args);
    }
    ${delegation}
    ${scroll}
  `;
  window.eval(prelude + src);
  await new Promise((r) => setTimeout(r, 20)); // 等页面 IIFE 里的首个 await 落地
  return {
    window, document,
    setLogs: (l) => { store = l.slice(); },
    clearCalls: () => { calls.length = 0; },
    calls,
  };
}

/// 页面每 2s 轮询一次。要验证"刷新"行为就得等真实的一轮，不能用假 tick —
/// 否则测的是"没刷新时也不变"，等于没测。
const POLL_MS = 2200;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

test("change 被代理：选账号真的筛选（历史 bug：死代码）", async (t) => {
  const page = await loadPage([row(1, "A"), row(2, "B")]);
  t.after(() => page.window.happyDOM.close());
  const { window, document } = page;

  assert.equal(document.querySelectorAll(".gwlog-row").length, 2);
  const sel = document.querySelector(".gwlog-filter");
  sel.value = "A";
  // 真实浏览器里 change 不冒泡成 click，正是原实现漏掉的事件
  sel.dispatchEvent(new window.Event("change", { bubbles: true }));

  const rows = [...document.querySelectorAll(".gwlog-row")];
  assert.equal(rows.length, 1, "只剩 A 的记录");
  assert.match(rows[0].textContent, /A/);
});

test("轮询刷新重建列表但不替换 <select>，选中账号保持（历史 bug 3）", async (t) => {
  const page = await loadPage([row(1, "A"), row(2, "B")]);
  t.after(() => page.window.happyDOM.close());
  const { window, document, setLogs } = page;

  const sel0 = document.querySelector(".gwlog-filter");
  sel0.value = "A";
  sel0.dispatchEvent(new window.Event("change", { bubbles: true }));
  assert.equal(sel0.value, "A");
  assert.equal(document.querySelectorAll(".gwlog-row").length, 1);

  // 账号集合不变、仅新增同账号记录 → 等一轮真实轮询
  setLogs([row(1, "A"), row(2, "B"), row(3, "A")]);
  await sleep(POLL_MS);

  const sel1 = document.querySelector(".gwlog-filter");
  assert.equal(sel1, sel0, "select 元素未被替换");
  assert.equal(sel1.value, "A", "选中账号仍是 A，没有回落为全部");
  assert.equal(document.querySelectorAll(".gwlog-row").length, 2, "筛选仍在生效且新记录已进列表");
});

test("列表容器跨刷新存活，非贴底时滚动位置不被重置（历史 bug 2）", async (t) => {
  const many = Array.from({ length: 40 }, (_, i) => row(i + 1, "A", `m-${i}`));
  const page = await loadPage(many);
  t.after(() => page.window.happyDOM.close());
  const { window, document, setLogs } = page;

  const before = document.querySelector(".gwlog-list");
  // happy-dom 不做布局，补上滚动度量语义，让"非贴底"分支真正生效
  Object.defineProperty(before, "scrollHeight", { value: 3000, configurable: true });
  Object.defineProperty(before, "clientHeight", { value: 400, configurable: true });
  before.scrollTop = 900; // 停在中间，不是贴底

  setLogs([row(9999, "C", "brand-new"), ...many]);
  await sleep(POLL_MS);

  // 关键：重新查询当前文档里的容器。整页重建会让旧引用变成游离节点，
  // 只断言旧引用等于自欺欺人。
  const after = document.querySelector(".gwlog-list");
  assert.equal(after, before, "文档中的列表容器未被替换（整页重建会换掉它）");
  assert.equal(after.scrollTop, 900, "scrollTop 未被清零/顶回顶部");
  assert.equal(document.querySelectorAll(".gwlog-row").length, 41, "新记录已渲染");
});

test("导出带上当前账号筛选，与界面所见一致", async (t) => {
  const page = await loadPage([row(1, "A"), row(2, "B")]);
  t.after(() => page.window.happyDOM.close());
  const { window, document, clearCalls, calls } = page;

  const sel = document.querySelector(".gwlog-filter");
  sel.value = "B";
  sel.dispatchEvent(new window.Event("change", { bubbles: true }));

  clearCalls();
  await window.actions.exportLogs();
  const call = calls.find((c) => c.cmd === "gateway_export_logs");
  assert.ok(call, "发起了导出调用");
  assert.equal(call.args?.account, "B", "导出请求携带筛选账号");
});

test("未筛选时导出不带 account 参数", async (t) => {
  const page = await loadPage([row(1, "A")]);
  t.after(() => page.window.happyDOM.close());
  const { window, clearCalls, calls } = page;

  clearCalls();
  await window.actions.exportLogs();
  const call = calls.find((c) => c.cmd === "gateway_export_logs");
  assert.equal(call.args?.account, null);
});
