import { invoke } from "@tauri-apps/api/core";
import { installDelegation, toast, esc } from "./ui.js";
import { ic } from "./icons.js";
import { init, t, lang, localeTag, stripErr } from "./i18n.js";
import { pickAnchor, anchorScrollTop, isAtBottom } from "./log-scroll.js";

const $app = document.getElementById("app");
let logs = [];
let filterAccount = "";
let autoRefresh = null;
let debugOn = false;
// 顶栏只画一次；之后每次轮询只更新列表内容的差异部分（见 renderList）。
let booted = false;
let accountsSig = null;
let lastSig = "";

function fmtTime(ts) {
  const d = new Date(ts);
  const sameDay = d.toDateString() === new Date().toDateString();
  const time = d.toLocaleTimeString(localeTag(), { hour12: false });
  return sameDay ? time : `${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")} ${time}`;
}

function statusClass(s) {
  if (s >= 200 && s < 300) return "ok";
  if (s >= 400 && s < 500) return "warn";
  return "err";
}

function visibleLogs() {
  return logs.filter((l) => !filterAccount || l.account === filterAccount);
}

/// 一条记录的身份键。列表每 2s 重取一次，用它做"内容没变就不重画"的短路，
/// 同时作为滚动锚点的定位标记。
function rowKey(l) {
  return [l.ts, l.route, l.model, l.account || "", l.status, l.ms, l.attempts].join("|");
}

/// 当前视图签名：账号筛选 + debug 开关 + 首尾记录。网关日志是 FIFO 的
/// 不可变记录，首尾+条数一致即可认定内容没变（环形缓冲淘汰时首尾必变）。
function viewSig() {
  const first = logs[0] ? rowKey(logs[0]) : "";
  const last = logs.length ? rowKey(logs[logs.length - 1]) : "";
  return `${filterAccount}\u0001${debugOn}\u0001${logs.length}\u0001${first}\u0001${last}`;
}

function rowsHtml() {
  const list = visibleLogs();
  if (!list.length) return `<div class="gwlog-empty">${t("gw.logsEmpty")}</div>`;
  return list.map((l) => {
    const isEvent = l.route === "repair" || l.route === "captcha";
    const st = l.route === "repair"
      ? `<span class="gwlog-st repair">REPAIR</span>`
      : l.route === "captcha"
        ? `<span class="gwlog-st repair">CAPTCHA</span>`
        : `<span class="gwlog-st ${statusClass(l.status)}">${l.status}</span>`;
    const err = l.error ? `<div class="gwlog-err" title="${esc(l.error)}">${esc(l.error)}</div>` : "";
    const detail = l.model; // 事件行始终显示 stage（error 走红字详情，不挤占 stage）
    return `
    <div class="gwlog-row" data-k="${esc(rowKey(l))}">
      <div class="gwlog-main">
        <span class="gwlog-time">${fmtTime(l.ts)}</span>
        ${st}
        <span class="gwlog-route">${isEvent ? l.route : `${l.format} · ${l.route}`}</span>
        <span class="gwlog-model">${esc(detail)}</span>
        <span class="gwlog-acct" title="${esc(l.account || "")}">${esc(l.account || "—")}</span>
        <span class="gwlog-plan">${esc(l.provider || "")}${l.plan ? ` · ${esc(l.plan)}` : ""}</span>
        <span class="gwlog-ms">${l.ms ? (l.ms > 10000 ? Math.round(l.ms / 1000) + "s" : l.ms + "ms") : ""}${l.attempts > 1 ? ` · ×${l.attempts}` : ""}</span>
      </div>
      ${err}
    </div>`;
  }).join("");
}

/// 只重画列表，不动顶栏。重建前记住视口里第一条可见行，重建后把它放回原处——
/// 否则新日志不停插到顶部，正在往上翻日志的人会被一路顶跑（旧实现在每次
/// 轮询时整页 innerHTML，直接跳回顶部）。
function renderList({ keepScroll = true } = {}) {
  const list = $app.querySelector(".gwlog-list");
  if (!list) { renderChrome(); return; }

  const rects = () => [...list.children].map((el) => {
    const r = el.getBoundingClientRect();
    return { key: el.dataset.k, top: r.top, bottom: r.bottom };
  });

  let anchor = null;
  let pinned = false;
  if (keepScroll && list.children.length) {
    pinned = isAtBottom(list.scrollTop, list.scrollHeight, list.clientHeight);
    const top = list.getBoundingClientRect().top;
    anchor = pickAnchor(rects(), top);
  }
  const prevScrollTop = list.scrollTop;

  list.innerHTML = rowsHtml();

  if (!keepScroll) { list.scrollTop = 0; return; }
  if (pinned) { list.scrollTop = list.scrollHeight; return; } // 贴底：继续跟随最新
  list.scrollTop = anchorScrollTop(prevScrollTop, anchor, rects());
}

/// 账号下拉：只有账号集合变化时才重建选项（重建会丢掉浏览器里的当前选中项，
/// 视觉上表现为"选了 A，一刷新变回全部账号"）。
function syncAccountOptions() {
  const sel = $app.querySelector(".gwlog-filter");
  if (!sel) return;
  const names = [...new Set(logs.map((l) => l.account).filter(Boolean))];
  // 选中的账号暂时没有日志时也保留在选项里，否则会静默回落到"全部账号"
  if (filterAccount && !names.includes(filterAccount)) names.push(filterAccount);
  const sig = names.join("\u0000");
  if (sig === accountsSig) return;
  accountsSig = sig;
  sel.innerHTML = `<option value="">${t("gw.logsAllAccounts")}</option>`
    + names.map((n) => `<option value="${esc(n)}"${n === filterAccount ? " selected" : ""}>${esc(n)}</option>`).join("");
}

/// debug 提示行随开关即时增删（不重建顶栏，避免连累下拉的选中态）。
function syncHint() {
  const topbar = $app.querySelector(".topbar");
  if (!topbar) return;
  const cur = $app.querySelector(".gwlog-hint");
  if (debugOn) {
    if (cur) cur.remove();
  } else if (!cur) {
    const div = document.createElement("div");
    div.className = "gwlog-hint";
    div.textContent = t("gw.logsDebugHint");
    topbar.after(div);
  }
}

function renderChrome() {
  document.title = `Z·SWITCH ${t("gw.logsTitle")}`;
  $app.innerHTML = `
    <header class="topbar">
      <div class="wordmark">Z·SWITCH <span class="ver">/ ${t("gw.logsTitle")}</span></div>
      <span class="tb-spacer"></span>
      <select class="gwlog-filter" aria-label="${t("gw.logsFilter")}" change="actions.pickAccount(event)">
        <option value="">${t("gw.logsAllAccounts")}</option>
        ${[...new Set(logs.map((l) => l.account).filter(Boolean))]
          .map((n) => `<option value="${esc(n)}"${n === filterAccount ? " selected" : ""}>${esc(n)}</option>`).join("")}
      </select>
      <button class="btn-ghost has-ic" click="actions.exportLogs()">${ic("exportAll", 14)} ${t("gw.logsExport")}</button>
      <button class="btn-ghost" click="actions.clear()">${t("gw.logsClear")}</button>
    </header>
    ${debugOn ? "" : `<div class="gwlog-hint">${t("gw.logsDebugHint")}</div>`}
    <section class="gwlog-list">${rowsHtml()}</section>
  `;
  accountsSig = [...new Set(logs.map((l) => l.account).filter(Boolean))].join("\u0000");
  booted = true;
}

async function refresh() {
  try {
    logs = await invoke("gateway_logs", { limit: 500 });
    // debug 开关状态：决定是否提示"验证类遥测需开 debug"
    const st = await invoke("get_state").catch(() => null);
    debugOn = !!st?.gateway_debug_log;
  } catch (e) {
    toast(stripErr(e), "err");
  }
  if (!booted) { renderChrome(); lastSig = viewSig(); return; }
  const sig = viewSig();
  if (sig === lastSig) return; // 内容没变：不碰 DOM，滚动位置自然不受影响
  lastSig = sig;
  syncHint();
  syncAccountOptions();
  renderList();
}

const actions = {
  async clear() {
    await invoke("gateway_clear_logs").catch(() => {});
    lastSig = "";
    await refresh();
  },
  async exportLogs() {
    try {
      // 带上当前筛选，导出内容与界面所见一致
      const r = await invoke("gateway_export_logs", { account: filterAccount || null });
      if (!r?.picked) { toast(t("gw.logsExportCanceled")); return; }
      toast(t("gw.logsExportToast", { count: r.count }), "ok", r.path);
    } catch (e) {
      toast(stripErr(e), "err");
    }
  },
  pickAccount(e) {
    filterAccount = e.target.value || "";
    lastSig = viewSig();
    renderList({ keepScroll: false }); // 换了筛选范围，回到列表顶部才对
  },
};

window.actions = actions;
installDelegation();

(async () => {
  try {
    const st = await invoke("get_state");
    if (st?.language) init(st.language);
  } catch { }
  await refresh();
  autoRefresh = setInterval(refresh, 2000);
})();
