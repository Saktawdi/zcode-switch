import { invoke } from "@tauri-apps/api/core";
import { installDelegation, toast } from "./ui.js";
import { init, t, lang, localeTag, stripErr } from "./i18n.js";

const $app = document.getElementById("app");
let logs = [];
let filterAccount = "";
let autoRefresh = null;

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

async function refresh() {
  try {
    logs = await invoke("gateway_logs", { limit: 500 });
  } catch (e) {
    toast(stripErr(e), "err");
  }
  render();
}

const actions = {
  async clear() {
    await invoke("gateway_clear_logs").catch(() => {});
    await refresh();
  },
  pickAccount(e) {
    filterAccount = e.target.value || "";
    render();
  },
};

function rowsHtml() {
  const list = logs.filter((l) => !filterAccount || l.account === filterAccount);
  if (!list.length) return `<div class="gwlog-empty">${t("gw.logsEmpty")}</div>`;
  return list.map((l) => {
    const st = l.route === "repair"
      ? `<span class="gwlog-st repair">REPAIR</span>`
      : `<span class="gwlog-st ${statusClass(l.status)}">${l.status}</span>`;
    const err = l.error ? `<div class="gwlog-err" title="${l.error.replace(/"/g, "&quot;")}">${l.error}</div>` : "";
    return `
    <div class="gwlog-row">
      <div class="gwlog-main">
        <span class="gwlog-time">${fmtTime(l.ts)}</span>
        ${st}
        <span class="gwlog-route">${l.route === "repair" ? "repair" : `${l.format} · ${l.route}`}</span>
        <span class="gwlog-model">${l.model}</span>
        <span class="gwlog-acct" title="${l.account || ""}">${l.account || "—"}</span>
        <span class="gwlog-plan">${l.provider || ""}${l.plan ? ` · ${l.plan}` : ""}</span>
        <span class="gwlog-ms">${l.ms ? l.ms + "ms" : ""}${l.attempts > 1 ? ` · ×${l.attempts}` : ""}</span>
      </div>
      ${err}
    </div>`;
  }).join("");
}

function accountsOptions() {
  const names = [...new Set(logs.map((l) => l.account).filter(Boolean))];
  return names.map((n) => `<option value="${n}" ${n === filterAccount ? "selected" : ""}>${n}</option>`).join("");
}

function render() {
  document.title = `Z·SWITCH ${t("gw.logsTitle")}`;
  $app.innerHTML = `
    <header class="topbar">
      <div class="wordmark">Z·SWITCH <span class="ver">/ ${t("gw.logsTitle")}</span></div>
      <span class="tb-spacer"></span>
      <select class="gwlog-filter" aria-label="${t("gw.logsFilter")}" change="actions.pickAccount(event)">
        <option value="">${t("gw.logsAllAccounts")}</option>
        ${accountsOptions()}
      </select>
      <button class="btn-ghost" click="actions.clear()">${t("gw.logsClear")}</button>
    </header>
    <section class="gwlog-list">${rowsHtml()}</section>
  `;
}

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
