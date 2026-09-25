
import { invoke } from "@tauri-apps/api/core";
import { emit } from "@tauri-apps/api/event";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { init, t, lang, stripErr } from "./i18n.js";

const SDK_URL = "https://o.alicdn.com/captcha-frontend/aliyunCaptcha/AliyunCaptcha.js";
const TRACELESS_TIMEOUT = 8000;

const $text = document.getElementById("cap-text");
const $detail = document.getElementById("cap-detail");
const $dot = document.getElementById("cap-dot");
const $btn = document.getElementById("cap-btn");

function status(text, tone = "run") {
  $text.textContent = text;
  $dot.className = "cap-dot" + (tone === "ok" ? " ok" : tone === "err" ? " err" : "");
}

function detail(text) {
  $detail.textContent = text || "";
}

document.addEventListener("securitypolicyviolation", (e) => {
  detail(t("c.cspBlocked", { directive: e.violatedDirective, uri: String(e.blockedURI).slice(0, 70) }));
});

const notifyStuck = () => { emit("captcha://interactive").catch(() => {}); };

function loadSdk() {
  return new Promise((resolve, reject) => {
    if (typeof window.initAliyunCaptcha === "function") return resolve();
    const s = document.createElement("script");
    s.src = SDK_URL;
    s.onload = () => resolve();
    s.onerror = () => reject(new Error(t("c.sdkFail")));
    document.head.appendChild(s);
  });
}

let submitted = false;
let region = null;
let tracelessTimer = 0;
// 验证码窗口复用：模式由窗口 label 决定（无共享状态、无竞态）——
//   "captcha-warmup" → 网关预解循环（隐藏后台解票，需人工时自行显形）
//   "captcha"        → claim 领取流程（或网关交互救援，经 captcha_get_mode）
let mode = "claim";

/// 验证码链路埋点（进请求日志窗口，route=captcha）
function gwlog(stage, detail) {
  return invoke("gateway_captcha_event", { stage, detail: detail ?? null }).catch(() => {});
}

/// 预解循环的单轮调度：池满等久一点，缺票（或 urgent）立即再来一张。
async function warmupNextRound() {
  let st = null;
  try { st = await invoke("gateway_captcha_pool_status"); } catch { }
  const size = st?.size ?? 0;
  const min = st?.min ?? 3;
  const max = st?.max ?? 12;
  const urgent = !!st?.urgent;
  const delay = size >= max ? 5000 : (size >= min && !urgent ? 2500 : 150);
  gwlog("round-next", `pool=${size}/${max} urgent=${urgent} next=${delay}ms`);
  setTimeout(() => location.reload(), delay);
}

/// 人工救援守卫：显形后 success 迟迟不来（SDK 回源卡住）→ 强制重来，
/// 否则窗口永远停在「验证通过！」而池里没有票。
function armRescueGuard(ms) {
  clearTimeout(window.__gwRescueGuard);
  window.__gwRescueGuard = setTimeout(() => {
    gwlog("success-stuck", `no success callback ${ms}ms after pass — reloading`);
    location.reload();
  }, ms);
}
function disarmRescueGuard() { clearTimeout(window.__gwRescueGuard); }

async function runWarmup() {
  // 隐藏问题不存在——本窗常驻可见（微型）。先归位微型形态（幂等）。
  try {
    mode = "gateway-warmup";
    document.title = "Z·GATEWAY · warmup";
    document.body.classList.add("warmup-mini");
    await invoke("gateway_captcha_warmup_visibility", { rescue: false }).catch(() => {});
    const st = await invoke("gateway_captcha_pool_status").catch(() => null);
    if (st && st.size >= (st.max ?? 12)) {
      gwlog("round-skip", `pool full ${st.size}/${st.max}`);
      setTimeout(() => location.reload(), 5000);
      return;
    }
    let cfg;
    let fallback = false;
    try {
      cfg = await invoke("gateway_captcha_config");
    } catch (e) {
      gwlog("config-fail", String(e));
      cfg = { enabled: true, region: "sgp", prefix: "no8xfe", scene_id: "11xygtvd" };
      fallback = true;
    }
    if (!cfg?.enabled || !cfg.scene_id) {
      gwlog("config-disabled", `enabled=${cfg?.enabled} scene=${cfg?.scene_id || "-"}`);
      setTimeout(() => location.reload(), 10000);
      return;
    }
    gwlog("config-ok", `scene=${cfg.scene_id} prefix=${cfg.prefix} region=${cfg.region}${fallback ? " (fallback)" : ""}`);
    region = cfg.region || null;
    await loadSdk();
    window.AliyunCaptchaConfig = { region: cfg.region, prefix: cfg.prefix };
    gwlog("sdk-init", `scene=${cfg.scene_id}`);
    window.initAliyunCaptcha({
      SceneId: cfg.scene_id,
      mode: "popup",
      region: cfg.region,
      prefix: cfg.prefix,
      language: lang() === "en" ? "en" : "zh-CN",
      showErrorTip: false,
      element: "#cap-holder",
      button: "#cap-btn",
      getInstance: (instance) => {
        if (typeof instance.startTracelessVerification === "function") {
          instance.startTracelessVerification();
          gwlog("traceless-start");
          // traceless 迟迟不回来 → 放大窗口请人工；守卫兜底防卡死
          tracelessTimer = setTimeout(() => {
            gwlog("traceless-stuck", "6s no result — rescue window");
            document.body.classList.remove("warmup-mini");
            invoke("gateway_captcha_warmup_visibility", { rescue: true }).catch(() => {});
            status(t("c.interactive"));
            $btn.hidden = false;
            armRescueGuard(30000);
          }, 6000);
        } else {
          gwlog("traceless-unavailable", "SDK has no startTracelessVerification");
          document.body.classList.remove("warmup-mini");
          invoke("gateway_captcha_warmup_visibility", { rescue: true }).catch(() => {});
          status(t("c.interactive"));
          $btn.hidden = false;
          armRescueGuard(45000);
        }
      },
      success: (param) => {
        disarmRescueGuard();
        submitted = false; // 每轮独立：守卫 reload 后旧行为不残留
        submit(typeof param === "string" ? param : param?.captchaVerifyParam);
      },
      fail: (p) => {
        // 拖拽失败：SDK 界面可重试，不 reload 打断用户；只埋点+延长守卫
        gwlog("sdk-fail", typeof p === "string" ? p.slice(0, 120) : JSON.stringify(p).slice(0, 120));
        armRescueGuard(60000);
      },
      onError: (p) => {
        gwlog("sdk-error", typeof p === "string" ? p.slice(0, 120) : JSON.stringify(p).slice(0, 120));
        tracelessTimer = setTimeout(() => location.reload(), 8000);
      },
    });
  } catch (e) {
    gwlog("warmup-crash", String(e));
    setTimeout(() => location.reload(), 8000);
  }
}

async function run() {
  try {
    const st = await invoke("get_state");
    if (st?.language) init(st.language);
  } catch { }
  document.title = t("c.title");
  $btn.textContent = t("c.btn");
  document.querySelector(".cap-foot").textContent = t("c.foot");
  status(t("c.preparing"));

  if (getCurrentWindow().label === "captcha-warmup") {
    mode = "gateway-warmup";
    await runWarmup();
    return;
  }
  try {
    mode = await invoke("captcha_get_mode").catch(() => "claim");
  } catch { }
  let cfg;
  try {
    cfg = await invoke(mode === "gateway" ? "gateway_captcha_config" : "claim_captcha_config");
  } catch (e) {
    notifyStuck();
    status(t("c.cfgFail"), "err");
    detail(stripErr(e));
    return;
  }
  if (!cfg.enabled || !cfg.scene_id) {
    notifyStuck();
    status(t("c.cfgUnavailable"), "err");
    detail(t("c.cfgUnavailableDetail"));
    return;
  }
  region = cfg.region || null;
  try {
    await loadSdk();
  } catch (e) {
    notifyStuck();
    status(e.message || t("c.sdkFail"), "err");
    return;
  }

  window.AliyunCaptchaConfig = { region: cfg.region, prefix: cfg.prefix };

  status(t("c.traceless"));

  const submit = (param) => {
    if (submitted || !param || !param.trim()) return;
    submitted = true;
    clearTimeout(tracelessTimer);
    if (mode === "gateway-warmup") {
      // 预解循环：入池 → 恢复微型预解形态 → 下一轮
      gwlog("success", `verifyParam len=${param.length}`);
      invoke("gateway_captcha_submit", { param, region })
        .then((r) => gwlog("pool-push", `accepted=${!!r?.accepted} size=${r?.size ?? "?"}`))
        .catch((e) => gwlog("pool-push-fail", String(e)))
        .finally(() => {
          invoke("gateway_captcha_warmup_visibility", { rescue: false }).catch(() => {});
          warmupNextRound();
        });
      return;
    }
    status(mode === "gateway" ? t("c.passedGw") : t("c.passed"));
    const cmd = mode === "gateway" ? "gateway_captcha_submit" : "claim_captcha_submit";
    invoke(cmd, { param, region }).catch((e) => {
      status(mode === "gateway" ? t("c.submitFailGw") : t("c.claimReqFail"), "err");
      detail(stripErr(e));
    });
  };

  const interactive = (why) => {
    notifyStuck();
    clearTimeout(tracelessTimer);
    status(t("c.interactive"));
    $btn.hidden = false;
    $btn.focus();
    if (why) detail(typeof why === "string" ? why.slice(0, 120) : JSON.stringify(why).slice(0, 120));
  };

  try {
    window.initAliyunCaptcha({
      SceneId: cfg.scene_id,
      mode: "popup",
      language: lang() === "en" ? "en" : "zh-CN",
      showErrorTip: false,
      element: "#cap-holder",
      button: "#cap-btn",
      getInstance: (instance) => {
        if (typeof instance.startTracelessVerification === "function") {
          instance.startTracelessVerification();
          tracelessTimer = setTimeout(interactive, TRACELESS_TIMEOUT);
        } else {
          interactive();
        }
      },
      success: (param) => submit(typeof param === "string" ? param : param?.captchaVerifyParam),
      fail: (p) => interactive(p),
      onError: (p) => interactive(p),
    });
  } catch (e) {
    notifyStuck();
    status(t("c.initFail"), "err");
    detail(String(e));
  }
}

$btn.addEventListener("click", () => {
  if (!$btn.hidden) status(t("c.inPopup"));
});

run();
