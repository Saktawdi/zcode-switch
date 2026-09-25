
import { invoke } from "@tauri-apps/api/core";
import { emit } from "@tauri-apps/api/event";
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
// 验证码窗口复用：claim 领取 / gateway 网关请求挑战。模式由后端在开窗时
// 写入（captcha_get_mode），不依赖 URL——dev 与打包环境行为一致。
let mode = "claim";

/// 预解循环的单轮调度：池满等久一点，缺票（或 urgent）立即再来一张。
async function warmupNextRound() {
  let st = null;
  try { st = await invoke("gateway_captcha_pool_status"); } catch { }
  const size = st?.size ?? 0;
  const min = st?.min ?? 3;
  const max = st?.max ?? 12;
  const urgent = !!st?.urgent;
  const delay = size >= max ? 5000 : (size >= min && !urgent ? 2500 : 150);
  setTimeout(() => location.reload(), delay);
}

async function runWarmup() {
  // 隐藏窗口：静默解票入池。traceless 通过即结束本轮；需要人工时显形。
  try {
    mode = "gateway-warmup";
    const st = await invoke("gateway_captcha_pool_status").catch(() => null);
    if (st && st.size >= (st.max ?? 12)) {
      setTimeout(() => location.reload(), 5000);
      return;
    }
    const cfg = await invoke("gateway_captcha_config");
    if (!cfg?.enabled || !cfg.scene_id) return;
    region = cfg.region || null;
    await loadSdk();
    window.AliyunCaptchaConfig = { region: cfg.region, prefix: cfg.prefix };
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
          // traceless 迟迟不回来 → 显形请人工，避免静默卡死
          tracelessTimer = setTimeout(() => {
            invoke("gateway_captcha_warmup_visibility", { visible: true }).catch(() => {});
            tracelessTimer = setTimeout(warmupNextRound, 60000);
          }, 6000);
        } else {
          invoke("gateway_captcha_warmup_visibility", { visible: true }).catch(() => {});
        }
      },
      success: (param) => submit(typeof param === "string" ? param : param?.captchaVerifyParam),
      fail: () => {
        invoke("gateway_captcha_warmup_visibility", { visible: true }).catch(() => {});
        tracelessTimer = setTimeout(warmupNextRound, 60000);
      },
      onError: () => {
        tracelessTimer = setTimeout(warmupNextRound, 8000);
      },
    });
  } catch {
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

  try {
    mode = await invoke("captcha_get_mode").catch(() => "claim");
  } catch { }
  if (mode === "gateway-warmup") {
    await runWarmup();
    return;
  }
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
      // 预解循环：入池 → 隐藏窗口（若曾因人工验证显形）→ 按池容量决定下一轮
      invoke("gateway_captcha_submit", { param, region })
        .then(() => invoke("gateway_captcha_warmup_visibility", { visible: false }).catch(() => {}))
        .catch(() => {})
        .finally(() => setTimeout(warmupNextRound, 400));
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
