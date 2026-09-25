
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

/// 清掉 SDK 的本地会话（localStorage/sessionStorage/IndexedDB）。
/// location.reload() 不会清这些——SDK 恢复旧会话会复用 certifyId，
/// 阿里云判 F008（duplicate certify），池永远拿不到票。zcode-api 的
/// 等价做法是失败后销毁整个 solver window。
async function wipeSdkState() {
  try { localStorage.clear(); } catch { }
  try { sessionStorage.clear(); } catch { }
  try {
    const dbs = (indexedDB.databases ? await indexedDB.databases() : []) || [];
    for (const d of dbs) { try { indexedDB.deleteDatabase(d.name); } catch { } }
  } catch { }
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

/// 求解阶段状态机（verifying/rescue/done）——兜底全部走同一个可靠
/// interval 轮询（tick 实测可靠；一次性 setTimeout 有不触发的案例）。
function setStage(stage) {
  window.__gwStage = stage;
  window.__gwStageAt = Date.now();
}

async function runWarmup() {
  // 隐藏问题不存在——本窗常驻可见（微型）。先归位微型形态（幂等）。
  try {
    mode = "gateway-warmup";
    document.title = "Z·GATEWAY · warmup";
    document.body.classList.add("warmup-mini");
    status(t("c.traceless"));
    wipeSdkState(); // 每轮全新 SDK 会话——certifyId 复用是 F008 的直接来源
    // renderer 心跳 + 阶段轮询（同一 interval，实测可靠）：
    //   verifying 超 9s → 显形救援（traceless-stuck）
    //   rescue 超 45s 无人通过 → 重来（rescue-stuck）
    if (window.__gwTick) clearInterval(window.__gwTick);
    let ticks = 0;
    setStage("init");
    window.__gwTick = setInterval(() => {
      ticks++;
      const stage = window.__gwStage || "init";
      const elapsed = Date.now() - (window.__gwStageAt || Date.now());
      if (ticks % 5 === 0) {
        gwlog("tick", `n=${ticks} stage=${stage} visibility=${document.visibilityState}`);
      }
      if (stage === "verifying" && elapsed > 9000) {
        setStage("rescue");
        gwlog("traceless-stuck", `${elapsed}ms no result — rescue window`);
        document.body.classList.remove("warmup-mini");
        invoke("gateway_captcha_warmup_visibility", { rescue: true }).catch(() => {});
        status(t("c.interactive"));
        $btn.hidden = false;
      } else if (stage === "rescue" && elapsed > 45000) {
        gwlog("rescue-stuck", `${elapsed}ms no pass — reloading`);
        location.reload();
      }
    }, 3000);
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
          setStage("verifying");
          gwlog("traceless-start");
        } else {
          gwlog("traceless-unavailable", "SDK has no startTracelessVerification");
          setStage("rescue");
          document.body.classList.remove("warmup-mini");
          invoke("gateway_captcha_warmup_visibility", { rescue: true }).catch(() => {});
          status(t("c.interactive"));
          $btn.hidden = false;
        }
      },
      success: (result) => {
        setStage("done");
        clearTimeout(tracelessTimer);
        // result 可能是对象：{success, verifyResult, verifyCode, certifyId, captchaVerifyParam?}
        // verifyResult=false = 风控拒（F008=certifyId 复用等）——清会话重来，绝不静默
        if (result && typeof result === "object" && result.verifyResult === false) {
          gwlog("verify-rejected", `code=${result.verifyCode} certify=${result.certifyId || "-"} — wiping session`);
          wipeSdkState().finally(() => setTimeout(() => location.reload(), 300));
          return;
        }
        const param = typeof result === "string"
          ? result
          : result?.captchaVerifyParam || result?.verifyParam || result?.data || result?.param;
        submitted = false;
        submit(typeof param === "string" ? param : param ? String(param) : "");
        if (!submitted) {
          gwlog("empty-param", JSON.stringify(result).slice(0, 120));
          wipeSdkState().finally(() => setTimeout(() => location.reload(), 300));
        }
      },
      fail: (p) => {
        // 拖拽失败 / 无痕被拒：SDK 界面可重试，不 reload 打断用户；埋点即可
        const raw = typeof p === "string" ? p : JSON.stringify(p || {});
        if (p && typeof p === "object" && p.verifyResult === false) {
          setStage("done");
          gwlog("verify-rejected-fail", `code=${p.verifyCode} certify=${p.certifyId || "-"}`);
          wipeSdkState().finally(() => setTimeout(() => location.reload(), 300));
          return;
        }
        setStage("rescue");
        gwlog("sdk-fail", raw.slice(0, 120));
        document.body.classList.remove("warmup-mini");
        invoke("gateway_captcha_warmup_visibility", { rescue: true }).catch(() => {});
        status(t("c.interactive"));
        $btn.hidden = false;
      },
      onError: (p) => {
        setStage("done");
        gwlog("sdk-error", typeof p === "string" ? p.slice(0, 120) : JSON.stringify(p).slice(0, 120));
        setTimeout(() => location.reload(), 8000);
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
      // 预解循环：质量校验（len<200 是必 3007 的废票，zcode-api 同款防线）
      // → 入池 → 恢复微型预解形态 → 下一轮
      if (submitted) return;
      submitted = true;
      setStage("done");
      if (!param || param.length < 200) {
        gwlog("degraded-param", `len=${param ? param.length : 0} — refusing, reloading`);
        wipeSdkState().finally(() => setTimeout(() => location.reload(), 300));
        return;
      }
      gwlog("success", `verifyParam len=${param.length}`);
      invoke("gateway_captcha_submit", { param, region })
        .then((r) => gwlog("pool-push", `accepted=${!!r?.accepted} size=${r?.size ?? "?"} ${r?.reason || ""}`))
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
