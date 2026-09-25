#!/usr/bin/env node
/**
 * 变体验证：把修复分别退回缺陷态，确认测试真的会红。
 * 这是对测试本身的检查——测试若不红，就没有回归价值。
 * 用法：node scripts/verify-tests-catch-bugs.mjs
 */
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const run = () => {
  try {
    const out = execFileSync(process.execPath, ["--test", join(root, "scripts/test-gateway-page.mjs")], {
      cwd: root, encoding: "utf8", timeout: 60000, stdio: ["ignore", "pipe", "pipe"],
    });
    return { ok: true, out };
  } catch (e) {
    // 超时也算被捕获：缺陷态下页面自旋/挂死本身就是失败信号，
    // 但它拿不到断言行文本，用 timedOut 标记区分。
    const timedOut = e.signal === "SIGTERM" || /ETIMEDOUT/.test(String(e.code));
    return { ok: false, timedOut, out: (e.stdout || "") + (e.stderr || "") };
  }
};
const count = (out, re) => (out.match(re) || []).length;

const uiPath = join(root, "src/ui.js");
const pagePath = join(root, "src/gateway-page.js");
const uiOrig = readFileSync(uiPath, "utf8");
const pageOrig = readFileSync(pagePath, "utf8");

/// 按索引切除一段（正则对中文注释+缩进太脆弱，直接定位标记更可靠）。
function cut(src, fromMarker, toMarker) {
  const a = src.indexOf(fromMarker);
  if (a < 0) return null;
  const b = src.indexOf(toMarker, a);
  if (b < 0) return null;
  return src.slice(0, a) + src.slice(b);
}

const results = [];
try {
  // ── 变体 A：去掉 change 代理（历史缺陷：筛选是死代码）
  const a = cut(uiOrig, "// change 也要代理", 'document.addEventListener("blur"');
  if (!a) throw new Error("变体 A 未能改出缺陷态");
  writeFileSync(uiPath, a, "utf8");
  const ra = run();
  results.push({
    name: "去掉 change 代理",
    caught: !ra.ok,
    failed: count(ra.out, /^not ok/gm),
    detail: ra.ok ? "!!! 测试仍然全绿，说明测不出这个缺陷" : "",
  });
  writeFileSync(uiPath, uiOrig, "utf8");

  // ── 变体 B：每次刷新整页重建（历史缺陷：滚动被重置、下拉被替换）
  const b = pageOrig.replace(
    /  if \(!booted\) \{ renderChrome\(\); lastSig = viewSig\(\); return; \}\n  const sig = viewSig\(\);\n  if \(sig === lastSig\) return;[^\n]*\n  lastSig = sig;\n  syncHint\(\);\n  syncAccountOptions\(\);\n  renderList\(\);/,
    "  renderChrome();",
  );
  if (b === pageOrig) throw new Error("变体 B 未能改出缺陷态");
  writeFileSync(pagePath, b, "utf8");
  const rb = run();
  results.push({
    name: "每轮刷新整页重建",
    caught: !rb.ok,
    failed: count(rb.out, /^not ok/gm),
    detail: rb.ok
      ? "!!! 测试仍然全绿，说明测不出这个缺陷"
      : rb.timedOut ? "（缺陷态下页面自旋超时，未走到断言）" : "",
  });
} finally {
  writeFileSync(uiPath, uiOrig, "utf8");
  writeFileSync(pagePath, pageOrig, "utf8");
}

let bad = 0;
for (const r of results) {
  const mark = r.caught ? "✓ 被测试捕获" : "✗ 漏检";
  if (!r.caught) bad++;
  console.log(`  ${mark}：${r.name}${r.failed ? `（${r.failed} 个用例失败）` : ""} ${r.detail}`);}
console.log(bad ? `\n✗ ${bad} 个缺陷态未被测试捕获` : "\n✓ 两个缺陷态都能被测试捕获（测试有回归价值）");
process.exit(bad ? 1 : 0);
