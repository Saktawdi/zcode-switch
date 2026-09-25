/**
 * 日志列表的滚动锚定（纯函数，便于测试）。
 *
 * 背景：日志页每 2s 重取一次数据。若整页重建 DOM，正在往上翻日志的人会被
 * 新记录顶回顶部；即使只重建列表内容，插入新行也会把视口推走。做法是在
 * 重建前记住"视口里第一条可见行"，重建后把同一行挪回原处。
 */

/// 视口内第一条可见行（矩形相对容器顶部定位）。取第一条而不是最后一条，
/// 因为用户向上翻时盯的是屏幕顶端那一行。
export function pickAnchor(rects, containerTop) {
  for (const r of rects) {
    if (r.bottom > containerTop + 1) return { key: r.key, top: r.top };
  }
  return null;
}

/// 重建后的新 scrollTop：把锚点行放回它原来的视口位置。
/// 锚点行被环形缓冲淘汰（找不到）时保持原值——内容整体后移，但至少
/// 不会跳到顶部。
export function anchorScrollTop(prevScrollTop, anchor, rects) {
  if (!anchor) return prevScrollTop;
  const back = rects.find((r) => r.key === anchor.key);
  if (!back) return prevScrollTop;
  return prevScrollTop + (back.top - anchor.top);
}

/// 是否已贴到底部。贴底时应继续跟随最新记录，而不是锚定某一行——
/// 否则用户停在底部不动，新日志进来他反而看不到。
export function isAtBottom(scrollTop, scrollHeight, clientHeight, slack = 8) {
  return scrollHeight - scrollTop - clientHeight < slack;
}
