//! GLM model catalog + reasoning-effort contract.
//!
//! Ported from zcode-api `src/provider/models.ts` and `src/provider/reasoning.ts`.

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct ModelDef {
    pub id: &'static str,
    pub name: &'static str,
    pub context_window: u64,
    pub max_output_tokens: u64,
    pub reasoning: bool,
}

pub const MODELS: &[ModelDef] = &[
    ModelDef { id: "glm-4.5-air", name: "GLM 4.5 Air", context_window: 131_072, max_output_tokens: 98_304, reasoning: true },
    ModelDef { id: "glm-4.6", name: "GLM 4.6", context_window: 200_000, max_output_tokens: 131_072, reasoning: true },
    ModelDef { id: "glm-4.6v", name: "GLM 4.6V", context_window: 131_072, max_output_tokens: 32_768, reasoning: false },
    ModelDef { id: "glm-4.7", name: "GLM 4.7", context_window: 200_000, max_output_tokens: 131_072, reasoning: true },
    ModelDef { id: "glm-5", name: "GLM 5", context_window: 200_000, max_output_tokens: 64_000, reasoning: true },
    ModelDef { id: "glm-5-turbo", name: "GLM 5 Turbo", context_window: 200_000, max_output_tokens: 64_000, reasoning: true },
    ModelDef { id: "glm-5v-turbo", name: "GLM 5V Turbo", context_window: 200_000, max_output_tokens: 131_072, reasoning: false },
    ModelDef { id: "glm-5.1", name: "GLM 5.1", context_window: 200_000, max_output_tokens: 64_000, reasoning: true },
    ModelDef { id: "glm-5.2", name: "GLM 5.2", context_window: 1_000_000, max_output_tokens: 128_000, reasoning: true },
    ModelDef { id: "glm-5.3", name: "GLM 5.3", context_window: 1_000_000, max_output_tokens: 128_000, reasoning: true },
    ModelDef { id: "glm-5.3-flash", name: "GLM 5.3 Flash", context_window: 1_000_000, max_output_tokens: 128_000, reasoning: true },
];

pub fn model_def(id: &str) -> Option<&'static ModelDef> {
    MODELS.iter().find(|m| m.id == id)
}

pub fn is_reasoning_model(model: &str) -> bool {
    model_def(model).is_some_and(|m| m.reasoning)
}

// ---------------------------------------------------------------------------
// GLM-5.3 reasoning contract
// ---------------------------------------------------------------------------

/// The three legal `output_config.effort` levels for GLM-5.3 family models.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Glm53Effort {
    Low,
    High,
    Max,
}

impl Glm53Effort {
    pub fn as_str(self) -> &'static str {
        match self {
            Glm53Effort::Low => "low",
            Glm53Effort::High => "high",
            Glm53Effort::Max => "max",
        }
    }
}

/// ZCode catalog's `defaultLevel` for glm-5.3 — used when no effort is requested.
pub const GLM53_DEFAULT_EFFORT: Glm53Effort = Glm53Effort::Max;

/// Thinking budgets paired with each effort level (zcode catalog).
pub fn glm53_thinking_budget(effort: Glm53Effort) -> u64 {
    match effort {
        Glm53Effort::Low => 8_000,
        Glm53Effort::High => 16_000,
        Glm53Effort::Max => 32_000,
    }
}

/// Floor below which a thinking budget stops being useful; also the SDK's
/// default budget when thinking is enabled without one.
pub const GLM53_MIN_THINKING_BUDGET: u64 = 1_024;

/// Match the GLM-5.3 family (`glm-5.3`, `glm-5.3-flash`), case-insensitive.
/// Deliberately excludes `glm-5` / `glm-5.1` / `glm-5.2`; rejects a trailing
/// digit so a future `glm-5.30` would not falsely match.
pub fn is_glm53_model(model: &str) -> bool {
    let lower = model.to_ascii_lowercase();
    if !lower.starts_with("glm-5.3") {
        return false;
    }
    let rest = &lower["glm-5.3".len()..];
    !rest.starts_with(|c: char| c.is_ascii_digit())
}

/// Map an OpenAI `reasoning_effort` value onto the GLM-5.3 effort levels.
/// Rounds UP (`medium` → `high`); unknown values fall back to the catalog
/// default (`max`), mirroring ZCode's own defaultLevel.
pub fn normalize_glm53_effort(effort: Option<&str>) -> Glm53Effort {
    match effort {
        Some("none") | Some("minimal") | Some("light") | Some("low") => Glm53Effort::Low,
        Some("medium") | Some("high") => Glm53Effort::High,
        Some("xhigh") | Some("max") | Some("ultra") => Glm53Effort::Max,
        _ => GLM53_DEFAULT_EFFORT,
    }
}

/// Clamp a thinking budget against the MODEL's maxOutputTokens ceiling.
pub fn clamp_glm53_budget_to_model(budget: u64, model_max_tokens: Option<u64>) -> u64 {
    match model_max_tokens {
        Some(max) => budget.min(max.saturating_sub(1)),
        None => budget,
    }
}

/// Resolve the max_tokens fallback when the OpenAI client omits it: the real
/// client falls back to the model's CATALOG ceiling, never a small constant.
pub fn resolve_default_max_tokens(model: &str) -> u64 {
    model_def(model).map(|m| m.max_output_tokens).unwrap_or(4096)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glm53_family_matching() {
        assert!(is_glm53_model("glm-5.3"));
        assert!(is_glm53_model("GLM-5.3"));
        assert!(is_glm53_model("glm-5.3-flash"));
        assert!(!is_glm53_model("glm-5.2"));
        assert!(!is_glm53_model("glm-5.1"));
        assert!(!is_glm53_model("glm-5"));
        assert!(!is_glm53_model("glm-5.30"));
        assert!(!is_glm53_model(""));
    }

    #[test]
    fn effort_mapping_rounds_up() {
        assert_eq!(normalize_glm53_effort(Some("low")), Glm53Effort::Low);
        assert_eq!(normalize_glm53_effort(Some("none")), Glm53Effort::Low);
        assert_eq!(normalize_glm53_effort(Some("medium")), Glm53Effort::High);
        assert_eq!(normalize_glm53_effort(Some("high")), Glm53Effort::High);
        assert_eq!(normalize_glm53_effort(Some("xhigh")), Glm53Effort::Max);
        assert_eq!(normalize_glm53_effort(Some("ultra")), Glm53Effort::Max);
        assert_eq!(normalize_glm53_effort(None), Glm53Effort::Max);
        assert_eq!(normalize_glm53_effort(Some("bogus")), Glm53Effort::Max);
    }

    #[test]
    fn default_max_tokens_uses_catalog() {
        assert_eq!(resolve_default_max_tokens("glm-5.3"), 128_000);
        assert_eq!(resolve_default_max_tokens("unknown-model"), 4096);
    }
}
