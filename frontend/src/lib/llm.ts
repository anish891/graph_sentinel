import type { SystemStatus } from "../types/api";

const NAMES: Record<SystemStatus["llm_provider"], string> = {
  azure: "Azure OpenAI",
  groq: "Groq",
  mock: "Mock planner (not an LLM)",
  unavailable: "No LLM configured",
};

/** Human label for the active LLM provider, e.g. "Groq · openai/gpt-oss-120b". */
export function llmLabel(s: Pick<SystemStatus, "llm_provider" | "llm_model"> | undefined): string {
  if (!s) return "LLM";
  const name = NAMES[s.llm_provider];
  return s.llm_model && (s.llm_provider === "azure" || s.llm_provider === "groq") ? `${name} · ${s.llm_model}` : name;
}

export function isRealLlm(s: Pick<SystemStatus, "llm_provider"> | undefined): boolean {
  return s?.llm_provider === "azure" || s?.llm_provider === "groq";
}
