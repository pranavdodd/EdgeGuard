import type { SecurityEvent } from "./types";

export type ThreatAnalysisConfidence = "low" | "medium" | "high";

export interface ThreatAnalysis {
  analysisId: string;
  eventId: string;
  model: string;
  createdAt: string;
  summary: string;
  category: string;
  evidenceSignalIds: string[];
  recommendedAction: string;
  proposedRule: {
    title: string;
    rationale: string;
    pattern: string | null;
  } | null;
  confidence: ThreatAnalysisConfidence;
  caveats: string[];
}

export interface WorkersAiBinding {
  run: (model: string, input: Record<string, unknown>) => Promise<unknown>;
}

interface ThreatAnalysisDraft {
  summary: string;
  category: string;
  evidenceSignalIds: string[];
  recommendedAction: string;
  proposedRule: ThreatAnalysis["proposedRule"];
  confidence: ThreatAnalysisConfidence;
  caveats: string[];
}

const MAX_TEXT_LENGTH = 512;
const MAX_CATEGORY_LENGTH = 96;
const MAX_SIGNAL_IDS = 32;
const MAX_CAVEATS = 8;
const DEFAULT_MODEL = "@cf/meta/llama-3.1-8b-instruct";
const ANALYSIS_TIMEOUT_MS = 8_000;

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null;

const boundedString = (value: unknown, maxLength: number): string | null => {
  if (typeof value !== "string") {
    return null;
  }

  const normalized = value.trim();
  return normalized && normalized.length <= maxLength ? normalized : null;
};

const parseJsonObject = (value: unknown): unknown => {
  if (typeof value === "string") {
    try {
      return JSON.parse(value);
    } catch {
      return null;
    }
  }

  if (isRecord(value) && typeof value.response === "string") {
    return parseJsonObject(value.response);
  }

  return value;
};

export const parseThreatAnalysisDraft = (
  output: unknown,
): ThreatAnalysisDraft | null => {
  const value = parseJsonObject(output);
  if (!isRecord(value)) {
    return null;
  }

  const allowedKeys = new Set([
    "summary",
    "category",
    "evidenceSignalIds",
    "recommendedAction",
    "proposedRule",
    "confidence",
    "caveats",
  ]);
  if (Object.keys(value).some((key) => !allowedKeys.has(key))) {
    return null;
  }

  const summary = boundedString(value.summary, MAX_TEXT_LENGTH);
  const category = boundedString(value.category, MAX_CATEGORY_LENGTH);
  const recommendedAction = boundedString(
    value.recommendedAction,
    MAX_TEXT_LENGTH,
  );
  const confidence = value.confidence;
  const evidenceSignalIds = value.evidenceSignalIds;
  const caveats = value.caveats;

  if (
    !summary ||
    !category ||
    !recommendedAction ||
    !Array.isArray(evidenceSignalIds) ||
    evidenceSignalIds.length > MAX_SIGNAL_IDS ||
    !evidenceSignalIds.every((signalId) => boundedString(signalId, 96)) ||
    !["low", "medium", "high"].includes(confidence as string) ||
    !Array.isArray(caveats) ||
    caveats.length > MAX_CAVEATS ||
    !caveats.every((caveat) => boundedString(caveat, MAX_TEXT_LENGTH))
  ) {
    return null;
  }

  let proposedRule: ThreatAnalysis["proposedRule"] = null;
  if (value.proposedRule !== null) {
    if (!isRecord(value.proposedRule)) {
      return null;
    }

    const title = boundedString(value.proposedRule.title, MAX_TEXT_LENGTH);
    const rationale = boundedString(
      value.proposedRule.rationale,
      MAX_TEXT_LENGTH,
    );
    const pattern = value.proposedRule.pattern;
    const normalizedPattern =
      pattern === null ? null : boundedString(pattern, MAX_TEXT_LENGTH);
    if (
      !title ||
      !rationale ||
      (pattern !== null && normalizedPattern === null)
    ) {
      return null;
    }
    proposedRule = { title, rationale, pattern: normalizedPattern };
  }

  return {
    summary,
    category,
    evidenceSignalIds,
    recommendedAction,
    proposedRule,
    confidence: confidence as ThreatAnalysisConfidence,
    caveats,
  };
};

export const buildThreatAnalysisPrompt = (event: SecurityEvent): string =>
  JSON.stringify({
    task: "Analyze this security event and return only the requested JSON object.",
    outputSchema: {
      summary: "string",
      category: "string",
      evidenceSignalIds: "string[]",
      recommendedAction: "string",
      proposedRule: {
        title: "string",
        rationale: "string",
        pattern: "string|null",
      },
      confidence: "low|medium|high",
      caveats: "string[]",
    },
    event: {
      action: event.action,
      riskScore: event.riskScore,
      method: event.method,
      path: event.path,
      signalIds: event.signalIds,
      upstreamStatus: event.upstreamStatus,
    },
    constraints: [
      "This is advisory analysis only.",
      "Do not make a blocking decision or activate a rule.",
      "Use only the supplied event fields.",
    ],
  });

export const analyzeSecurityEvent = async (
  ai: WorkersAiBinding,
  event: SecurityEvent,
  model = DEFAULT_MODEL,
): Promise<ThreatAnalysis | null> => {
  const prompt = buildThreatAnalysisPrompt(event);
  let timeoutId: ReturnType<typeof setTimeout> | undefined;
  try {
    const result = await Promise.race([
      ai.run(model, {
        messages: [
          {
            role: "system",
            content:
              "You are a security analyst. Return strict JSON and never expose secrets.",
          },
          { role: "user", content: prompt },
        ],
      }),
      new Promise<never>((_, reject) => {
        timeoutId = setTimeout(
          () => reject(new Error("Workers AI analysis timed out")),
          ANALYSIS_TIMEOUT_MS,
        );
      }),
    ]);
    const draft = parseThreatAnalysisDraft(result);
    if (!draft) {
      return null;
    }

    return {
      analysisId: crypto.randomUUID(),
      eventId: event.id,
      model,
      createdAt: new Date().toISOString(),
      ...draft,
    };
  } finally {
    if (timeoutId) {
      clearTimeout(timeoutId);
    }
  }
};
