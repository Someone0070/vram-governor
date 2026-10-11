export type RuntimeControlTier = "hot_vram" | "cold_disk";
export type RuntimeControlApi = <T>(path: string, init?: RequestInit) => Promise<T>;

type ResidencySnapshot = {
  target_id: string;
  model: string;
  observed_tier: string;
};

type ResidencyTransition = {
  id: string;
  idempotency_key: string;
  target_id: string;
  model: string;
  to_tier: string;
  observed_tier?: string;
  status: "planned" | "running" | "succeeded" | "failed" | "manual_reconciliation_required";
  error?: string;
};

type ResidencyTransitionResponse = {
  residency: ResidencySnapshot;
  transitions: ResidencyTransition[] | null;
};

type ResidencyListing = {
  residencies: ResidencySnapshot[];
  transitions: ResidencyTransition[] | null;
};

export type RuntimeControlOutcome =
  | { state: "recorded"; tier: RuntimeControlTier; requestKey: string; observedTier: string; transitionId?: string }
  | { state: "pending"; tier: RuntimeControlTier; requestKey: string; transitionId: string; transitionStatus: "planned" | "running"; observedTier?: string }
  | { state: "terminal"; tier: RuntimeControlTier; requestKey: string; transitionId: string; transitionStatus: "succeeded" | "failed"; currentTier?: string; message?: string }
  | { state: "attention"; tier: RuntimeControlTier; requestKey: string; transitionId: string; message: string }
  | { state: "unknown"; tier: RuntimeControlTier; requestKey: string; message: string };

const transitionStatuses = ["planned", "running", "succeeded", "failed", "manual_reconciliation_required"] as const;

function validTransition(value: unknown): value is ResidencyTransition {
  if (!value || typeof value !== "object") return false;
  const row = value as Partial<ResidencyTransition>;
  return typeof row.id === "string" && row.id.trim() !== "" &&
    typeof row.idempotency_key === "string" &&
    typeof row.target_id === "string" && typeof row.model === "string" && typeof row.to_tier === "string" &&
    transitionStatuses.includes(row.status as typeof transitionStatuses[number]) &&
    (row.observed_tier === undefined || typeof row.observed_tier === "string") &&
    (row.error === undefined || typeof row.error === "string");
}

function exactTransition(rows: unknown, targetId: string, model: string, tier: RuntimeControlTier, requestKey: string): ResidencyTransition | undefined {
  if (!Array.isArray(rows)) return undefined;
  for (let index = rows.length - 1; index >= 0; index--) {
    const candidate = rows[index];
    if (!validTransition(candidate)) continue;
    if (candidate.idempotency_key === requestKey && candidate.target_id === targetId &&
        candidate.model === model && candidate.to_tier === tier) return candidate;
  }
  return undefined;
}

function classifyTransition(transition: ResidencyTransition, tier: RuntimeControlTier, requestKey: string, currentTier?: string): RuntimeControlOutcome {
  if (transition.status === "failed" || transition.status === "succeeded") {
    return {
      state: "terminal", tier, requestKey, transitionId: transition.id,
      transitionStatus: transition.status, ...(currentTier ? { currentTier } : {}),
      ...(transition.error ? { message: transition.error } : {}),
    };
  }
  if (transition.status === "manual_reconciliation_required") {
    return { state: "attention", tier, requestKey, transitionId: transition.id, message: transition.error || "This transition requires manual reconciliation." };
  }
  return { state: "pending", tier, requestKey, transitionId: transition.id, transitionStatus: transition.status, ...(currentTier ? { observedTier: currentTier } : {}) };
}

function exactCurrentTier(rows: unknown, targetId: string, model: string): string | undefined {
  if (!Array.isArray(rows)) return undefined;
  const current = rows.find((row) => row && typeof row === "object" &&
    (row as ResidencySnapshot).target_id === targetId && (row as ResidencySnapshot).model === model &&
    typeof (row as ResidencySnapshot).observed_tier === "string");
  return current ? (current as ResidencySnapshot).observed_tier : undefined;
}

export function retireSettledRequestKeys(keys: Map<string, string>, transitions: unknown, targetId: string): void {
  for (const [scope, requestKey] of keys) {
    let parsed: unknown;
    try { parsed = JSON.parse(scope); } catch { continue; }
    if (!Array.isArray(parsed) || parsed.length !== 3 || parsed[0] !== targetId ||
        typeof parsed[1] !== "string" || (parsed[2] !== "hot_vram" && parsed[2] !== "cold_disk")) continue;
    const transition = exactTransition(transitions, targetId, parsed[1], parsed[2], requestKey);
    if (transition?.status === "succeeded") keys.delete(scope);
  }
}

function isMatchingResidency(response: ResidencyTransitionResponse, targetId: string, model: string): boolean {
  return Boolean(response && response.residency && response.residency.target_id === targetId &&
    response.residency.model === model && typeof response.residency.observed_tier === "string" &&
    (response.transitions === null || Array.isArray(response.transitions)));
}

function unknownOutcome(tier: RuntimeControlTier, requestKey: string, message: string): RuntimeControlOutcome {
  return { state: "unknown", tier, requestKey, message };
}

export async function recoverRuntimeTransition(
  apiCall: RuntimeControlApi,
  targetId: string,
  model: string,
  desiredTier: RuntimeControlTier,
  idempotencyKey: string,
): Promise<RuntimeControlOutcome> {
  try {
    const listing = await apiCall<ResidencyListing>("/admin/api/residency", { method: "GET" });
    const recovered = exactTransition(listing?.transitions, targetId, model, desiredTier, idempotencyKey);
    if (!recovered) {
      return unknownOutcome(desiredTier, idempotencyKey, "Request outcome is unknown; no exact matching transition was found by the read-only lookup.");
    }
    return classifyTransition(recovered, desiredTier, idempotencyKey, exactCurrentTier(listing?.residencies, targetId, model));
  } catch (lookupError) {
    return unknownOutcome(desiredTier, idempotencyKey,
      `Request outcome is unknown; the read-only recovery lookup failed: ${lookupError instanceof Error ? lookupError.message : "lookup failed"}`);
  }
}

export async function requestRuntimeTransition(
  apiCall: RuntimeControlApi,
  targetId: string,
  model: string,
  desiredTier: RuntimeControlTier,
  idempotencyKey: string,
): Promise<RuntimeControlOutcome> {
  if (typeof targetId !== "string" || targetId.trim() === "" ||
      typeof model !== "string" || model.trim() === "" ||
      (desiredTier !== "hot_vram" && desiredTier !== "cold_disk") ||
      typeof idempotencyKey !== "string" || idempotencyKey.trim() === "") {
    throw new Error("A target, model, load/unload tier, and idempotency key are required.");
  }

  let response: ResidencyTransitionResponse;
  try {
    response = await apiCall<ResidencyTransitionResponse>("/admin/api/residency/transition", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Idempotency-Key": idempotencyKey },
      body: JSON.stringify({ target_id: targetId, model, desired_tier: desiredTier }),
    });
  } catch (postError) {
    const recovered = await recoverRuntimeTransition(apiCall, targetId, model, desiredTier, idempotencyKey);
    return recovered.state === "unknown"
      ? { ...recovered, message: `${recovered.message} POST detail: ${postError instanceof Error ? postError.message : "request failed"}` }
      : recovered;
  }

  if (!isMatchingResidency(response, targetId, model)) {
    return recoverRuntimeTransition(apiCall, targetId, model, desiredTier, idempotencyKey);
  }
  const transition = exactTransition(response.transitions, targetId, model, desiredTier, idempotencyKey);
  if (transition) return classifyTransition(transition, desiredTier, idempotencyKey, response.residency.observed_tier);

  if (response.residency.observed_tier === desiredTier && (response.transitions === null || response.transitions.length === 0)) {
    return { state: "recorded", tier: desiredTier, requestKey: idempotencyKey, observedTier: response.residency.observed_tier };
  }

  return recoverRuntimeTransition(apiCall, targetId, model, desiredTier, idempotencyKey);
}
