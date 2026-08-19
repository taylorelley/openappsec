// Copyright (C) 2026 Check Point Software Technologies Ltd. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import type {
  Agent,
  AssetLearning,
  AuditEntry,
  Decision,
  EventRow,
  MetricSample,
  PolicyDocument,
  Revision,
  SearchResult,
  Suggestion,
  Summary,
  TimeBucket,
  TopEntry,
  TuningDecisionValue,
  TuningEventType,
  User,
  ValidationResult,
} from "./types";

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function request<T>(
  path: string,
  init: RequestInit = {},
): Promise<T> {
  const response = await fetch(path, {
    credentials: "same-origin",
    headers:
      init.body === undefined
        ? undefined
        : { "Content-Type": "application/json" },
    ...init,
  });

  if (response.status === 204) {
    return undefined as T;
  }

  const text = await response.text();
  if (!response.ok) {
    // The server sends {"error": "..."} for anything it expects a human to
    // read; fall back to the raw body for anything it does not.
    let message = text || response.statusText;
    try {
      const parsed = JSON.parse(text) as { error?: string };
      if (parsed.error) message = parsed.error;
    } catch {
      /* keep the raw text */
    }
    throw new ApiError(response.status, message);
  }

  return text ? (JSON.parse(text) as T) : (undefined as T);
}

// query builds a query string from any plain object, dropping empty values so
// an unset filter does not become `field=`.
function query(params: object): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== "") {
      search.set(key, String(value));
    }
  }
  const s = search.toString();
  return s ? `?${s}` : "";
}

export interface TimeRange {
  from?: string;
  to?: string;
}

export const api = {
  // ---------------------------------------------------------------- session
  session: () =>
    request<{ authenticated: boolean; user?: User }>("/api/session"),
  login: (username: string, password: string) =>
    request<User>("/api/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),
  logout: () => request<void>("/api/logout", { method: "POST" }),
  me: () => request<User>("/api/me"),
  changePassword: (currentPassword: string, newPassword: string) =>
    request<void>("/api/me/password", {
      method: "POST",
      body: JSON.stringify({ currentPassword, newPassword }),
    }),

  // ----------------------------------------------------------------- events
  searchEvents: (
    params: TimeRange & {
      q?: string;
      agentId?: string;
      limit?: number;
      offset?: number;
    },
  ) => request<SearchResult>(`/api/events${query(params)}`),
  getEvent: (id: number) => request<Record<string, unknown>>(`/api/events/${id}`),
  eventFields: () => request<string[]>("/api/events/fields"),

  // ------------------------------------------------------------- dashboards
  summary: (params: TimeRange & { q?: string; agentId?: string }) =>
    request<Summary>(`/api/dashboard/summary${query(params)}`),
  timeline: (
    params: TimeRange & { q?: string; groupBy?: string; buckets?: number },
  ) => request<TimeBucket[]>(`/api/dashboard/timeline${query(params)}`),
  top: (params: TimeRange & { q?: string; field: string; limit?: number }) =>
    request<TopEntry[]>(`/api/dashboard/top${query(params)}`),

  // ------------------------------------------------------------------ fleet
  agents: () => request<Agent[]>("/api/agents"),
  agent: (id: string) => request<Agent>(`/api/agents/${id}`),
  agentMetrics: (id: string) =>
    request<MetricSample[]>(`/api/agents/${id}/metrics`),
  enrollAgent: (name: string, agentUuid: string) =>
    request<{ agent: Agent; enrollmentToken: string; note: string }>(
      "/api/agents",
      { method: "POST", body: JSON.stringify({ name, agentUuid }) },
    ),
  updateAgent: (
    id: string,
    patch: { name?: string; metricsEndpoint?: string },
  ) =>
    request<Agent>(`/api/agents/${id}`, {
      method: "PATCH",
      body: JSON.stringify(patch),
    }),
  revokeAgent: (id: string) =>
    request<void>(`/api/agents/${id}/revoke`, { method: "POST" }),
  deleteAgent: (id: string) =>
    request<void>(`/api/agents/${id}`, { method: "DELETE" }),

  // ----------------------------------------------------------------- policy
  deployedPolicy: (agentId?: string) =>
    request<Revision>(`/api/policy${query({ agentId })}`),
  policySchema: () => request<Record<string, unknown>>("/api/policy/schema"),
  renderedPolicy: async (agentId?: string) => {
    const response = await fetch(`/api/policy/rendered${query({ agentId })}`, {
      credentials: "same-origin",
    });
    if (!response.ok) {
      throw new ApiError(response.status, await response.text());
    }
    return response.text();
  },
  revisions: (limit = 50) =>
    request<Revision[]>(`/api/policy/revisions${query({ limit })}`),
  revision: (id: number) => request<Revision>(`/api/policy/revisions/${id}`),
  revisionDiff: (from: number, to: number) =>
    request<{ diff: string }>(`/api/policy/revisions/${from}/diff/${to}`),
  validatePolicy: (body: PolicyDocument) =>
    request<ValidationResult>("/api/policy/validate", {
      method: "POST",
      body: JSON.stringify({ body }),
    }),
  diffCandidate: (body: PolicyDocument) =>
    request<{ diff: string }>("/api/policy/diff", {
      method: "POST",
      body: JSON.stringify({ body }),
    }),
  createRevision: (body: PolicyDocument, message: string) =>
    request<Revision>("/api/policy/revisions", {
      method: "POST",
      body: JSON.stringify({ body, message }),
    }),
  enforce: (revisionId: number, agentId?: string) =>
    request<{ revisionId: number; target: string }>("/api/policy/enforce", {
      method: "POST",
      body: JSON.stringify({ revisionId, agentId }),
    }),
  exceptionFromEvent: (eventId: number, keys: string[], action = "accept") =>
    request<{
      body: PolicyDocument;
      validation: ValidationResult;
      diff: string;
      exception: Record<string, unknown>;
    }>("/api/policy/exception-from-event", {
      method: "POST",
      body: JSON.stringify({ eventId, keys, action }),
    }),

  // --------------------------------------------------------------- learning
  learningAssets: () => request<AssetLearning[]>("/api/learning/assets"),
  suggestions: (assetId: string, tenantId: string, limit = 50) =>
    request<Suggestion[]>(
      `/api/learning/suggestions${query({ assetId, tenantId, limit })}`,
    ),
  decisions: (assetId?: string, tenantId?: string) =>
    request<Decision[]>(`/api/learning/decisions${query({ assetId, tenantId })}`),
  setDecision: (input: {
    tenantId: string;
    assetId: string;
    eventType: TuningEventType;
    eventTitle: string;
    decision: TuningDecisionValue;
  }) =>
    request<Decision>("/api/learning/decisions", {
      method: "POST",
      body: JSON.stringify(input),
    }),
  deleteDecision: (id: number) =>
    request<void>(`/api/learning/decisions/${id}`, { method: "DELETE" }),

  // ------------------------------------------------------------------ admin
  users: () => request<User[]>("/api/users"),
  createUser: (input: {
    username: string;
    email: string;
    password: string;
    role: string;
  }) =>
    request<User>("/api/users", {
      method: "POST",
      body: JSON.stringify(input),
    }),
  updateUser: (
    id: string,
    patch: { role?: string; disabled?: boolean; password?: string },
  ) =>
    request<User>(`/api/users/${id}`, {
      method: "PATCH",
      body: JSON.stringify(patch),
    }),
  deleteUser: (id: string) =>
    request<void>(`/api/users/${id}`, { method: "DELETE" }),
  audit: (limit = 200) => request<AuditEntry[]>(`/api/audit${query({ limit })}`),
};

export type { EventRow, Agent, Revision, User };
