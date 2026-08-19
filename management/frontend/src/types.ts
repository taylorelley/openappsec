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

export type Role = "admin" | "editor" | "viewer";

export interface User {
  id: string;
  username: string;
  email: string;
  role: Role;
  disabled: boolean;
  createdAt: string;
  lastLoginAt?: string;
}

export interface EventRow {
  id: number;
  eventTime: string;
  agentId?: string;
  eventName: string;
  eventSeverity: string;
  eventConfidence: string;
  assetName: string;
  securityAction: string;
  waapIncidentType: string;
  sourceIp: string;
  sourceCountryName: string;
  httpHostName: string;
  httpMethod: string;
  httpUriPath: string;
  httpResponseCode?: number;
  matchedLocation: string;
  matchedParameter: string;
  matchedSample: string;
  practiceType: string;
  waapFinalScore?: number;
}

export interface SearchResult {
  rows: EventRow[];
  total: number;
  limit: number;
  offset: number;
  truncated: boolean;
}

export interface Summary {
  total: number;
  prevented: number;
  detected: number;
  uniqueHosts: number;
  uniqueSources: number;
  bySeverity: Record<string, number>;
}

export interface TimeBucket {
  bucket: string;
  counts: Record<string, number>;
}

export interface TopEntry {
  key: string;
  count: number;
}

export type Health = "healthy" | "degraded" | "unhealthy" | "unknown";

export interface Agent {
  id: string;
  name: string;
  agentUuid: string;
  tenantId: string;
  profileId: string;
  mode: string;
  version: string;
  policyVersion: string;
  appliedRevisionId?: number;
  health: Health;
  status: Record<string, unknown>;
  labels: Record<string, unknown>;
  metricsEndpoint: string;
  enrolled: boolean;
  firstSeenAt: string;
  lastSeenAt?: string;
  lastStatusAt?: string;
}

export interface MetricSample {
  name: string;
  labels: Record<string, string>;
  value: number;
}

// The canonical policy document. It is intentionally untyped beyond this: the
// schema grows between agent versions, and the editor round-trips fields it
// does not know about rather than dropping them.
export type PolicyDocument = Record<string, unknown>;

export interface Revision {
  id: number;
  apiVersion: string;
  body: PolicyDocument;
  checksum: string;
  message: string;
  authorName?: string;
  createdAt: string;
}

export interface Problem {
  path: string;
  message: string;
  severity: "error" | "warning";
}

export interface ValidationResult {
  errors: Problem[];
  warnings: Problem[];
}

export type Readiness =
  | "insufficient-data"
  | "learning"
  | "nearly-ready"
  | "ready-for-prevent";

export interface AssetLearning {
  tenantId: string;
  assetId: string;
  assetName: string;
  firstSeenAt: string;
  lastSeenAt: string;
  totalEvents: number;
  uniqueSources: number;
  uniqueUris: number;
  learningHours: number;
  completedLearningWindows: number;
  lastWindowAt?: string;
  criticalLast48h: number;
  highLast48h: number;
  preventLast48h: number;
  detectLast48h: number;
  openSuggestions: number;
  decisions: number;
  readiness: Readiness;
  recommendation: string;
}

export type TuningEventType =
  | "source"
  | "url"
  | "parameterName"
  | "parameterValue";
export type TuningDecisionValue = "benign" | "malicious" | "dismiss";

export interface Suggestion {
  tenantId: string;
  assetId: string;
  assetName: string;
  eventType: TuningEventType;
  eventTitle: string;
  events: number;
  sources: number;
  topAttackType: string;
  maxSeverity: string;
  firstSeen: string;
  lastSeen: string;
  decision?: string;
}

export interface Decision {
  id: number;
  tenantId: string;
  assetId: string;
  eventType: TuningEventType;
  eventTitle: string;
  decision: TuningDecisionValue;
  decidedBy: string;
  decidedAt: string;
}

export interface AuditEntry {
  id: number;
  occurredAt: string;
  username: string;
  action: string;
  targetType: string;
  targetId: string;
  detail: unknown;
  remoteAddr: string;
}
