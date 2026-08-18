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

// Categorical series colours, in fixed slot order. Assigned by entity, never
// by rank, and never cycled: an entity keeps its colour when a filter changes
// which entities are on screen.
export const SERIES_VARS = [
  "var(--series-1)",
  "var(--series-2)",
  "var(--series-3)",
  "var(--series-4)",
] as const;

// A stable colour per security action, so Prevent does not become orange just
// because a filter removed every Detect row.
const ACTION_SLOTS: Record<string, string> = {
  prevent: "var(--series-1)",
  detect: "var(--series-2)",
};

export function actionColor(action: string, fallbackIndex = 0): string {
  return (
    ACTION_SLOTS[action.toLowerCase()] ??
    SERIES_VARS[fallbackIndex % SERIES_VARS.length] ??
    "var(--series-1)"
  );
}

// Severity is a state, not a series, so it uses the reserved status palette.
// Status colour never travels alone — every use here sits beside its label.
export function severityColor(severity: string): string {
  switch (severity.toLowerCase()) {
    case "critical":
      return "var(--status-critical)";
    case "high":
      return "var(--status-serious)";
    case "medium":
      return "var(--status-warning)";
    case "low":
      return "var(--status-good)";
    default:
      return "var(--text-muted)";
  }
}

export function healthColor(health: string): string {
  switch (health) {
    case "healthy":
      return "var(--status-good)";
    case "degraded":
      return "var(--status-warning)";
    case "unhealthy":
      return "var(--status-critical)";
    default:
      return "var(--text-muted)";
  }
}

export function formatNumber(n: number): string {
  if (!Number.isFinite(n)) return "—";
  if (Math.abs(n) >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (Math.abs(n) >= 10_000) return `${(n / 1000).toFixed(1)}k`;
  return n.toLocaleString();
}

export function formatTime(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

export function formatShortTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

export function relativeTime(iso?: string): string {
  if (!iso) return "never";
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return iso;

  const seconds = Math.round((Date.now() - then) / 1000);
  if (seconds < 60) return "just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

// niceMax rounds an axis maximum up to a readable value, so ticks land on
// round numbers rather than on the data's exact peak.
export function niceMax(value: number): number {
  if (value <= 0) return 1;
  const magnitude = 10 ** Math.floor(Math.log10(value));
  const normalized = value / magnitude;
  const step = normalized <= 1 ? 1 : normalized <= 2 ? 2 : normalized <= 5 ? 5 : 10;
  return step * magnitude;
}
