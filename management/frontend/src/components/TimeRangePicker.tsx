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

export const RANGES = [
  { id: "1h", label: "Last hour", hours: 1 },
  { id: "24h", label: "Last 24 hours", hours: 24 },
  { id: "7d", label: "Last 7 days", hours: 24 * 7 },
  { id: "30d", label: "Last 30 days", hours: 24 * 30 },
] as const;

export type RangeId = (typeof RANGES)[number]["id"];

export function rangeToParams(id: RangeId): { from: string; to: string } {
  const range = RANGES.find((r) => r.id === id) ?? RANGES[1];
  const to = new Date();
  const from = new Date(to.getTime() - range.hours * 3600_000);
  return { from: from.toISOString(), to: to.toISOString() };
}

/** Filters sit in one row above the charts they drive. */
export function TimeRangePicker({
  value,
  onChange,
}: {
  value: RangeId;
  onChange: (id: RangeId) => void;
}) {
  return (
    <div className="row" style={{ gap: 2 }} role="group" aria-label="Time range">
      {RANGES.map((range) => (
        <button
          key={range.id}
          className="btn btn-sm"
          onClick={() => onChange(range.id)}
          aria-pressed={value === range.id}
          style={{
            background:
              value === range.id ? "var(--surface-sunken)" : "var(--surface-raised)",
            fontWeight: value === range.id ? 600 : 500,
          }}
        >
          {range.label}
        </button>
      ))}
    </div>
  );
}
