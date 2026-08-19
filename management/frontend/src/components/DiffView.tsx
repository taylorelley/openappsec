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

/**
 * A unified diff of the rendered policy.
 *
 * Added and removed lines carry a +/- prefix as well as a tint, so the change
 * is legible without relying on colour.
 */
export function DiffView({ diff }: { diff: string }) {
  if (!diff.trim()) {
    return (
      <div className="muted" style={{ fontSize: 13, padding: "20px 0" }}>
        The candidate matches what is deployed.
      </div>
    );
  }

  const lines = diff.split("\n");

  return (
    <pre
      className="mono"
      style={{
        background: "var(--surface-sunken)",
        borderRadius: "var(--radius-sm)",
        padding: "10px 0",
        margin: 0,
        overflowX: "auto",
        fontSize: 11.5,
        maxHeight: 620,
      }}
    >
      {lines.map((line, i) => {
        const added = line.startsWith("+") && !line.startsWith("+++");
        const removed = line.startsWith("-") && !line.startsWith("---");
        const hunk = line.startsWith("@@");

        return (
          <div
            key={i}
            style={{
              padding: "0 12px",
              whiteSpace: "pre",
              background: added
                ? "color-mix(in srgb, var(--status-good) 14%, transparent)"
                : removed
                  ? "color-mix(in srgb, var(--status-critical) 14%, transparent)"
                  : undefined,
              color: hunk ? "var(--text-muted)" : undefined,
            }}
          >
            {line || " "}
          </div>
        );
      })}
    </pre>
  );
}
