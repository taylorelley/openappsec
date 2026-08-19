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

import type { ReactNode } from "react";

interface Props {
  label: string;
  value: ReactNode;
  hint?: string;
  /** Reserved for status meaning only; never used to make a tile decorative. */
  accent?: string;
}

/**
 * A single headline number. Not a chart: there is nothing to compare within a
 * tile, so a plot would add decoration and no information.
 */
export function StatTile({ label, value, hint, accent }: Props) {
  return (
    <div className="card" style={{ padding: "14px 16px" }}>
      <div style={{ fontSize: 12, color: "var(--text-secondary)", fontWeight: 600 }}>
        {label}
      </div>
      <div
        style={{
          fontSize: 28,
          fontWeight: 650,
          lineHeight: 1.15,
          marginTop: 4,
          // Text wears text tokens; an accent is only applied where the colour
          // is carrying a status meaning that the label also states.
          color: accent ?? "var(--text-primary)",
        }}
      >
        {value}
      </div>
      {hint && (
        <div style={{ fontSize: 11.5, color: "var(--text-muted)", marginTop: 2 }}>
          {hint}
        </div>
      )}
    </div>
  );
}
