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

import type { TopEntry } from "../../types";
import { formatNumber } from "./chart-utils";
import { EmptyPlot } from "./TimelineChart";

interface Props {
  entries: TopEntry[];
  /** Optional per-row colour, e.g. severity. Omit for a single-hue ranking. */
  colorFor?: (key: string) => string;
  emptyMessage?: string;
  onSelect?: (key: string) => void;
}

/**
 * A ranked horizontal bar list — the right form for "top N by volume", where
 * the labels are long and comparison is between rows.
 *
 * One series, so no legend: the card title names it. Values are direct-labelled
 * because there are few enough rows for that to stay readable.
 */
export function BarList({ entries, colorFor, emptyMessage, onSelect }: Props) {
  if (entries.length === 0) {
    return <EmptyPlot height={120} message={emptyMessage ?? "No data in this range."} />;
  }

  const max = Math.max(...entries.map((e) => e.count), 1);

  return (
    <div className="stack" style={{ gap: 7 }}>
      {entries.map((entry) => {
        const pct = (entry.count / max) * 100;
        const label = entry.key || "(none)";
        const interactive = Boolean(onSelect);

        return (
          <div
            key={entry.key}
            onClick={onSelect ? () => onSelect(entry.key) : undefined}
            role={interactive ? "button" : undefined}
            tabIndex={interactive ? 0 : undefined}
            onKeyDown={
              onSelect
                ? (e) => {
                    if (e.key === "Enter" || e.key === " ") {
                      e.preventDefault();
                      onSelect(entry.key);
                    }
                  }
                : undefined
            }
            style={{ cursor: interactive ? "pointer" : "default" }}
            title={label}
          >
            <div
              className="row"
              style={{ justifyContent: "space-between", gap: 12, marginBottom: 3 }}
            >
              <span
                style={{
                  fontSize: 12.5,
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                }}
              >
                {label}
              </span>
              <span className="num" style={{ fontSize: 12.5, fontWeight: 600 }}>
                {formatNumber(entry.count)}
              </span>
            </div>
            <div
              style={{
                height: 6,
                background: "var(--surface-sunken)",
                borderRadius: 3,
                overflow: "hidden",
              }}
            >
              <div
                style={{
                  width: `${Math.max(pct, 1.5)}%`,
                  height: "100%",
                  // Rounded data-end, anchored to the baseline at the left.
                  borderRadius: "0 3px 3px 0",
                  background: colorFor ? colorFor(entry.key) : "var(--seq-450)",
                }}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
}
