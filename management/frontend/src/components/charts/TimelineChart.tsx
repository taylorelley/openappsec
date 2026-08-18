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

import { useMemo } from "react";
import type { TimeBucket } from "../../types";
import {
  actionColor,
  formatNumber,
  formatShortTime,
  niceMax,
} from "./chart-utils";
import { Tooltip, useTooltip } from "./Tooltip";
import { useMeasure } from "./useMeasure";

interface Props {
  buckets: TimeBucket[];
  height?: number;
}

const PAD_LEFT = 52;
const PAD_RIGHT = 8;
const PAD_TOP = 10;
const PAD_BOTTOM = 26;

/**
 * Requests over time, split by security action.
 *
 * A stacked column: the job is magnitude over time across a small, stable set
 * of categories, where the total matters as much as the split. One y-axis.
 */
export function TimelineChart({ buckets, height = 240 }: Props) {
  const { tip, show, hide } = useTooltip();
  const { ref, width } = useMeasure<HTMLDivElement>();

  const { series, max, totals } = useMemo(() => {
    const names = new Set<string>();
    for (const b of buckets) {
      for (const key of Object.keys(b.counts)) names.add(key);
    }
    // Sorted, so a series keeps its position as buckets change.
    const series = [...names].sort();
    const totals = buckets.map((b) =>
      series.reduce((sum, name) => sum + (b.counts[name] ?? 0), 0),
    );
    return { series, max: niceMax(Math.max(1, ...totals)), totals };
  }, [buckets]);

  const plotWidth = Math.max(width - PAD_LEFT - PAD_RIGHT, 10);
  const plotHeight = height - PAD_TOP - PAD_BOTTOM;
  const slot = buckets.length > 0 ? plotWidth / buckets.length : plotWidth;
  const barWidth = Math.max(Math.min(slot * 0.68, 42), 1);

  // Label every nth bucket so ticks never collide, whatever the width.
  const tickStep = Math.max(1, Math.ceil((buckets.length * 62) / Math.max(plotWidth, 1)));

  return (
    <div ref={ref} style={{ position: "relative", width: "100%" }}>
      {buckets.length === 0 || width === 0 ? (
        <EmptyPlot height={height} message="No events in this range." />
      ) : (
        <svg
          width={width}
          height={height}
          role="img"
          aria-label="Requests over time by security action"
          style={{ display: "block" }}
        >
          {/* Recessive gridlines with round-number ticks. */}
          {[0, 0.25, 0.5, 0.75, 1].map((fraction) => {
            const y = PAD_TOP + plotHeight * (1 - fraction);
            return (
              <g key={fraction}>
                <line
                  x1={PAD_LEFT}
                  x2={PAD_LEFT + plotWidth}
                  y1={y}
                  y2={y}
                  stroke="var(--grid)"
                  strokeWidth={1}
                />
                <text
                  x={PAD_LEFT - 8}
                  y={y + 4}
                  textAnchor="end"
                  fontSize={11}
                  fill="var(--text-muted)"
                  style={{ fontVariantNumeric: "tabular-nums" }}
                >
                  {formatNumber(Math.round(max * fraction))}
                </text>
              </g>
            );
          })}

          {buckets.map((bucket, i) => {
            let cursor = 0;
            const slotX = PAD_LEFT + i * slot;
            const x = slotX + (slot - barWidth) / 2;

            return (
              <g
                key={bucket.bucket}
                onMouseMove={(e) =>
                  show(
                    e,
                    <BucketTooltip
                      bucket={bucket}
                      series={series}
                      total={totals[i] ?? 0}
                    />,
                  )
                }
                onMouseLeave={hide}
              >
                {/* A full-height transparent target: the hit area is larger
                    than the mark, so short bars stay easy to hover. */}
                <rect
                  x={slotX}
                  y={PAD_TOP}
                  width={slot}
                  height={plotHeight}
                  fill="transparent"
                />
                {series.map((name) => {
                  const value = bucket.counts[name] ?? 0;
                  if (value === 0) return null;

                  const segment = (value / max) * plotHeight;
                  const y = PAD_TOP + plotHeight - cursor - segment;
                  cursor += segment;

                  return (
                    <rect
                      key={name}
                      x={x}
                      y={y}
                      width={barWidth}
                      // A 2px surface gap keeps stacked segments legible
                      // without needing a stroke.
                      height={Math.max(segment - 2, 1)}
                      fill={actionColor(name)}
                      rx={2}
                    />
                  );
                })}
              </g>
            );
          })}

          {/* Baseline. */}
          <line
            x1={PAD_LEFT}
            x2={PAD_LEFT + plotWidth}
            y1={PAD_TOP + plotHeight}
            y2={PAD_TOP + plotHeight}
            stroke="var(--axis)"
            strokeWidth={1}
          />

          {buckets.map((bucket, i) => {
            if (i % tickStep !== 0) return null;
            return (
              <text
                key={`tick-${bucket.bucket}`}
                x={PAD_LEFT + i * slot + slot / 2}
                y={height - 8}
                textAnchor="middle"
                fontSize={11}
                fill="var(--text-muted)"
                style={{ fontVariantNumeric: "tabular-nums" }}
              >
                {formatShortTime(bucket.bucket)}
              </text>
            );
          })}
        </svg>
      )}

      <Legend series={series} />
      <Tooltip tip={tip} />
    </div>
  );
}

function BucketTooltip({
  bucket,
  series,
  total,
}: {
  bucket: TimeBucket;
  series: string[];
  total: number;
}) {
  return (
    <div>
      <div style={{ fontWeight: 600, marginBottom: 4 }}>
        {new Date(bucket.bucket).toLocaleString()}
      </div>
      {series.map((name) => (
        <div key={name} className="row" style={{ gap: 6, marginTop: 2 }}>
          <span className="dot" style={{ background: actionColor(name) }} />
          <span style={{ flex: 1 }}>{name}</span>
          <span className="num" style={{ fontWeight: 600 }}>
            {formatNumber(bucket.counts[name] ?? 0)}
          </span>
        </div>
      ))}
      <div
        className="row"
        style={{
          gap: 6,
          marginTop: 5,
          borderTop: "1px solid var(--grid)",
          paddingTop: 4,
        }}
      >
        <span style={{ flex: 1 }} className="muted">
          Total
        </span>
        <span className="num" style={{ fontWeight: 600 }}>
          {formatNumber(total)}
        </span>
      </div>
    </div>
  );
}

/** A legend is always present for two or more series. */
export function Legend({ series }: { series: string[] }) {
  if (series.length < 2) return null;

  return (
    <div className="row" style={{ gap: 14, marginTop: 8 }}>
      {series.map((name) => (
        <span key={name} className="row" style={{ gap: 5 }}>
          <span className="dot" style={{ background: actionColor(name) }} />
          <span style={{ fontSize: 12, color: "var(--text-secondary)" }}>{name}</span>
        </span>
      ))}
    </div>
  );
}

export function EmptyPlot({
  height,
  message,
}: {
  height: number;
  message: string;
}) {
  return (
    <div
      className="muted"
      style={{
        height,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        fontSize: 13,
      }}
    >
      {message}
    </div>
  );
}
