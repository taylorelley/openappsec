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

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";

import { api } from "../api";
import { ErrorBanner, Loading, PageHeader } from "../components/Layout";
import { StatTile } from "../components/StatTile";
import { BarList } from "../components/charts/BarList";
import { TimelineChart } from "../components/charts/TimelineChart";
import { formatNumber, severityColor } from "../components/charts/chart-utils";
import {
  rangeToParams,
  TimeRangePicker,
  type RangeId,
} from "../components/TimeRangePicker";

// Severity is ordered, so it is always presented in this order rather than by
// count — a shifting row order makes two readings hard to compare.
const SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"];

export function Dashboard() {
  const [range, setRange] = useState<RangeId>("24h");
  const params = rangeToParams(range);
  const navigate = useNavigate();

  const summary = useQuery({
    queryKey: ["summary", range],
    queryFn: () => api.summary(params),
    refetchInterval: 30_000,
  });
  const timeline = useQuery({
    queryKey: ["timeline", range],
    queryFn: () => api.timeline({ ...params, groupBy: "securityaction" }),
    refetchInterval: 30_000,
  });
  const topAttacks = useQuery({
    queryKey: ["top", "waapincidenttype", range],
    queryFn: () => api.top({ ...params, field: "waapincidenttype", limit: 8 }),
  });
  const topSources = useQuery({
    queryKey: ["top", "sourceip", range],
    queryFn: () => api.top({ ...params, field: "sourceip", limit: 8 }),
  });
  const topAssets = useQuery({
    queryKey: ["top", "assetname", range],
    queryFn: () => api.top({ ...params, field: "assetname", limit: 8 }),
  });
  const topUris = useQuery({
    queryKey: ["top", "httpuripath", range],
    queryFn: () => api.top({ ...params, field: "httpuripath", limit: 8 }),
  });

  const error =
    summary.error ?? timeline.error ?? topAttacks.error ?? topSources.error;

  const severityEntries = SEVERITY_ORDER.map((name) => ({
    key: name,
    count: summary.data?.bySeverity[name] ?? 0,
  })).filter((e) => e.count > 0);

  const total = summary.data?.total ?? 0;
  const prevented = summary.data?.prevented ?? 0;

  return (
    <>
      <PageHeader
        title="Dashboard"
        description="Security activity across every connected agent"
        actions={<TimeRangePicker value={range} onChange={setRange} />}
      />

      <ErrorBanner error={error} />

      <div
        className="grid"
        style={{ gridTemplateColumns: "repeat(auto-fit, minmax(170px, 1fr))" }}
      >
        <StatTile label="Security events" value={formatNumber(total)} />
        <StatTile
          label="Prevented"
          value={formatNumber(prevented)}
          hint={total > 0 ? `${Math.round((prevented / total) * 100)}% of events` : undefined}
        />
        <StatTile label="Detected" value={formatNumber(summary.data?.detected ?? 0)} />
        <StatTile
          label="Unique sources"
          value={formatNumber(summary.data?.uniqueSources ?? 0)}
        />
        <StatTile
          label="Protected hosts"
          value={formatNumber(summary.data?.uniqueHosts ?? 0)}
        />
      </div>

      <div style={{ height: 16 }} />

      <div className="card">
        <h2 className="card-title">Requests over time, by security action</h2>
        {timeline.isPending ? (
          <Loading />
        ) : (
          <TimelineChart buckets={timeline.data ?? []} />
        )}
      </div>

      <div style={{ height: 16 }} />

      <div
        className="grid"
        style={{ gridTemplateColumns: "repeat(auto-fit, minmax(310px, 1fr))" }}
      >
        <div className="card">
          <h2 className="card-title">Top attack types</h2>
          <BarList
            entries={topAttacks.data ?? []}
            onSelect={(key) =>
              navigate(`/events?q=${encodeURIComponent(`waapincidenttype:"${key}"`)}`)
            }
            emptyMessage="No attacks matched in this range."
          />
        </div>

        <div className="card">
          <h2 className="card-title">Events by severity</h2>
          <BarList
            entries={severityEntries}
            colorFor={severityColor}
            onSelect={(key) =>
              navigate(`/events?q=${encodeURIComponent(`eventseverity:${key}`)}`)
            }
            emptyMessage="No events in this range."
          />
        </div>

        <div className="card">
          <h2 className="card-title">Top source addresses</h2>
          <BarList
            entries={topSources.data ?? []}
            onSelect={(key) =>
              navigate(`/events?q=${encodeURIComponent(`sourceip:${key}`)}`)
            }
          />
        </div>

        <div className="card">
          <h2 className="card-title">Busiest assets</h2>
          <BarList
            entries={topAssets.data ?? []}
            onSelect={(key) =>
              navigate(`/events?q=${encodeURIComponent(`assetname:"${key}"`)}`)
            }
          />
        </div>

        <div className="card">
          <h2 className="card-title">Most targeted paths</h2>
          <BarList
            entries={topUris.data ?? []}
            onSelect={(key) =>
              navigate(`/events?q=${encodeURIComponent(`httpuripath:"${key}"`)}`)
            }
          />
        </div>
      </div>
    </>
  );
}
