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

import { useEffect, useState, type FormEvent } from "react";
import { useQuery } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";

import { api } from "../api";
import { ErrorBanner, Loading, PageHeader } from "../components/Layout";
import {
  rangeToParams,
  TimeRangePicker,
  type RangeId,
} from "../components/TimeRangePicker";
import {
  actionColor,
  formatTime,
  severityColor,
} from "../components/charts/chart-utils";
import type { EventRow } from "../types";
import { EventDetail } from "../components/EventDetail";

const PAGE_SIZE = 100;

export function Events() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [range, setRange] = useState<RangeId>("24h");
  const [draft, setDraft] = useState(searchParams.get("q") ?? "");
  const [page, setPage] = useState(0);
  const [selected, setSelected] = useState<EventRow | null>(null);

  const query = searchParams.get("q") ?? "";

  // Navigating in from a dashboard drill-down changes the URL, not the box.
  useEffect(() => setDraft(query), [query]);
  useEffect(() => setPage(0), [query, range]);

  const params = rangeToParams(range);
  const events = useQuery({
    queryKey: ["events", query, range, page],
    queryFn: () =>
      api.searchEvents({
        ...params,
        q: query,
        limit: PAGE_SIZE,
        offset: page * PAGE_SIZE,
      }),
    refetchInterval: page === 0 ? 15_000 : false,
  });

  const fields = useQuery({
    queryKey: ["event-fields"],
    queryFn: api.eventFields,
    staleTime: Infinity,
  });

  function submit(e: FormEvent) {
    e.preventDefault();
    setSearchParams(draft ? { q: draft } : {});
  }

  const rows = events.data?.rows ?? [];
  const total = events.data?.total ?? 0;

  return (
    <>
      <PageHeader
        title="Events"
        description="Security events reported by every agent"
        actions={<TimeRangePicker value={range} onChange={setRange} />}
      />

      <form onSubmit={submit} className="row" style={{ marginBottom: 14, gap: 8 }}>
        <input
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          placeholder={`Filter, e.g. sourceip:192.168.0.0/16 AND securityaction:Prevent`}
          list="event-fields"
          aria-label="Event query"
          style={{ flex: 1, minWidth: 260, fontFamily: "var(--mono)", fontSize: 12.5 }}
        />
        <datalist id="event-fields">
          {(fields.data ?? []).map((f) => (
            <option key={f} value={`${f}:`} />
          ))}
        </datalist>
        <button className="btn btn-primary" type="submit">
          Search
        </button>
        {query && (
          <button
            className="btn"
            type="button"
            onClick={() => setSearchParams({})}
          >
            Clear
          </button>
        )}
      </form>

      <ErrorBanner error={events.error} />

      <div className="card" style={{ padding: 0 }}>
        <div
          className="row"
          style={{
            justifyContent: "space-between",
            padding: "10px 14px",
            borderBottom: "1px solid var(--border)",
          }}
        >
          <span className="muted" style={{ fontSize: 12.5 }}>
            {events.isPending
              ? "Searching…"
              : `${events.data?.truncated ? "over " : ""}${total.toLocaleString()} matching events`}
          </span>
          <span className="row" style={{ gap: 6 }}>
            <button
              className="btn btn-sm"
              disabled={page === 0}
              onClick={() => setPage((p) => Math.max(0, p - 1))}
            >
              Previous
            </button>
            <span className="muted num" style={{ fontSize: 12.5 }}>
              Page {page + 1}
            </span>
            <button
              className="btn btn-sm"
              disabled={rows.length < PAGE_SIZE}
              onClick={() => setPage((p) => p + 1)}
            >
              Next
            </button>
          </span>
        </div>

        {events.isPending ? (
          <Loading />
        ) : rows.length === 0 ? (
          <div className="muted" style={{ padding: 32, textAlign: "center" }}>
            No events matched.
          </div>
        ) : (
          <div className="scroll-x">
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Severity</th>
                  <th>Action</th>
                  <th>Attack type</th>
                  <th>Asset</th>
                  <th>Source</th>
                  <th>Host</th>
                  <th>Path</th>
                  <th>Matched</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <tr
                    key={row.id}
                    onClick={() => setSelected(row)}
                    tabIndex={0}
                    // Opening an event was mouse-only; BarList already handles
                    // Enter and Space for the same pattern.
                    onKeyDown={(e) => {
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        setSelected(row);
                      }
                    }}
                    style={{ cursor: "pointer" }}
                  >
                    <td className="num" style={{ whiteSpace: "nowrap" }}>
                      {formatTime(row.eventTime)}
                    </td>
                    <td>
                      {/* Colour never alone: the dot always sits beside the
                          severity's own name. */}
                      <span className="row" style={{ gap: 5, flexWrap: "nowrap" }}>
                        <span
                          className="dot"
                          style={{ background: severityColor(row.eventSeverity) }}
                        />
                        {row.eventSeverity || "—"}
                      </span>
                    </td>
                    <td>
                      <span className="row" style={{ gap: 5, flexWrap: "nowrap" }}>
                        <span
                          className="dot"
                          style={{ background: actionColor(row.securityAction) }}
                        />
                        {row.securityAction || "—"}
                      </span>
                    </td>
                    <td>{row.waapIncidentType || "—"}</td>
                    <td>{row.assetName || "—"}</td>
                    <td className="mono">{row.sourceIp || "—"}</td>
                    <td>{row.httpHostName || "—"}</td>
                    <td
                      className="mono"
                      style={{
                        maxWidth: 240,
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}
                      title={row.httpUriPath}
                    >
                      {row.httpUriPath || "—"}
                    </td>
                    <td
                      className="mono"
                      style={{
                        maxWidth: 200,
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}
                      title={row.matchedSample}
                    >
                      {row.matchedSample || "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {selected && (
        <EventDetail event={selected} onClose={() => setSelected(null)} />
      )}
    </>
  );
}
