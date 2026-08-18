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
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api } from "../api";
import { useAuth } from "../auth-context";
import { ErrorBanner, Loading, PageHeader } from "../components/Layout";
import {
  formatNumber,
  formatTime,
  healthColor,
  relativeTime,
} from "../components/charts/chart-utils";
import type { Agent } from "../types";
import { Modal } from "../components/Modal";

// The metrics worth surfacing per agent, what to call them, and how to combine
// the samples. The aggregation is not cosmetic: a metric arrives once per
// process and per asset, so summing a peak or an average across those samples
// reports nonsense — two processes each at 40% CPU would read as 80% peak.
type Aggregation = "sum" | "max" | "mean";

const HEADLINE_METRICS: Array<[string, string, Aggregation]> = [
  ["total_requests_counter", "Requests inspected", "sum"],
  ["requests_blocked_by_waf_counter", "Blocked by the WAF", "sum"],
  ["unique_sources_counter", "Unique sources", "max"],
  ["requests_time_latency_average", "Average latency (ms)", "mean"],
  ["cpu_usage_percentage_max", "Peak CPU (%)", "max"],
  ["service_physical_memory_size_kb_max", "Peak memory (KB)", "max"],
];

function aggregate(values: number[], kind: Aggregation): number {
  if (values.length === 0) return 0;
  if (kind === "max") return Math.max(...values);

  const sum = values.reduce((a, b) => a + b, 0);
  return kind === "mean" ? sum / values.length : sum;
}

export function Fleet() {
  const { canEdit, canAdmin } = useAuth();
  const queryClient = useQueryClient();
  const [selected, setSelected] = useState<Agent | null>(null);
  const [showEnroll, setShowEnroll] = useState(false);
  const [issuedToken, setIssuedToken] = useState<string | null>(null);

  const agents = useQuery({
    queryKey: ["agents"],
    queryFn: api.agents,
    refetchInterval: 15_000,
  });

  // Writes go through useMutation so a failed request surfaces in the banner.
  // React does not observe a rejected promise returned from an event handler,
  // so an inline async onClick would fail silently.
  const remove = useMutation({
    mutationFn: (id: string) => api.deleteAgent(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["agents"] }),
  });

  const enroll = useMutation({
    mutationFn: ({ name, uuid }: { name: string; uuid: string }) =>
      api.enrollAgent(name, uuid),
    onSuccess: async (result) => {
      setIssuedToken(result.enrollmentToken);
      setShowEnroll(false);
      await queryClient.invalidateQueries({ queryKey: ["agents"] });
    },
  });

  return (
    <>
      <PageHeader
        title="Fleet"
        description="Every agent reporting to this manager"
        actions={
          canEdit && (
            <button className="btn btn-primary" onClick={() => setShowEnroll(true)}>
              Enroll an agent
            </button>
          )
        }
      />

      <ErrorBanner error={agents.error ?? enroll.error ?? remove.error} />

      {issuedToken && (
        <div className="banner banner-ok" style={{ marginBottom: 14 }}>
          <strong>Enrollment token — copy it now, it is not shown again.</strong>
          <pre className="mono" style={{ margin: "8px 0 0", whiteSpace: "pre-wrap" }}>
            {issuedToken}
          </pre>
          <button
            className="btn btn-sm"
            style={{ marginTop: 8 }}
            onClick={() => setIssuedToken(null)}
          >
            Done
          </button>
        </div>
      )}

      {showEnroll && (
        <EnrollForm
          busy={enroll.isPending}
          onCancel={() => setShowEnroll(false)}
          onSubmit={(name, uuid) => enroll.mutate({ name, uuid })}
        />
      )}

      {agents.isPending ? (
        <Loading />
      ) : (agents.data ?? []).length === 0 ? (
        <EmptyFleet />
      ) : (
        <div className="card" style={{ padding: 0 }}>
          <div className="scroll-x">
            <table>
              <thead>
                <tr>
                  <th>Agent</th>
                  <th>Health</th>
                  <th>Mode</th>
                  <th>Policy version</th>
                  <th>Version</th>
                  <th>Last seen</th>
                  <th>Managed by</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {(agents.data ?? []).map((agent) => (
                  <tr key={agent.id}>
                    <td>
                      <div style={{ fontWeight: 600 }}>{agent.name || "unnamed"}</div>
                      <div className="mono muted" style={{ fontSize: 11 }}>
                        {agent.agentUuid || "—"}
                      </div>
                    </td>
                    <td>
                      {/* Icon + label: health is never colour alone. */}
                      <span className="row" style={{ gap: 5, flexWrap: "nowrap" }}>
                        <span
                          className="dot"
                          style={{ background: healthColor(agent.health) }}
                        />
                        {agent.health}
                      </span>
                    </td>
                    <td>{agent.mode || "—"}</td>
                    <td className="num">{agent.policyVersion || "—"}</td>
                    <td className="num">{agent.version || "—"}</td>
                    <td className="num" title={agent.lastSeenAt ? formatTime(agent.lastSeenAt) : ""}>
                      {relativeTime(agent.lastSeenAt)}
                    </td>
                    <td>
                      <span className="chip">
                        {agent.enrolled ? "sync companion" : "discovered"}
                      </span>
                    </td>
                    <td style={{ textAlign: "right", whiteSpace: "nowrap" }}>
                      <button
                        className="btn btn-sm"
                        onClick={() => setSelected(agent)}
                      >
                        Details
                      </button>
                      {canAdmin && (
                        <button
                          className="btn btn-sm btn-danger"
                          style={{ marginLeft: 6 }}
                          disabled={remove.isPending}
                          onClick={() => {
                            // Removing an agent drops its events and history,
                            // so confirm rather than acting on a stray click.
                            if (
                              window.confirm(
                                `Remove ${agent.name || "this agent"}? Its recorded status and metrics are deleted.`,
                              )
                            ) {
                              remove.mutate(agent.id);
                            }
                          }}
                        >
                          Remove
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {selected && (
        <AgentDetail agent={selected} onClose={() => setSelected(null)} />
      )}
    </>
  );
}

function EmptyFleet() {
  return (
    <div className="card">
      <h2 className="card-title">No agents yet</h2>
      <p style={{ fontSize: 13, marginTop: 0 }}>
        An agent appears here as soon as it sends its first event. To route an
        agent's events to this manager, set{" "}
        <code className="mono">TUNING_HOST</code> to this manager's hostname on
        the agent container, and enable{" "}
        <code className="mono">logDestination.local-tuning</code> in the policy's
        log trigger.
      </p>
      <p style={{ fontSize: 13 }}>
        For agents this manager cannot reach by shared volume, enroll one above
        and run <code className="mono">appsec-agent-sync</code> alongside it.
      </p>
    </div>
  );
}

function EnrollForm({
  busy,
  onCancel,
  onSubmit,
}: {
  busy: boolean;
  onCancel: () => void;
  onSubmit: (name: string, uuid: string) => void;
}) {
  const [name, setName] = useState("");
  const [uuid, setUuid] = useState("");

  return (
    <div className="card" style={{ marginBottom: 14 }}>
      <h2 className="card-title">Enroll an agent</h2>
      <p className="muted" style={{ fontSize: 12.5, marginTop: 0 }}>
        Issues a token for the <code className="mono">appsec-agent-sync</code>{" "}
        companion. Leave the agent ID blank if you do not know it yet — it is
        matched up automatically once the agent reports.
      </p>
      <div className="row" style={{ gap: 10, alignItems: "flex-end" }}>
        <div style={{ flex: 1, minWidth: 180 }}>
          <label htmlFor="agent-name">Name</label>
          <input
            id="agent-name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="edge-nginx-1"
          />
        </div>
        <div style={{ flex: 1, minWidth: 180 }}>
          <label htmlFor="agent-uuid">Agent ID (optional)</label>
          <input
            id="agent-uuid"
            value={uuid}
            onChange={(e) => setUuid(e.target.value)}
            placeholder="from open-appsec-ctl -s"
          />
        </div>
        <button
          className="btn btn-primary"
          disabled={busy || !name}
          onClick={() => onSubmit(name, uuid)}
        >
          {busy ? "Enrolling…" : "Enroll"}
        </button>
        <button className="btn" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </div>
  );
}

function AgentDetail({ agent, onClose }: { agent: Agent; onClose: () => void }) {
  const queryClient = useQueryClient();
  const [endpoint, setEndpoint] = useState(agent.metricsEndpoint);

  const metrics = useQuery({
    queryKey: ["agent-metrics", agent.id],
    queryFn: () => api.agentMetrics(agent.id),
    refetchInterval: 30_000,
  });

  // The server validates the endpoint and refuses internal targets, so the
  // rejection has to be visible here rather than swallowed.
  const saveEndpoint = useMutation({
    mutationFn: (value: string) =>
      api.updateAgent(agent.id, { metricsEndpoint: value }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["agents"] });
      await queryClient.invalidateQueries({ queryKey: ["agent-metrics"] });
    },
  });

  const headline = HEADLINE_METRICS.map(([name, label, kind]) => {
    const values = (metrics.data ?? [])
      .filter((m) => m.name === name)
      .map((m) => m.value);
    return { label, value: aggregate(values, kind), present: values.length > 0 };
  }).filter((m) => m.present);

  return (
    <Modal label={`Agent ${agent.name || "detail"}`} onClose={onClose} width={640}>
      <>
        <div className="row" style={{ justifyContent: "space-between", marginBottom: 16 }}>
          <h2 style={{ margin: 0, fontSize: 17 }}>{agent.name || "unnamed agent"}</h2>
          <button className="btn btn-sm" onClick={onClose}>
            Close
          </button>
        </div>

        <div className="stack" style={{ gap: 3, marginBottom: 18, fontSize: 12.5 }}>
          <Row label="Agent ID" value={agent.agentUuid} mono />
          <Row label="Tenant" value={agent.tenantId} mono />
          <Row label="Profile" value={agent.profileId} mono />
          <Row label="Orchestration mode" value={agent.mode} />
          <Row label="Policy version" value={agent.policyVersion} />
          <Row
            label="Applied revision"
            value={agent.appliedRevisionId ? String(agent.appliedRevisionId) : "—"}
          />
          <Row label="First seen" value={formatTime(agent.firstSeenAt)} />
          <Row
            label="Last status"
            value={agent.lastStatusAt ? formatTime(agent.lastStatusAt) : "never"}
          />
        </div>

        <h3 className="card-title">Metrics endpoint</h3>
        <p className="muted" style={{ fontSize: 12, marginTop: 0 }}>
          A hostname is expanded to <code className="mono">http://host:7465/metrics</code>.
          The agent needs <code className="mono">PROMETHEUS=true</code> for this to
          serve anything.
        </p>
        <ErrorBanner error={saveEndpoint.error} />
        <div className="row" style={{ gap: 8, marginBottom: 18 }}>
          <input
            value={endpoint}
            onChange={(e) => setEndpoint(e.target.value)}
            placeholder="appsec-agent"
            style={{ flex: 1 }}
            aria-label="Metrics endpoint"
          />
          <button
            className="btn"
            disabled={saveEndpoint.isPending}
            onClick={() => saveEndpoint.mutate(endpoint)}
          >
            {saveEndpoint.isPending ? "Saving…" : "Save"}
          </button>
        </div>

        <h3 className="card-title">Latest metrics</h3>
        {metrics.isPending ? (
          <Loading />
        ) : headline.length === 0 ? (
          <p className="muted" style={{ fontSize: 12.5 }}>
            No metrics scraped yet.
          </p>
        ) : (
          <div
            className="grid"
            style={{ gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))" }}
          >
            {headline.map((m) => (
              <div key={m.label} className="card" style={{ padding: "10px 12px" }}>
                <div className="muted" style={{ fontSize: 11.5 }}>
                  {m.label}
                </div>
                <div className="num" style={{ fontSize: 19, fontWeight: 650 }}>
                  {formatNumber(Math.round(m.value * 100) / 100)}
                </div>
              </div>
            ))}
          </div>
        )}

        <h3 className="card-title" style={{ marginTop: 18 }}>
          Reported status
        </h3>
        <pre
          className="mono"
          style={{
            background: "var(--surface-sunken)",
            padding: 12,
            borderRadius: "var(--radius-sm)",
            overflowX: "auto",
            margin: 0,
            fontSize: 11.5,
            maxHeight: 320,
          }}
        >
          {JSON.stringify(agent.status ?? {}, null, 2)}
        </pre>
      </>
    </Modal>
  );
}

function Row({
  label,
  value,
  mono,
}: {
  label: string;
  value?: string;
  mono?: boolean;
}) {
  return (
    <div className="row" style={{ gap: 10 }}>
      <span className="muted" style={{ width: 150, flex: "none" }}>
        {label}
      </span>
      <span className={mono ? "mono" : undefined} style={{ wordBreak: "break-all" }}>
        {value || "—"}
      </span>
    </div>
  );
}
