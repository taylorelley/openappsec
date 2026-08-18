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
import { Link } from "react-router-dom";

import { api } from "../api";
import { useAuth } from "../auth-context";
import { ErrorBanner, Loading, PageHeader } from "../components/Layout";
import { formatNumber, formatTime } from "../components/charts/chart-utils";
import type {
  AssetLearning,
  Readiness,
  Suggestion,
  TuningDecisionValue,
} from "../types";

// Readiness is a state, so it uses the reserved status palette — and always
// travels with its label, never as a bare colour.
const READINESS: Record<Readiness, { label: string; color: string }> = {
  "insufficient-data": { label: "Insufficient data", color: "var(--text-muted)" },
  learning: { label: "Learning", color: "var(--status-warning)" },
  "nearly-ready": { label: "Nearly ready", color: "var(--status-serious)" },
  "ready-for-prevent": { label: "Ready for prevent", color: "var(--status-good)" },
};

export function Learning() {
  const [selected, setSelected] = useState<AssetLearning | null>(null);

  const assets = useQuery({
    queryKey: ["learning-assets"],
    queryFn: api.learningAssets,
    refetchInterval: 60_000,
  });

  return (
    <>
      <PageHeader
        title="Learning"
        description="Per-asset learning progress and tuning decisions"
      />

      <ErrorBanner error={assets.error} />

      {assets.isPending ? (
        <Loading />
      ) : (assets.data ?? []).length === 0 ? (
        <div className="card">
          <h2 className="card-title">Nothing learned yet</h2>
          <p style={{ fontSize: 13, marginTop: 0 }}>
            Assets appear here once agents start reporting events for them.
          </p>
        </div>
      ) : (
        <div className="stack">
          {(assets.data ?? []).map((asset) => (
            <AssetCard
              key={`${asset.tenantId}/${asset.assetId}`}
              asset={asset}
              onOpen={() => setSelected(asset)}
            />
          ))}
        </div>
      )}

      {selected && (
        <TuningPanel asset={selected} onClose={() => setSelected(null)} />
      )}
    </>
  );
}

function AssetCard({
  asset,
  onOpen,
}: {
  asset: AssetLearning;
  onOpen: () => void;
}) {
  const readiness = READINESS[asset.readiness];

  return (
    <div className="card">
      <div
        className="row"
        style={{ justifyContent: "space-between", marginBottom: 10 }}
      >
        <div>
          <h2 style={{ margin: 0, fontSize: 15 }}>
            {asset.assetName || asset.assetId}
          </h2>
          <div className="mono muted" style={{ fontSize: 11 }}>
            {asset.assetId}
          </div>
        </div>
        <div className="row" style={{ gap: 8 }}>
          <span className="chip">
            <span className="dot" style={{ background: readiness.color }} />
            {readiness.label}
          </span>
          <button className="btn btn-sm" onClick={onOpen}>
            Review tuning
          </button>
        </div>
      </div>

      <div
        className="grid"
        style={{
          gridTemplateColumns: "repeat(auto-fit, minmax(130px, 1fr))",
          gap: 10,
          marginBottom: 10,
        }}
      >
        <Metric label="Events seen" value={formatNumber(asset.totalEvents)} />
        <Metric label="Unique sources" value={formatNumber(asset.uniqueSources)} />
        <Metric label="Distinct paths" value={formatNumber(asset.uniqueUris)} />
        <Metric
          label="Observed over"
          value={`${Math.round(asset.learningHours)}h`}
        />
        <Metric
          label="Learning windows"
          value={formatNumber(asset.completedLearningWindows)}
        />
        <Metric label="Decisions made" value={formatNumber(asset.decisions)} />
      </div>

      <p style={{ fontSize: 12.5, margin: "0 0 8px" }}>{asset.recommendation}</p>

      {(asset.criticalLast48h > 0 || asset.highLast48h > 0) && (
        <div className="row" style={{ gap: 8, fontSize: 12.5 }}>
          <span className="muted">Last 48 hours:</span>
          {asset.criticalLast48h > 0 && (
            <Link
              to={`/events?q=${encodeURIComponent(
                `assetname:"${asset.assetName}" AND eventseverity:Critical`,
              )}`}
            >
              {asset.criticalLast48h} critical
            </Link>
          )}
          {asset.highLast48h > 0 && (
            <Link
              to={`/events?q=${encodeURIComponent(
                `assetname:"${asset.assetName}" AND eventseverity:High`,
              )}`}
            >
              {asset.highLast48h} high
            </Link>
          )}
        </div>
      )}
    </div>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="muted" style={{ fontSize: 11.5 }}>
        {label}
      </div>
      <div className="num" style={{ fontSize: 17, fontWeight: 650 }}>
        {value}
      </div>
    </div>
  );
}

function TuningPanel({
  asset,
  onClose,
}: {
  asset: AssetLearning;
  onClose: () => void;
}) {
  const { canEdit } = useAuth();
  const queryClient = useQueryClient();

  const suggestions = useQuery({
    queryKey: ["suggestions", asset.assetId],
    queryFn: () => api.suggestions(asset.assetId, asset.tenantId),
  });
  const decisions = useQuery({
    queryKey: ["decisions", asset.assetId],
    queryFn: () => api.decisions(asset.assetId, asset.tenantId),
  });

  const decide = useMutation({
    mutationFn: (input: {
      suggestion: Suggestion;
      decision: TuningDecisionValue;
    }) =>
      api.setDecision({
        tenantId: input.suggestion.tenantId,
        assetId: input.suggestion.assetId,
        eventType: input.suggestion.eventType,
        eventTitle: input.suggestion.eventTitle,
        decision: input.decision,
      }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["suggestions"] });
      await queryClient.invalidateQueries({ queryKey: ["decisions"] });
      await queryClient.invalidateQueries({ queryKey: ["learning-assets"] });
    },
  });

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label={`Tuning for ${asset.assetName}`}
      onClick={onClose}
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0,0,0,0.4)",
        zIndex: 40,
        display: "flex",
        justifyContent: "flex-end",
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          width: "min(760px, 100%)",
          background: "var(--surface-1)",
          borderLeft: "1px solid var(--border)",
          overflowY: "auto",
          padding: 20,
        }}
      >
        <div className="row" style={{ justifyContent: "space-between", marginBottom: 8 }}>
          <h2 style={{ margin: 0, fontSize: 17 }}>
            Tuning · {asset.assetName || asset.assetId}
          </h2>
          <button className="btn btn-sm" onClick={onClose}>
            Close
          </button>
        </div>

        <p className="muted" style={{ fontSize: 12.5, marginTop: 0 }}>
          Decisions are published as <code className="mono">decisions.data</code> and
          picked up by the agent on its next poll, roughly every 30 minutes.
        </p>

        <ErrorBanner error={decide.error} />

        <h3 className="card-title" style={{ marginTop: 16 }}>
          Suggestions
        </h3>
        {suggestions.isPending ? (
          <Loading />
        ) : (suggestions.data ?? []).length === 0 ? (
          <p className="muted" style={{ fontSize: 12.5 }}>
            Nothing left to classify for this asset.
          </p>
        ) : (
          <div className="scroll-x">
            <table>
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Value</th>
                  <th>Events</th>
                  <th>Sources</th>
                  <th>Top attack</th>
                  {canEdit && <th>Decide</th>}
                </tr>
              </thead>
              <tbody>
                {(suggestions.data ?? []).map((suggestion) => (
                  <tr key={`${suggestion.eventType}:${suggestion.eventTitle}`}>
                    <td>
                      <span className="chip">{suggestion.eventType}</span>
                    </td>
                    <td
                      className="mono"
                      style={{
                        maxWidth: 240,
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}
                      title={suggestion.eventTitle}
                    >
                      {suggestion.eventTitle}
                    </td>
                    <td className="num">{formatNumber(suggestion.events)}</td>
                    <td className="num">{formatNumber(suggestion.sources)}</td>
                    <td>{suggestion.topAttackType || "—"}</td>
                    {canEdit && (
                      <td style={{ whiteSpace: "nowrap" }}>
                        {(
                          [
                            ["benign", "Benign"],
                            ["malicious", "Malicious"],
                            ["dismiss", "Dismiss"],
                          ] as const
                        ).map(([value, label]) => (
                          <button
                            key={value}
                            className="btn btn-sm"
                            style={{ marginRight: 4 }}
                            disabled={decide.isPending}
                            onClick={() =>
                              decide.mutate({ suggestion, decision: value })
                            }
                          >
                            {label}
                          </button>
                        ))}
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <h3 className="card-title" style={{ marginTop: 20 }}>
          Decisions already made
        </h3>
        {(decisions.data ?? []).length === 0 ? (
          <p className="muted" style={{ fontSize: 12.5 }}>
            None yet.
          </p>
        ) : (
          <div className="scroll-x">
            <table>
              <thead>
                <tr>
                  <th>Decision</th>
                  <th>Type</th>
                  <th>Value</th>
                  <th>By</th>
                  <th>When</th>
                  {canEdit && <th />}
                </tr>
              </thead>
              <tbody>
                {(decisions.data ?? []).map((decision) => (
                  <tr key={decision.id}>
                    <td>
                      <span className="chip">{decision.decision}</span>
                    </td>
                    <td>{decision.eventType}</td>
                    <td className="mono">{decision.eventTitle}</td>
                    <td>{decision.decidedBy || "—"}</td>
                    <td className="num">{formatTime(decision.decidedAt)}</td>
                    {canEdit && (
                      <td style={{ textAlign: "right" }}>
                        <button
                          className="btn btn-sm"
                          onClick={async () => {
                            await api.deleteDecision(decision.id);
                            await queryClient.invalidateQueries({
                              queryKey: ["decisions"],
                            });
                            await queryClient.invalidateQueries({
                              queryKey: ["suggestions"],
                            });
                          }}
                        >
                          Undo
                        </button>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
