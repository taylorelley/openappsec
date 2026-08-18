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
import { useAuth } from "../auth-context";
import type { EventRow } from "../types";
import { formatTime, severityColor } from "./charts/chart-utils";

// The exception condition keys the agent understands. Hostname, URL and
// parameter name are pre-selected: narrow enough to be safe for the common
// "this parameter on this endpoint is fine" case.
const EXCEPTION_KEYS = [
  { key: "hostName", label: "Host name", default: true },
  { key: "url", label: "URL path", default: true },
  { key: "paramName", label: "Parameter name", default: true },
  { key: "paramValue", label: "Parameter value", default: false },
  { key: "sourceIp", label: "Source IP", default: false },
  { key: "countryCode", label: "Country code", default: false },
  { key: "protectionName", label: "Protection", default: false },
];

export function EventDetail({
  event,
  onClose,
}: {
  event: EventRow;
  onClose: () => void;
}) {
  const { canEdit } = useAuth();
  const navigate = useNavigate();
  const [keys, setKeys] = useState<string[]>(
    EXCEPTION_KEYS.filter((k) => k.default).map((k) => k.key),
  );
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState("");

  const raw = useQuery({
    queryKey: ["event", event.id],
    queryFn: () => api.getEvent(event.id),
  });

  async function createException() {
    setCreating(true);
    setError("");
    try {
      const result = await api.exceptionFromEvent(event.id, keys);
      // Hand the candidate to the policy editor for review. Nothing is
      // enforced here: widening a WAF policy is a deliberate act.
      sessionStorage.setItem(
        "policy-candidate",
        JSON.stringify({
          body: result.body,
          message: `Exception from event ${event.id}`,
        }),
      );
      navigate("/policy?candidate=1");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not build the exception");
    } finally {
      setCreating(false);
    }
  }

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="Event detail"
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
          width: "min(680px, 100%)",
          background: "var(--surface-1)",
          borderLeft: "1px solid var(--border)",
          overflowY: "auto",
          padding: 20,
        }}
      >
        <div
          className="row"
          style={{ justifyContent: "space-between", marginBottom: 14 }}
        >
          <div>
            <h2 style={{ margin: 0, fontSize: 17 }}>{event.eventName}</h2>
            <div className="muted" style={{ fontSize: 12.5 }}>
              {formatTime(event.eventTime)}
            </div>
          </div>
          <button className="btn btn-sm" onClick={onClose}>
            Close
          </button>
        </div>

        <div className="row" style={{ gap: 8, marginBottom: 16 }}>
          <span className="chip">
            <span
              className="dot"
              style={{ background: severityColor(event.eventSeverity) }}
            />
            {event.eventSeverity || "Unknown severity"}
          </span>
          <span className="chip">{event.securityAction || "No action"}</span>
          {event.waapIncidentType && (
            <span className="chip">{event.waapIncidentType}</span>
          )}
          {event.eventConfidence && (
            <span className="chip">Confidence: {event.eventConfidence}</span>
          )}
        </div>

        <Section title="Request">
          <Field label="Host" value={event.httpHostName} />
          <Field label="Method" value={event.httpMethod} />
          <Field label="Path" value={event.httpUriPath} mono />
          <Field label="Response code" value={event.httpResponseCode?.toString()} />
          <Field label="Source" value={event.sourceIp} mono />
          <Field label="Source country" value={event.sourceCountryName} />
        </Section>

        <Section title="Detection">
          <Field label="Asset" value={event.assetName} />
          <Field label="Practice" value={event.practiceType} />
          <Field label="Matched location" value={event.matchedLocation} />
          <Field label="Matched parameter" value={event.matchedParameter} mono />
          <Field label="Matched sample" value={event.matchedSample} mono />
          <Field label="Final score" value={event.waapFinalScore?.toString()} />
        </Section>

        {canEdit && (
          <Section title="This was a false positive">
            <p className="muted" style={{ fontSize: 12.5, margin: "0 0 8px" }}>
              Build an exception from this event. You will review the diff before
              anything is enforced.
            </p>
            <div className="row" style={{ gap: 12, marginBottom: 10 }}>
              {EXCEPTION_KEYS.map((k) => (
                <label
                  key={k.key}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 5,
                    marginBottom: 0,
                    fontWeight: 400,
                    fontSize: 12.5,
                    color: "var(--text-primary)",
                  }}
                >
                  <input
                    type="checkbox"
                    checked={keys.includes(k.key)}
                    onChange={(e) =>
                      setKeys((prev) =>
                        e.target.checked
                          ? [...prev, k.key]
                          : prev.filter((x) => x !== k.key),
                      )
                    }
                    style={{ width: "auto" }}
                  />
                  {k.label}
                </label>
              ))}
            </div>
            {error && (
              <div className="banner banner-error" style={{ marginBottom: 10 }}>
                {error}
              </div>
            )}
            <button
              className="btn"
              onClick={() => void createException()}
              disabled={creating || keys.length === 0}
            >
              {creating ? "Building…" : "Create exception for review"}
            </button>
          </Section>
        )}

        <Section title="Raw event">
          <pre
            className="mono"
            style={{
              background: "var(--surface-sunken)",
              padding: 12,
              borderRadius: "var(--radius-sm)",
              overflowX: "auto",
              margin: 0,
              fontSize: 11.5,
              maxHeight: 420,
            }}
          >
            {raw.isPending
              ? "Loading…"
              : JSON.stringify(raw.data ?? {}, null, 2)}
          </pre>
        </Section>
      </div>
    </div>
  );
}

function Section({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div style={{ marginBottom: 20 }}>
      <h3 className="card-title" style={{ marginBottom: 8 }}>
        {title}
      </h3>
      {children}
    </div>
  );
}

function Field({
  label,
  value,
  mono,
}: {
  label: string;
  value?: string;
  mono?: boolean;
}) {
  if (!value) return null;
  return (
    <div
      className="row"
      style={{ gap: 10, alignItems: "flex-start", padding: "3px 0" }}
    >
      <span
        className="muted"
        style={{ width: 140, flex: "none", fontSize: 12.5 }}
      >
        {label}
      </span>
      <span
        className={mono ? "mono" : undefined}
        style={{ wordBreak: "break-all", fontSize: 12.5 }}
      >
        {value}
      </span>
    </div>
  );
}
