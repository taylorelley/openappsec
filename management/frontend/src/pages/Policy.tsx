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

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";

import { api } from "../api";
import { useAuth } from "../auth-context";
import { ErrorBanner, Loading, PageHeader } from "../components/Layout";
import { DiffView } from "../components/DiffView";
import { PolicyForm } from "../components/PolicyForm";
import { formatTime } from "../components/charts/chart-utils";
import type { PolicyDocument, Revision, ValidationResult } from "../types";

type Tab = "form" | "json" | "rendered" | "revisions";

export function Policy() {
  const { canEdit } = useAuth();
  const queryClient = useQueryClient();
  const [searchParams, setSearchParams] = useSearchParams();

  const [tab, setTab] = useState<Tab>("form");
  const [draft, setDraft] = useState<PolicyDocument | null>(null);
  const [jsonText, setJsonText] = useState("");
  const [jsonError, setJsonError] = useState("");
  const [message, setMessage] = useState("");
  const [validation, setValidation] = useState<ValidationResult | null>(null);
  const [diff, setDiff] = useState("");
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState<unknown>(null);

  const deployed = useQuery({
    queryKey: ["policy", "deployed"],
    queryFn: () => api.deployedPolicy(),
  });
  const revisions = useQuery({
    queryKey: ["policy", "revisions"],
    queryFn: () => api.revisions(50),
  });
  const rendered = useQuery({
    queryKey: ["policy", "rendered"],
    queryFn: () => api.renderedPolicy(),
  });

  // Seed the editor from the deployed revision, or from a candidate handed
  // over by the "create exception" flow.
  const seeded = useRef(false);
  useEffect(() => {
    if (seeded.current || !deployed.data) return;
    seeded.current = true;

    if (searchParams.get("candidate") === "1") {
      const stored = sessionStorage.getItem("policy-candidate");
      if (stored) {
        try {
          const parsed = JSON.parse(stored) as {
            body: PolicyDocument;
            message?: string;
          };
          setDraft(parsed.body);
          setMessage(parsed.message ?? "");
          setNotice(
            "Loaded a candidate policy. Review the diff below, then Save and enforce.",
          );
          sessionStorage.removeItem("policy-candidate");
          setSearchParams({});
          return;
        } catch {
          /* fall through to the deployed policy */
        }
      }
    }
    setDraft(deployed.data.body);
  }, [deployed.data, searchParams, setSearchParams]);

  useEffect(() => {
    if (draft) setJsonText(JSON.stringify(draft, null, 2));
  }, [draft]);

  // Validate and diff on every change. A policy that fails to load leaves
  // almost no trace on the agent, so problems must surface here, not there.
  const revalidate = useCallback(async (doc: PolicyDocument) => {
    try {
      const [v, d] = await Promise.all([
        api.validatePolicy(doc),
        api.diffCandidate(doc),
      ]);
      setValidation(v);
      setDiff(d.diff);
    } catch (err) {
      setError(err);
    }
  }, []);

  useEffect(() => {
    if (!draft) return;
    const timer = setTimeout(() => void revalidate(draft), 350);
    return () => clearTimeout(timer);
  }, [draft, revalidate]);

  const dirty = useMemo(() => {
    if (!draft || !deployed.data) return false;
    return JSON.stringify(draft) !== JSON.stringify(deployed.data.body);
  }, [draft, deployed.data]);

  const blocked = (validation?.errors?.length ?? 0) > 0;

  async function saveAndEnforce() {
    if (!draft) return;
    setBusy(true);
    setError(null);
    setNotice("");
    try {
      const revision = await api.createRevision(
        draft,
        message || "Updated from the manager UI",
      );
      await api.enforce(revision.id);
      setNotice(`Revision ${revision.id} saved and enforced.`);
      setMessage("");
      await queryClient.invalidateQueries({ queryKey: ["policy"] });
      seeded.current = false;
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  async function rollback(revision: Revision) {
    setBusy(true);
    setError(null);
    setNotice("");
    try {
      await api.enforce(revision.id);
      setNotice(`Rolled back to revision ${revision.id}.`);
      await queryClient.invalidateQueries({ queryKey: ["policy"] });
      seeded.current = false;
      setDraft(null);
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  function applyJson() {
    try {
      setDraft(JSON.parse(jsonText) as PolicyDocument);
      setJsonError("");
    } catch (err) {
      setJsonError(err instanceof Error ? err.message : "Invalid JSON");
    }
  }

  if (deployed.isPending) return <Loading />;

  return (
    <>
      <PageHeader
        title="Policy"
        description={
          deployed.data
            ? `Deployed revision ${deployed.data.id} · ${formatTime(deployed.data.createdAt)}`
            : undefined
        }
        actions={
          canEdit && (
            <>
              <input
                value={message}
                onChange={(e) => setMessage(e.target.value)}
                placeholder="Describe this change"
                style={{ width: 240 }}
                aria-label="Change description"
              />
              <button
                className="btn btn-primary"
                onClick={() => void saveAndEnforce()}
                disabled={busy || !dirty || blocked}
                title={
                  blocked
                    ? "Fix the validation errors first"
                    : !dirty
                      ? "No changes to enforce"
                      : undefined
                }
              >
                {busy ? "Enforcing…" : "Save and enforce"}
              </button>
            </>
          )
        }
      />

      <ErrorBanner error={error ?? deployed.error} />
      {notice && (
        <div className="banner banner-ok" style={{ marginBottom: 14 }}>
          {notice}
        </div>
      )}

      <div className="row" style={{ gap: 2, marginBottom: 14 }}>
        {(
          [
            ["form", "Editor"],
            ["json", "Raw document"],
            ["rendered", "Rendered YAML"],
            ["revisions", "Revisions"],
          ] as const
        ).map(([id, label]) => (
          <button
            key={id}
            className="btn btn-sm"
            onClick={() => setTab(id)}
            aria-pressed={tab === id}
            style={{
              background: tab === id ? "var(--surface-sunken)" : "var(--surface-raised)",
              fontWeight: tab === id ? 600 : 500,
            }}
          >
            {label}
          </button>
        ))}
      </div>

      {validation && <ValidationPanel result={validation} />}

      <div
        className="grid"
        style={{ gridTemplateColumns: tab === "revisions" ? "1fr" : "1.15fr 1fr" }}
      >
        {tab === "form" && draft && (
          <div className="card">
            <h2 className="card-title">Policy</h2>
            <PolicyForm
              document={draft}
              readOnly={!canEdit}
              onChange={setDraft}
            />
          </div>
        )}

        {tab === "json" && (
          <div className="card">
            <h2 className="card-title">Raw document</h2>
            <textarea
              value={jsonText}
              onChange={(e) => setJsonText(e.target.value)}
              onBlur={applyJson}
              readOnly={!canEdit}
              rows={30}
              spellCheck={false}
              aria-label="Policy document as JSON"
            />
            {jsonError && (
              <div className="banner banner-error" style={{ marginTop: 8 }}>
                {jsonError}
              </div>
            )}
            {canEdit && (
              <button className="btn btn-sm" onClick={applyJson} style={{ marginTop: 8 }}>
                Apply changes
              </button>
            )}
          </div>
        )}

        {tab === "rendered" && (
          <div className="card">
            <h2 className="card-title">
              local_policy.yaml — exactly what the agent receives
            </h2>
            <pre
              className="mono"
              style={{
                background: "var(--surface-sunken)",
                padding: 12,
                borderRadius: "var(--radius-sm)",
                overflowX: "auto",
                margin: 0,
                fontSize: 11.5,
                maxHeight: 620,
              }}
            >
              {rendered.isPending ? "Loading…" : rendered.data}
            </pre>
          </div>
        )}

        {tab === "revisions" && (
          <div className="card" style={{ padding: 0 }}>
            <div className="scroll-x">
              <table>
                <thead>
                  <tr>
                    <th>Revision</th>
                    <th>Created</th>
                    <th>Author</th>
                    <th>Description</th>
                    <th>Checksum</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {(revisions.data ?? []).map((revision) => {
                    const isDeployed = revision.id === deployed.data?.id;
                    return (
                      <tr key={revision.id}>
                        <td className="num">
                          {revision.id}
                          {isDeployed && (
                            <span className="chip" style={{ marginLeft: 8 }}>
                              deployed
                            </span>
                          )}
                        </td>
                        <td className="num">{formatTime(revision.createdAt)}</td>
                        <td>{revision.authorName || "—"}</td>
                        <td>{revision.message || "—"}</td>
                        <td className="mono">{revision.checksum.slice(0, 12)}</td>
                        <td style={{ textAlign: "right" }}>
                          {canEdit && !isDeployed && (
                            <button
                              className="btn btn-sm"
                              disabled={busy}
                              onClick={() => void rollback(revision)}
                            >
                              Roll back to this
                            </button>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {tab !== "revisions" && (
          <div className="card">
            <h2 className="card-title">
              {dirty ? "Pending changes" : "No pending changes"}
            </h2>
            <DiffView diff={diff} />
          </div>
        )}
      </div>
    </>
  );
}

function ValidationPanel({ result }: { result: ValidationResult }) {
  // Defensive: an older server, or a proxy that rewrites the body, could send
  // null instead of an empty array. A validation panel must never be the
  // reason the policy editor fails to render.
  const errors = result.errors ?? [];
  const warnings = result.warnings ?? [];
  if (errors.length === 0 && warnings.length === 0) return null;

  return (
    <div className="stack" style={{ gap: 8, marginBottom: 14 }}>
      {errors.length > 0 && (
        <div className="banner banner-error">
          <strong>
            {errors.length} error
            {errors.length === 1 ? "" : "s"} — this policy cannot be enforced
          </strong>
          <ul style={{ margin: "6px 0 0", paddingLeft: 18 }}>
            {errors.map((problem, i) => (
              <li key={i}>
                <code className="mono">{problem.path}</code> {problem.message}
              </li>
            ))}
          </ul>
        </div>
      )}
      {warnings.length > 0 && (
        <div className="banner banner-warn">
          <strong>
            {warnings.length} warning
            {warnings.length === 1 ? "" : "s"}
          </strong>
          <ul style={{ margin: "6px 0 0", paddingLeft: 18 }}>
            {warnings.map((problem, i) => (
              <li key={i}>
                <code className="mono">{problem.path}</code> {problem.message}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
