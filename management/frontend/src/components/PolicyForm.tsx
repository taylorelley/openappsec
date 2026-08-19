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

import { useState, type ReactNode } from "react";
import type { PolicyDocument } from "../types";

// Enumerations from the v1beta2 schema. Kept explicit so the control renders
// exactly the values the agent's parsers accept.
const MODES = ["prevent-learn", "detect-learn", "prevent", "detect", "inactive"];
const OVERRIDE_MODES = [...MODES, "inherited"];
const PRACTICE_MODES = ["inherited", ...MODES];
const CONFIDENCE = ["medium", "high", "critical"];
const SEVERITY = ["low", "medium", "high", "critical"];
const EXCEPTION_ACTIONS = ["skip", "accept", "drop", "suppressLog"];
const RESPONSE_MODES = ["block-page", "redirect", "response-code-only"];
const RATE_UNITS = ["minute", "second"];

// The condition keys the agent's exception loader recognises
// (components/security_apps/local_policy_mgmt_gen/new_exceptions.cc).
const CONDITION_KEYS = [
  "countryCode",
  "countryName",
  "hostName",
  "paramName",
  "paramValue",
  "protectionName",
  "sourceIdentifier",
  "sourceIp",
  "url",
];

interface Props {
  document: PolicyDocument;
  readOnly: boolean;
  onChange: (next: PolicyDocument) => void;
}

/**
 * A structured editor over the canonical policy.
 *
 * Every edit goes through a deep clone and writes back the whole document, so
 * fields this form does not render are preserved rather than dropped.
 */
export function PolicyForm({ document, readOnly, onChange }: Props) {
  const update = (mutate: (draft: PolicyDocument) => void) => {
    const next = structuredClone(document);
    mutate(next);
    onChange(next);
  };

  const policies = (document["policies"] ?? {}) as Record<string, unknown>;
  const defaultRule = (policies["default"] ?? {}) as Record<string, unknown>;
  const specificRules = (policies["specificRules"] ?? []) as Record<string, unknown>[];

  const threatPractices = (document["threatPreventionPractices"] ??
    []) as Record<string, unknown>[];
  const accessPractices = (document["accessControlPractices"] ??
    []) as Record<string, unknown>[];
  const triggers = (document["logTriggers"] ?? []) as Record<string, unknown>[];
  const responses = (document["customResponses"] ?? []) as Record<string, unknown>[];
  const exceptions = (document["exceptions"] ?? []) as Record<string, unknown>[];

  const names = (items: Record<string, unknown>[]) =>
    items.map((i) => String(i["name"] ?? "")).filter(Boolean);

  return (
    <div className="stack" style={{ gap: 14 }}>
      <Group title="Default rule" defaultOpen>
        <Select
          label="Mode"
          value={String(defaultRule["mode"] ?? "detect-learn")}
          options={MODES}
          disabled={readOnly}
          hint="How the default rule behaves for traffic that no specific rule matches."
          onChange={(v) =>
            update((d) => {
              rule(d)["mode"] = v;
            })
          }
        />
        <MultiSelect
          label="Threat prevention practices"
          value={(defaultRule["threatPreventionPractices"] ?? []) as string[]}
          options={names(threatPractices)}
          disabled={readOnly}
          onChange={(v) =>
            update((d) => {
              rule(d)["threatPreventionPractices"] = v;
            })
          }
        />
        <MultiSelect
          label="Access control practices"
          value={(defaultRule["accessControlPractices"] ?? []) as string[]}
          options={names(accessPractices)}
          disabled={readOnly}
          onChange={(v) =>
            update((d) => {
              rule(d)["accessControlPractices"] = v;
            })
          }
        />
        <MultiSelect
          label="Log triggers"
          value={(defaultRule["triggers"] ?? []) as string[]}
          options={names(triggers)}
          disabled={readOnly}
          onChange={(v) =>
            update((d) => {
              rule(d)["triggers"] = v;
            })
          }
        />
        <MultiSelect
          label="Exceptions"
          value={(defaultRule["exceptions"] ?? []) as string[]}
          options={names(exceptions)}
          disabled={readOnly}
          onChange={(v) =>
            update((d) => {
              rule(d)["exceptions"] = v;
            })
          }
        />
        <Select
          label="Custom response"
          // Show the effective value: a document carrying the plural spelling
          // is folded into the singular on apply, so the form must reflect
          // what will actually be enforced rather than reading as unset.
          value={String(
            defaultRule["customResponse"] ?? defaultRule["customResponses"] ?? "",
          )}
          options={["", ...names(responses)]}
          disabled={readOnly}
          hint="Written as `customResponse` (singular); the agent ignores the plural spelling."
          onChange={(v) =>
            update((d) => {
              const target = rule(d);
              delete target["customResponses"];
              target["customResponse"] = v;
            })
          }
        />
      </Group>

      <Group title={`Specific rules (${specificRules.length})`}>
        {specificRules.map((r, i) => (
          <Card key={i} onRemove={readOnly ? undefined : () => removeAt(update, "specificRules", i)}>
            <Text
              label="Host"
              value={String(r["host"] ?? "")}
              disabled={readOnly}
              onChange={(v) =>
                update((d) => {
                  specific(d)[i]!["host"] = v;
                })
              }
            />
            <Select
              label="Mode"
              value={String(r["mode"] ?? "detect-learn")}
              options={MODES}
              disabled={readOnly}
              onChange={(v) =>
                update((d) => {
                  specific(d)[i]!["mode"] = v;
                })
              }
            />
            <MultiSelect
              label="Threat prevention practices"
              value={(r["threatPreventionPractices"] ?? []) as string[]}
              options={names(threatPractices)}
              disabled={readOnly}
              onChange={(v) =>
                update((d) => {
                  specific(d)[i]!["threatPreventionPractices"] = v;
                })
              }
            />
            <MultiSelect
              label="Log triggers"
              value={(r["triggers"] ?? []) as string[]}
              options={names(triggers)}
              disabled={readOnly}
              onChange={(v) =>
                update((d) => {
                  specific(d)[i]!["triggers"] = v;
                })
              }
            />
          </Card>
        ))}
        {!readOnly && (
          <AddButton
            label="Add specific rule"
            onClick={() =>
              update((d) => {
                specific(d).push({
                  host: "example.com",
                  mode: "detect-learn",
                  threatPreventionPractices: names(threatPractices).slice(0, 1),
                  accessControlPractices: [],
                  triggers: names(triggers).slice(0, 1),
                });
              })
            }
          />
        )}
      </Group>

      <Group title={`Threat prevention practices (${threatPractices.length})`}>
        {threatPractices.map((practice, i) => {
          const web = (practice["webAttacks"] ?? {}) as Record<string, unknown>;
          const protections = (web["protections"] ?? {}) as Record<string, unknown>;
          const ips = (practice["intrusionPrevention"] ?? {}) as Record<string, unknown>;
          const files = (practice["fileSecurity"] ?? {}) as Record<string, unknown>;
          const at = (d: PolicyDocument) =>
            (d["threatPreventionPractices"] as Record<string, unknown>[])[i]!;

          return (
            <Card key={i}>
              <Text
                label="Name"
                value={String(practice["name"] ?? "")}
                disabled={readOnly}
                onChange={(v) => update((d) => void (at(d)["name"] = v))}
              />
              <Select
                label="Practice mode"
                value={String(practice["practiceMode"] ?? "inherited")}
                options={PRACTICE_MODES}
                disabled={readOnly}
                onChange={(v) => update((d) => void (at(d)["practiceMode"] = v))}
              />

              <SubGroup title="Web attacks">
                <Select
                  label="Override mode"
                  value={String(web["overrideMode"] ?? "inherited")}
                  options={OVERRIDE_MODES}
                  disabled={readOnly}
                  onChange={(v) =>
                    update((d) => void (nested(at(d), "webAttacks")["overrideMode"] = v))
                  }
                />
                <Select
                  label="Minimum confidence"
                  value={String(web["minimumConfidence"] ?? "high")}
                  options={CONFIDENCE}
                  disabled={readOnly}
                  hint="How certain the engine must be before it acts."
                  onChange={(v) =>
                    update(
                      (d) => void (nested(at(d), "webAttacks")["minimumConfidence"] = v),
                    )
                  }
                />
                <Num
                  label="Max URL size (bytes)"
                  value={web["maxUrlSizeBytes"] as number | undefined}
                  placeholder="32768"
                  disabled={readOnly}
                  onChange={(v) =>
                    update((d) => void (nested(at(d), "webAttacks")["maxUrlSizeBytes"] = v))
                  }
                />
                <Num
                  label="Max body size (KB)"
                  value={web["maxBodySizeKb"] as number | undefined}
                  placeholder="1000000"
                  disabled={readOnly}
                  onChange={(v) =>
                    update((d) => void (nested(at(d), "webAttacks")["maxBodySizeKb"] = v))
                  }
                />
                {["csrfProtection", "errorDisclosure", "openRedirect"].map((key) => (
                  <Select
                    key={key}
                    label={humanize(key)}
                    value={String(protections[key] ?? "inherited")}
                    options={OVERRIDE_MODES}
                    disabled={readOnly}
                    onChange={(v) =>
                      update(
                        (d) =>
                          void (nested(
                            nested(at(d), "webAttacks"),
                            "protections",
                          )[key] = v),
                      )
                    }
                  />
                ))}
              </SubGroup>

              <SubGroup title="Intrusion prevention">
                <Select
                  label="Override mode"
                  value={String(ips["overrideMode"] ?? "inherited")}
                  options={OVERRIDE_MODES}
                  disabled={readOnly}
                  onChange={(v) =>
                    update(
                      (d) =>
                        void (nested(at(d), "intrusionPrevention")["overrideMode"] = v),
                    )
                  }
                />
                <Select
                  label="Minimum severity"
                  value={String(ips["minSeverityLevel"] ?? "medium")}
                  options={SEVERITY}
                  disabled={readOnly}
                  onChange={(v) =>
                    update(
                      (d) =>
                        void (nested(at(d), "intrusionPrevention")["minSeverityLevel"] =
                          v),
                    )
                  }
                />
                <Num
                  label="Minimum CVE year"
                  value={ips["minCveYear"] as number | undefined}
                  placeholder="2016"
                  disabled={readOnly}
                  onChange={(v) =>
                    update(
                      (d) =>
                        void (nested(at(d), "intrusionPrevention")["minCveYear"] = v),
                    )
                  }
                />
              </SubGroup>

              <SubGroup title="File security">
                <Select
                  label="Override mode"
                  value={String(files["overrideMode"] ?? "inherited")}
                  options={OVERRIDE_MODES}
                  disabled={readOnly}
                  onChange={(v) =>
                    update(
                      (d) => void (nested(at(d), "fileSecurity")["overrideMode"] = v),
                    )
                  }
                />
                <Select
                  label="Minimum severity"
                  value={String(files["minSeverityLevel"] ?? "medium")}
                  options={SEVERITY}
                  disabled={readOnly}
                  onChange={(v) =>
                    update(
                      (d) =>
                        void (nested(at(d), "fileSecurity")["minSeverityLevel"] = v),
                    )
                  }
                />
              </SubGroup>
            </Card>
          );
        })}
      </Group>

      <Group title={`Access control practices (${accessPractices.length})`}>
        {accessPractices.map((practice, i) => {
          const rateLimit = (practice["rateLimit"] ?? {}) as Record<string, unknown>;
          const rules = (rateLimit["rules"] ?? []) as Record<string, unknown>[];
          const at = (d: PolicyDocument) =>
            (d["accessControlPractices"] as Record<string, unknown>[])[i]!;

          return (
            <Card key={i}>
              <Text
                label="Name"
                value={String(practice["name"] ?? "")}
                disabled={readOnly}
                onChange={(v) => update((d) => void (at(d)["name"] = v))}
              />
              <Select
                label="Rate limit override mode"
                value={String(rateLimit["overrideMode"] ?? "inherited")}
                options={["prevent", "detect", "inactive", "inherited"]}
                disabled={readOnly}
                onChange={(v) =>
                  update((d) => void (nested(at(d), "rateLimit")["overrideMode"] = v))
                }
              />

              {rules.map((r, j) => (
                <Card
                  key={j}
                  onRemove={
                    readOnly
                      ? undefined
                      : () =>
                          update((d) => {
                            (
                              nested(at(d), "rateLimit")["rules"] as unknown[]
                            ).splice(j, 1);
                          })
                  }
                >
                  <Text
                    label="URI"
                    value={String(r["uri"] ?? "")}
                    disabled={readOnly}
                    onChange={(v) =>
                      update(
                        (d) =>
                          void ((
                            nested(at(d), "rateLimit")["rules"] as Record<
                              string,
                              unknown
                            >[]
                          )[j]!["uri"] = v),
                      )
                    }
                  />
                  <Num
                    label="Limit"
                    value={r["limit"] as number | undefined}
                    disabled={readOnly}
                    onChange={(v) =>
                      update(
                        (d) =>
                          void ((
                            nested(at(d), "rateLimit")["rules"] as Record<
                              string,
                              unknown
                            >[]
                          )[j]!["limit"] = v),
                      )
                    }
                  />
                  <Select
                    label="Per"
                    value={String(r["unit"] ?? "minute")}
                    options={RATE_UNITS}
                    disabled={readOnly}
                    onChange={(v) =>
                      update(
                        (d) =>
                          void ((
                            nested(at(d), "rateLimit")["rules"] as Record<
                              string,
                              unknown
                            >[]
                          )[j]!["unit"] = v),
                      )
                    }
                  />
                </Card>
              ))}
              {!readOnly && (
                <AddButton
                  label="Add rate limit rule"
                  onClick={() =>
                    update((d) => {
                      const target = nested(at(d), "rateLimit");
                      if (!Array.isArray(target["rules"])) target["rules"] = [];
                      (target["rules"] as unknown[]).push({
                        uri: "/",
                        limit: 100,
                        unit: "minute",
                      });
                    })
                  }
                />
              )}
            </Card>
          );
        })}
      </Group>

      <Group title={`Log triggers (${triggers.length})`}>
        {triggers.map((trigger, i) => {
          const destination = (trigger["logDestination"] ?? {}) as Record<string, unknown>;
          const appsec = (trigger["appsecLogging"] ?? {}) as Record<string, unknown>;
          const extended = (trigger["extendedLogging"] ?? {}) as Record<string, unknown>;
          const at = (d: PolicyDocument) =>
            (d["logTriggers"] as Record<string, unknown>[])[i]!;

          return (
            <Card key={i}>
              <Text
                label="Name"
                value={String(trigger["name"] ?? "")}
                disabled={readOnly}
                onChange={(v) => update((d) => void (at(d)["name"] = v))}
              />

              <SubGroup title="What to log">
                {["detectEvents", "preventEvents", "allWebRequests"].map((key) => (
                  <Toggle
                    key={key}
                    label={humanize(key)}
                    value={Boolean(appsec[key])}
                    disabled={readOnly}
                    onChange={(v) =>
                      update((d) => void (nested(at(d), "appsecLogging")[key] = v))
                    }
                  />
                ))}
                {["urlPath", "urlQuery", "httpHeaders", "requestBody"].map((key) => (
                  <Toggle
                    key={key}
                    label={`Include ${humanize(key).toLowerCase()}`}
                    value={Boolean(extended[key])}
                    disabled={readOnly}
                    onChange={(v) =>
                      update((d) => void (nested(at(d), "extendedLogging")[key] = v))
                    }
                  />
                ))}
              </SubGroup>

              <SubGroup title="Where to send it">
                <Toggle
                  label="Send to this manager"
                  value={Boolean(destination["local-tuning"])}
                  disabled={readOnly}
                  hint="Sets logDestination.local-tuning. This is what routes the agent's event stream to the manager; without it no events arrive."
                  onChange={(v) =>
                    update(
                      (d) => void (nested(at(d), "logDestination")["local-tuning"] = v),
                    )
                  }
                />
                <Toggle
                  label="Write to the agent's local log file"
                  value={Boolean(destination["logToAgent"])}
                  disabled={readOnly}
                  hint="Keeps /var/log/nano_agent/cp-nano-http-transaction-handler.log as a fallback."
                  onChange={(v) =>
                    update((d) => void (nested(at(d), "logDestination")["logToAgent"] = v))
                  }
                />
                <Toggle
                  label="Send to the open-appsec cloud"
                  value={Boolean(destination["cloud"])}
                  disabled={readOnly}
                  hint="Leave off for a fully self-hosted deployment."
                  onChange={(v) =>
                    update((d) => void (nested(at(d), "logDestination")["cloud"] = v))
                  }
                />
              </SubGroup>
            </Card>
          );
        })}
      </Group>

      <Group title={`Custom responses (${responses.length})`}>
        {responses.map((response, i) => {
          const at = (d: PolicyDocument) =>
            (d["customResponses"] as Record<string, unknown>[])[i]!;
          return (
            <Card key={i}>
              <Text
                label="Name"
                value={String(response["name"] ?? "")}
                disabled={readOnly}
                onChange={(v) => update((d) => void (at(d)["name"] = v))}
              />
              <Select
                label="Mode"
                value={String(response["mode"] ?? "response-code-only")}
                options={RESPONSE_MODES}
                disabled={readOnly}
                onChange={(v) => update((d) => void (at(d)["mode"] = v))}
              />
              <Num
                label="HTTP response code"
                value={response["httpResponseCode"] as number | undefined}
                placeholder="403"
                disabled={readOnly}
                onChange={(v) => update((d) => void (at(d)["httpResponseCode"] = v))}
              />
              {response["mode"] === "block-page" && (
                <>
                  <Text
                    label="Message title"
                    value={String(response["messageTitle"] ?? "")}
                    disabled={readOnly}
                    onChange={(v) => update((d) => void (at(d)["messageTitle"] = v))}
                  />
                  <Text
                    label="Message body"
                    value={String(response["messageBody"] ?? "")}
                    disabled={readOnly}
                    onChange={(v) => update((d) => void (at(d)["messageBody"] = v))}
                  />
                </>
              )}
              {response["mode"] === "redirect" && (
                <Text
                  label="Redirect URL"
                  value={String(response["redirectUrl"] ?? "")}
                  disabled={readOnly}
                  onChange={(v) => update((d) => void (at(d)["redirectUrl"] = v))}
                />
              )}
            </Card>
          );
        })}
      </Group>

      <Group title={`Exceptions (${exceptions.length})`}>
        {exceptions.map((exception, i) => {
          const conditions = (exception["condition"] ?? []) as Record<string, unknown>[];
          const at = (d: PolicyDocument) =>
            (d["exceptions"] as Record<string, unknown>[])[i]!;

          return (
            <Card
              key={i}
              onRemove={readOnly ? undefined : () => removeAt(update, "exceptions", i)}
            >
              <Text
                label="Name"
                value={String(exception["name"] ?? "")}
                disabled={readOnly}
                onChange={(v) => update((d) => void (at(d)["name"] = v))}
              />
              <Select
                label="Action"
                value={String(exception["action"] ?? "accept")}
                options={EXCEPTION_ACTIONS}
                disabled={readOnly}
                onChange={(v) => update((d) => void (at(d)["action"] = v))}
              />
              {conditions.map((condition, j) => (
                <div className="row" key={j} style={{ gap: 6, alignItems: "flex-end" }}>
                  <div style={{ flex: "0 0 170px" }}>
                    <Select
                      label="Key"
                      value={String(condition["key"] ?? "")}
                      options={CONDITION_KEYS}
                      disabled={readOnly}
                      onChange={(v) =>
                        update(
                          (d) =>
                            void ((at(d)["condition"] as Record<string, unknown>[])[j]![
                              "key"
                            ] = v),
                        )
                      }
                    />
                  </div>
                  <div style={{ flex: 1 }}>
                    <Text
                      label="Value"
                      value={String(condition["value"] ?? "")}
                      disabled={readOnly}
                      onChange={(v) =>
                        update(
                          (d) =>
                            void ((at(d)["condition"] as Record<string, unknown>[])[j]![
                              "value"
                            ] = v),
                        )
                      }
                    />
                  </div>
                  {!readOnly && (
                    <button
                      className="btn btn-sm"
                      onClick={() =>
                        update((d) => {
                          (at(d)["condition"] as unknown[]).splice(j, 1);
                        })
                      }
                      aria-label="Remove condition"
                    >
                      ✕
                    </button>
                  )}
                </div>
              ))}
              {!readOnly && (
                <AddButton
                  label="Add condition"
                  onClick={() =>
                    update((d) => {
                      const target = at(d);
                      if (!Array.isArray(target["condition"])) target["condition"] = [];
                      (target["condition"] as unknown[]).push({
                        key: "hostName",
                        value: "",
                      });
                    })
                  }
                />
              )}
            </Card>
          );
        })}
        {!readOnly && (
          <AddButton
            label="Add exception"
            onClick={() =>
              update((d) => {
                if (!Array.isArray(d["exceptions"])) d["exceptions"] = [];
                (d["exceptions"] as unknown[]).push({
                  name: `exception-${exceptions.length + 1}`,
                  action: "accept",
                  condition: [{ key: "hostName", value: "" }],
                });
              })
            }
          />
        )}
      </Group>
    </div>
  );
}

// ------------------------------------------------------------------ helpers

function rule(d: PolicyDocument): Record<string, unknown> {
  const policies = nested(d, "policies");
  return nested(policies, "default");
}

function specific(d: PolicyDocument): Record<string, unknown>[] {
  const policies = nested(d, "policies");
  if (!Array.isArray(policies["specificRules"])) policies["specificRules"] = [];
  return policies["specificRules"] as Record<string, unknown>[];
}

/** nested returns an object property, creating it when absent. */
function nested(
  parent: Record<string, unknown>,
  key: string,
): Record<string, unknown> {
  if (typeof parent[key] !== "object" || parent[key] === null) {
    parent[key] = {};
  }
  return parent[key] as Record<string, unknown>;
}

function removeAt(
  update: (mutate: (d: PolicyDocument) => void) => void,
  section: string,
  index: number,
) {
  update((d) => {
    if (section === "specificRules") {
      specific(d).splice(index, 1);
      return;
    }
    const list = d[section];
    if (Array.isArray(list)) list.splice(index, 1);
  });
}

function humanize(key: string): string {
  const spaced = key.replace(/([A-Z])/g, " $1").toLowerCase();
  return spaced.charAt(0).toUpperCase() + spaced.slice(1);
}

// ---------------------------------------------------------------- controls

function Group({
  title,
  children,
  defaultOpen = false,
}: {
  title: string;
  children: ReactNode;
  defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div
      style={{
        border: "1px solid var(--border)",
        borderRadius: "var(--radius-sm)",
      }}
    >
      <button
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        style={{
          width: "100%",
          textAlign: "left",
          padding: "9px 12px",
          background: "transparent",
          border: "none",
          color: "var(--text-primary)",
          fontWeight: 600,
          fontSize: 13,
          cursor: "pointer",
        }}
      >
        {open ? "▾" : "▸"} {title}
      </button>
      {open && (
        <div className="stack" style={{ gap: 10, padding: "4px 12px 14px" }}>
          {children}
        </div>
      )}
    </div>
  );
}

function SubGroup({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div style={{ marginTop: 8 }}>
      <div
        className="muted"
        style={{
          fontSize: 11,
          textTransform: "uppercase",
          letterSpacing: "0.04em",
          fontWeight: 600,
          marginBottom: 6,
        }}
      >
        {title}
      </div>
      <div className="stack" style={{ gap: 8 }}>
        {children}
      </div>
    </div>
  );
}

function Card({
  children,
  onRemove,
}: {
  children: ReactNode;
  onRemove?: () => void;
}) {
  return (
    <div
      style={{
        border: "1px solid var(--grid)",
        borderRadius: "var(--radius-sm)",
        padding: 12,
        position: "relative",
      }}
    >
      {onRemove && (
        <button
          className="btn btn-sm"
          onClick={onRemove}
          style={{ position: "absolute", top: 8, right: 8 }}
          aria-label="Remove"
        >
          ✕
        </button>
      )}
      <div className="stack" style={{ gap: 9 }}>
        {children}
      </div>
    </div>
  );
}

function AddButton({ label, onClick }: { label: string; onClick: () => void }) {
  return (
    <button className="btn btn-sm" onClick={onClick} style={{ alignSelf: "flex-start" }}>
      + {label}
    </button>
  );
}

function Hint({ text }: { text?: string }) {
  if (!text) return null;
  return (
    <div className="muted" style={{ fontSize: 11.5, marginTop: 3 }}>
      {text}
    </div>
  );
}

function Select({
  label,
  value,
  options,
  disabled,
  hint,
  onChange,
}: {
  label: string;
  value: string;
  options: string[];
  disabled?: boolean;
  hint?: string;
  onChange: (v: string) => void;
}) {
  return (
    <div>
      <label>{label}</label>
      <select
        value={value}
        disabled={disabled}
        onChange={(e) => onChange(e.target.value)}
      >
        {options.map((option) => (
          <option key={option} value={option}>
            {option === "" ? "(none)" : option}
          </option>
        ))}
      </select>
      <Hint text={hint} />
    </div>
  );
}

function MultiSelect({
  label,
  value,
  options,
  disabled,
  onChange,
}: {
  label: string;
  value: string[];
  options: string[];
  disabled?: boolean;
  onChange: (v: string[]) => void;
}) {
  return (
    <div>
      <label>{label}</label>
      {options.length === 0 ? (
        <div className="muted" style={{ fontSize: 12 }}>
          None defined in this policy.
        </div>
      ) : (
        <div className="row" style={{ gap: 10 }}>
          {options.map((option) => (
            <label
              key={option}
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
                checked={value.includes(option)}
                disabled={disabled}
                style={{ width: "auto" }}
                onChange={(e) =>
                  onChange(
                    e.target.checked
                      ? [...value, option]
                      : value.filter((v) => v !== option),
                  )
                }
              />
              {option}
            </label>
          ))}
        </div>
      )}
    </div>
  );
}

function Text({
  label,
  value,
  disabled,
  hint,
  onChange,
}: {
  label: string;
  value: string;
  disabled?: boolean;
  hint?: string;
  onChange: (v: string) => void;
}) {
  return (
    <div>
      <label>{label}</label>
      <input value={value} disabled={disabled} onChange={(e) => onChange(e.target.value)} />
      <Hint text={hint} />
    </div>
  );
}

function Num({
  label,
  value,
  placeholder,
  disabled,
  onChange,
}: {
  label: string;
  value?: number;
  placeholder?: string;
  disabled?: boolean;
  onChange: (v: number | undefined) => void;
}) {
  return (
    <div>
      <label>{label}</label>
      <input
        type="number"
        value={value ?? ""}
        placeholder={placeholder}
        disabled={disabled}
        onChange={(e) =>
          onChange(e.target.value === "" ? undefined : Number(e.target.value))
        }
      />
    </div>
  );
}

function Toggle({
  label,
  value,
  disabled,
  hint,
  onChange,
}: {
  label: string;
  value: boolean;
  disabled?: boolean;
  hint?: string;
  onChange: (v: boolean) => void;
}) {
  return (
    <div>
      <label
        style={{
          display: "flex",
          alignItems: "center",
          gap: 7,
          marginBottom: 0,
          fontWeight: 400,
          fontSize: 12.5,
          color: "var(--text-primary)",
        }}
      >
        <input
          type="checkbox"
          checked={value}
          disabled={disabled}
          style={{ width: "auto" }}
          onChange={(e) => onChange(e.target.checked)}
        />
        {label}
      </label>
      <Hint text={hint} />
    </div>
  );
}
