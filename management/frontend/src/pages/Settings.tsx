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

import { useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api } from "../api";
import { useAuth } from "../auth-context";
import { ErrorBanner, Loading, PageHeader } from "../components/Layout";
import { formatTime } from "../components/charts/chart-utils";
import type { Role } from "../types";

export function Settings() {
  const { canAdmin } = useAuth();

  return (
    <>
      <PageHeader title="Settings" />
      <div className="stack">
        <ChangePassword />
        {canAdmin && <Users />}
        <AuditLog />
      </div>
    </>
  );
}

function ChangePassword() {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [notice, setNotice] = useState("");
  const [error, setError] = useState<unknown>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setNotice("");
    try {
      await api.changePassword(current, next);
      setNotice("Password changed.");
      setCurrent("");
      setNext("");
    } catch (err) {
      setError(err);
    }
  }

  return (
    <form className="card" onSubmit={submit}>
      <h2 className="card-title">Change your password</h2>
      <ErrorBanner error={error} />
      {notice && (
        <div className="banner banner-ok" style={{ marginBottom: 10 }}>
          {notice}
        </div>
      )}
      <div className="row" style={{ gap: 10, alignItems: "flex-end" }}>
        <div style={{ flex: 1, minWidth: 180 }}>
          <label htmlFor="current">Current password</label>
          <input
            id="current"
            type="password"
            value={current}
            onChange={(e) => setCurrent(e.target.value)}
            autoComplete="current-password"
            required
          />
        </div>
        <div style={{ flex: 1, minWidth: 180 }}>
          <label htmlFor="next">New password</label>
          <input
            id="next"
            type="password"
            value={next}
            onChange={(e) => setNext(e.target.value)}
            autoComplete="new-password"
            minLength={12}
            required
          />
        </div>
        <button className="btn btn-primary" type="submit">
          Update
        </button>
      </div>
      <p className="muted" style={{ fontSize: 12, marginBottom: 0 }}>
        At least 12 characters.
      </p>
    </form>
  );
}

function Users() {
  const queryClient = useQueryClient();
  const [showAdd, setShowAdd] = useState(false);

  const users = useQuery({ queryKey: ["users"], queryFn: api.users });

  const create = useMutation({
    mutationFn: (input: {
      username: string;
      email: string;
      password: string;
      role: string;
    }) => api.createUser(input),
    onSuccess: async () => {
      setShowAdd(false);
      await queryClient.invalidateQueries({ queryKey: ["users"] });
    },
  });

  const update = useMutation({
    mutationFn: ({ id, patch }: { id: string; patch: Record<string, unknown> }) =>
      api.updateUser(id, patch),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["users"] }),
  });

  const remove = useMutation({
    mutationFn: (id: string) => api.deleteUser(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["users"] }),
  });

  return (
    <div className="card" style={{ padding: 0 }}>
      <div
        className="row"
        style={{
          justifyContent: "space-between",
          padding: "12px 16px",
          borderBottom: "1px solid var(--border)",
        }}
      >
        <h2 className="card-title" style={{ margin: 0 }}>
          Users
        </h2>
        <button className="btn btn-sm" onClick={() => setShowAdd((s) => !s)}>
          {showAdd ? "Cancel" : "Add user"}
        </button>
      </div>

      <div style={{ padding: 16 }}>
        <ErrorBanner error={create.error ?? update.error ?? remove.error} />

        {showAdd && (
          <AddUserForm busy={create.isPending} onSubmit={create.mutate} />
        )}

        {users.isPending ? (
          <Loading />
        ) : (
          <div className="scroll-x">
            <table>
              <thead>
                <tr>
                  <th>Username</th>
                  <th>Role</th>
                  <th>Status</th>
                  <th>Last sign-in</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {(users.data ?? []).map((user) => (
                  <tr key={user.id}>
                    <td>
                      <div style={{ fontWeight: 600 }}>{user.username}</div>
                      {user.email && (
                        <div className="muted" style={{ fontSize: 11.5 }}>
                          {user.email}
                        </div>
                      )}
                    </td>
                    <td>
                      <select
                        value={user.role}
                        onChange={(e) =>
                          update.mutate({
                            id: user.id,
                            patch: { role: e.target.value as Role },
                          })
                        }
                        style={{ width: 110 }}
                        aria-label={`Role for ${user.username}`}
                      >
                        <option value="admin">admin</option>
                        <option value="editor">editor</option>
                        <option value="viewer">viewer</option>
                      </select>
                    </td>
                    <td>
                      <span className="chip">
                        {user.disabled ? "disabled" : "active"}
                      </span>
                    </td>
                    <td className="num">
                      {user.lastLoginAt ? formatTime(user.lastLoginAt) : "never"}
                    </td>
                    <td style={{ textAlign: "right", whiteSpace: "nowrap" }}>
                      <button
                        className="btn btn-sm"
                        onClick={() =>
                          update.mutate({
                            id: user.id,
                            patch: { disabled: !user.disabled },
                          })
                        }
                      >
                        {user.disabled ? "Enable" : "Disable"}
                      </button>
                      <button
                        className="btn btn-sm btn-danger"
                        style={{ marginLeft: 6 }}
                        onClick={() => remove.mutate(user.id)}
                      >
                        Delete
                      </button>
                    </td>
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

function AddUserForm({
  busy,
  onSubmit,
}: {
  busy: boolean;
  onSubmit: (input: {
    username: string;
    email: string;
    password: string;
    role: string;
  }) => void;
}) {
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("viewer");

  return (
    <div
      className="row"
      style={{ gap: 10, alignItems: "flex-end", marginBottom: 16 }}
    >
      <div style={{ flex: 1, minWidth: 130 }}>
        <label htmlFor="new-username">Username</label>
        <input
          id="new-username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
        />
      </div>
      <div style={{ flex: 1, minWidth: 130 }}>
        <label htmlFor="new-email">Email</label>
        <input
          id="new-email"
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
        />
      </div>
      <div style={{ flex: 1, minWidth: 130 }}>
        <label htmlFor="new-password">Password</label>
        <input
          id="new-password"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          minLength={12}
        />
      </div>
      <div style={{ width: 120 }}>
        <label htmlFor="new-role">Role</label>
        <select
          id="new-role"
          value={role}
          onChange={(e) => setRole(e.target.value)}
        >
          <option value="admin">admin</option>
          <option value="editor">editor</option>
          <option value="viewer">viewer</option>
        </select>
      </div>
      <button
        className="btn btn-primary"
        disabled={busy || !username || password.length < 12}
        onClick={() => onSubmit({ username, email, password, role })}
      >
        Create
      </button>
    </div>
  );
}

function AuditLog() {
  const entries = useQuery({ queryKey: ["audit"], queryFn: () => api.audit(200) });

  return (
    <div className="card" style={{ padding: 0 }}>
      <div style={{ padding: "12px 16px", borderBottom: "1px solid var(--border)" }}>
        <h2 className="card-title" style={{ margin: 0 }}>
          Audit log
        </h2>
      </div>
      {entries.isPending ? (
        <Loading />
      ) : (
        <div className="scroll-x">
          <table>
            <thead>
              <tr>
                <th>When</th>
                <th>Who</th>
                <th>Action</th>
                <th>Target</th>
                <th>Source</th>
              </tr>
            </thead>
            <tbody>
              {(entries.data ?? []).map((entry) => (
                <tr key={entry.id}>
                  <td className="num" style={{ whiteSpace: "nowrap" }}>
                    {formatTime(entry.occurredAt)}
                  </td>
                  <td>{entry.username || "—"}</td>
                  <td className="mono">{entry.action}</td>
                  <td className="mono">
                    {entry.targetType}
                    {entry.targetId ? ` ${entry.targetId}` : ""}
                  </td>
                  <td className="mono">{entry.remoteAddr}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
