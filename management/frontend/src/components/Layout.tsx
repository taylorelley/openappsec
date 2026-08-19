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

import { useEffect, useState, type ReactNode } from "react";
import { NavLink } from "react-router-dom";

import { useAuth } from "../auth-context";

const NAV = [
  { to: "/", label: "Dashboard", end: true },
  { to: "/events", label: "Events" },
  { to: "/policy", label: "Policy" },
  { to: "/fleet", label: "Fleet" },
  { to: "/learning", label: "Learning" },
  { to: "/settings", label: "Settings" },
];

export function Layout({ children }: { children: ReactNode }) {
  const { user, logout } = useAuth();
  const [theme, setTheme] = useTheme();

  return (
    <div style={{ minHeight: "100vh", display: "flex", flexDirection: "column" }}>
      <header
        style={{
          borderBottom: "1px solid var(--border)",
          background: "var(--surface-1)",
          position: "sticky",
          top: 0,
          zIndex: 20,
        }}
      >
        <div
          style={{
            maxWidth: 1440,
            margin: "0 auto",
            padding: "0 20px",
            display: "flex",
            alignItems: "center",
            gap: 24,
            height: 52,
          }}
        >
          <span style={{ fontWeight: 650, whiteSpace: "nowrap" }}>
            open-appsec
            <span className="muted" style={{ fontWeight: 400 }}>
              {" "}
              Manager
            </span>
          </span>

          <nav className="row" style={{ gap: 2, flex: 1 }}>
            {NAV.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                style={({ isActive }) => ({
                  padding: "6px 11px",
                  borderRadius: "var(--radius-sm)",
                  fontSize: 13,
                  fontWeight: 500,
                  textDecoration: "none",
                  color: isActive ? "var(--text-primary)" : "var(--text-secondary)",
                  background: isActive ? "var(--surface-sunken)" : "transparent",
                })}
              >
                {item.label}
              </NavLink>
            ))}
          </nav>

          <div className="row" style={{ gap: 10 }}>
            <button
              className="btn btn-sm"
              onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
              title={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}
              aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}
            >
              {theme === "dark" ? "Light" : "Dark"}
            </button>
            <span className="muted" style={{ fontSize: 12.5 }}>
              {user?.username} · {user?.role}
            </span>
            <button className="btn btn-sm" onClick={() => void logout()}>
              Sign out
            </button>
          </div>
        </div>
      </header>

      <main
        style={{
          flex: 1,
          maxWidth: 1440,
          width: "100%",
          margin: "0 auto",
          padding: "20px",
        }}
      >
        {children}
      </main>
    </div>
  );
}

type Theme = "light" | "dark" | "system";

/** The explicit choice wins over the OS setting, in both directions. */
function useTheme(): [Theme, (t: Theme) => void] {
  const [theme, setTheme] = useState<Theme>(
    () => (localStorage.getItem("theme") as Theme | null) ?? "system",
  );

  useEffect(() => {
    if (theme === "system") {
      document.documentElement.removeAttribute("data-theme");
      localStorage.removeItem("theme");
    } else {
      document.documentElement.setAttribute("data-theme", theme);
      localStorage.setItem("theme", theme);
    }
  }, [theme]);

  return [theme, setTheme];
}

export function PageHeader({
  title,
  description,
  actions,
}: {
  title: string;
  description?: string;
  actions?: ReactNode;
}) {
  return (
    <div
      className="row"
      style={{ justifyContent: "space-between", marginBottom: 18, gap: 16 }}
    >
      <div>
        <h1 style={{ fontSize: 19, margin: 0 }}>{title}</h1>
        {description && (
          <p className="muted" style={{ margin: "3px 0 0", fontSize: 13 }}>
            {description}
          </p>
        )}
      </div>
      {actions && <div className="row">{actions}</div>}
    </div>
  );
}

export function ErrorBanner({ error }: { error: unknown }) {
  if (!error) return null;
  const message = error instanceof Error ? error.message : String(error);
  return (
    <div className="banner banner-error" role="alert" style={{ marginBottom: 14 }}>
      {message}
    </div>
  );
}

export function Loading({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="muted" style={{ padding: 28, textAlign: "center", fontSize: 13 }}>
      {label}
    </div>
  );
}
