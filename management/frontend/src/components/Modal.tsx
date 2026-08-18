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

import { useEffect, useRef, type ReactNode } from "react";

const FOCUSABLE = [
  "a[href]",
  "button:not([disabled])",
  "input:not([disabled])",
  "select:not([disabled])",
  "textarea:not([disabled])",
  '[tabindex]:not([tabindex="-1"])',
].join(",");

interface Props {
  label: string;
  onClose: () => void;
  children: ReactNode;
  width?: number;
}

/**
 * A side panel that behaves like a real dialog.
 *
 * Declaring role="dialog" is not enough on its own: without Escape handling,
 * initial focus, a focus trap and focus restoration, a keyboard or
 * screen-reader user can open one of these panels and then be unable to act in
 * it or leave it. All three detail panels share this so the behaviour cannot
 * drift apart between them.
 */
export function Modal({ label, onClose, children, width = 680 }: Props) {
  const panelRef = useRef<HTMLDivElement>(null);
  const restoreTo = useRef<HTMLElement | null>(null);

  // Held in a ref so the focus lifecycle below can depend on nothing.
  // Every call site passes an inline arrow, so onClose is a new function on
  // each parent render; an effect depending on it would tear down and set up
  // again — restoring focus to the trigger and then pulling it back to the
  // panel — every time the page behind the panel rerendered, stealing focus
  // from whatever control the user was actually using.
  const onCloseRef = useRef(onClose);
  useEffect(() => {
    onCloseRef.current = onClose;
  }, [onClose]);

  useEffect(() => {
    restoreTo.current = document.activeElement as HTMLElement | null;
    panelRef.current?.focus();

    function onKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") {
        event.stopPropagation();
        onCloseRef.current();
        return;
      }
      if (event.key !== "Tab") return;

      // Keep Tab inside the panel; otherwise focus walks off into the page
      // behind the overlay, which the user cannot see.
      const panel = panelRef.current;
      if (!panel) return;

      const focusable = Array.from(
        panel.querySelectorAll<HTMLElement>(FOCUSABLE),
      ).filter((el) => el.offsetParent !== null || el === panel);
      if (focusable.length === 0) {
        event.preventDefault();
        panel.focus();
        return;
      }

      const first = focusable[0]!;
      const last = focusable[focusable.length - 1]!;
      const active = document.activeElement;

      if (!event.shiftKey && active === last) {
        event.preventDefault();
        first.focus();
      } else if (event.shiftKey && (active === first || active === panel)) {
        event.preventDefault();
        last.focus();
      }
    }

    document.addEventListener("keydown", onKeyDown, true);
    return () => {
      document.removeEventListener("keydown", onKeyDown, true);
      restoreTo.current?.focus?.();
    };
    // Mount and unmount only: this is the panel's focus lifecycle, not a
    // reaction to any prop.
  }, []);

  return (
    <div
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
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-label={label}
        tabIndex={-1}
        onClick={(e) => e.stopPropagation()}
        style={{
          width: `min(${width}px, 100%)`,
          background: "var(--surface-1)",
          borderLeft: "1px solid var(--border)",
          overflowY: "auto",
          padding: 20,
          outline: "none",
        }}
      >
        {children}
      </div>
    </div>
  );
}
