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

export interface TooltipState {
  x: number;
  y: number;
  content: ReactNode;
}

/** useTooltip wires the hover layer every chart here ships with. */
export function useTooltip() {
  const [tip, setTip] = useState<TooltipState | null>(null);

  const show = (event: { clientX: number; clientY: number }, content: ReactNode) =>
    setTip({ x: event.clientX, y: event.clientY, content });
  const hide = () => setTip(null);

  return { tip, show, hide };
}

export function Tooltip({ tip }: { tip: TooltipState | null }) {
  if (!tip) return null;

  // Nudged away from the cursor and clamped so it cannot run off the viewport.
  const left = Math.min(tip.x + 14, window.innerWidth - 300);
  const top = Math.min(tip.y + 14, window.innerHeight - 120);

  return (
    <div className="tooltip" style={{ left, top }} role="tooltip">
      {tip.content}
    </div>
  );
}
