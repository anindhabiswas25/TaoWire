"use client";

import { animate, motion, useInView, useReducedMotion } from "motion/react";
import { useEffect, useRef, useState, type ReactNode } from "react";

/* ---------- block-letter glyphs: a 100 x 90 box built from rectangles ---------- */

type Rect = [number, number, number, number];
const GLYPHS: Record<string, [number, Rect[]]> = {
  T: [100, [[0, 0, 100, 20], [40, 0, 20, 90]]],
  A: [100, [[12, 0, 76, 20], [0, 12, 20, 78], [80, 12, 20, 78], [0, 46, 100, 18]]],
  O: [100, [[12, 0, 76, 20], [12, 70, 76, 20], [0, 12, 20, 66], [80, 12, 20, 66]]],
  _: [48, [[0, 72, 48, 18]]],
  W: [100, [[0, 0, 20, 78], [80, 0, 20, 78], [40, 34, 20, 44], [12, 70, 76, 20]]],
  I: [84, [[0, 0, 84, 20], [32, 0, 20, 90], [0, 70, 84, 20]]],
  R: [100, [[0, 0, 20, 90], [0, 0, 88, 20], [80, 12, 20, 34], [20, 42, 68, 18], [72, 52, 20, 38]]],
  E: [100, [[0, 0, 20, 90], [0, 0, 100, 20], [0, 38, 78, 16], [0, 70, 100, 20]]],
  "0": [100, [[12, 0, 76, 20], [12, 70, 76, 20], [0, 12, 20, 66], [80, 12, 20, 66], [40, 38, 20, 16]]],
  "6": [100, [[0, 0, 20, 90], [0, 0, 92, 18], [0, 40, 92, 16], [80, 46, 20, 32], [0, 72, 88, 18]]],
};
const GAP = 12;

/** Block-letter text drawn as SVG; the rectangles assemble when it scrolls into view. */
export function PixelText({ text, height, animated = true, blinkLast = false, delay = 0, className }: {
  text: string; height?: number; animated?: boolean; blinkLast?: boolean; delay?: number; className?: string;
}) {
  const reduce = useReducedMotion();
  const rects: { r: Rect; x: number; i: number; last: boolean }[] = [];
  let x = 0, i = 0;
  const chars = [...text];
  chars.forEach((ch, ci) => {
    const [w, rs] = GLYPHS[ch];
    for (const r of rs) rects.push({ r, x, i: i++, last: ci === chars.length - 1 });
    x += w + GAP;
  });
  const vw = x - GAP;
  const anim = animated && !reduce;
  // Observe the whole word: a glyph bar starting above the viewBox is clipped
  // and would never report itself as in view.
  const ref = useRef<SVGSVGElement>(null);
  const inView = useInView(ref, { once: true });
  return (
    <svg ref={ref} viewBox={`0 0 ${vw} 90`} className={className} aria-hidden="true"
      style={{ overflow: "visible", ...(height ? { height, width: (vw * height) / 90 } : {}) }}>
      {rects.map(({ r: [rx, ry, rw, rh], x: ox, i: ri, last }) => (
        <motion.g key={ri}
          initial={anim ? { opacity: 0, y: -30 } : false}
          animate={inView || !anim ? { opacity: 1, y: 0 } : undefined}
          transition={{ delay: delay + ri * 0.035, type: "spring", stiffness: 260, damping: 18 }}>
          <rect x={ox + rx} y={ry} width={rw} height={rh} rx={3} fill="currentColor"
            className={blinkLast && last ? "blink-rect" : undefined} />
        </motion.g>
      ))}
      {blinkLast && <style>{`.blink-rect{animation:blink 1.1s steps(1) infinite 1.6s}@media (prefers-reduced-motion:reduce){.blink-rect{animation:none}}`}</style>}
    </svg>
  );
}

/* ---------- reveal on scroll ---------- */

export function Reveal({ children, delay = 0, y = 18, className, as = "div" }: {
  children: ReactNode; delay?: number; y?: number; className?: string; as?: "div" | "section" | "li";
}) {
  const M = motion[as];
  return (
    <M className={className} initial={{ opacity: 0, y }} whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: "-60px" }} transition={{ duration: 0.6, delay, ease: [0.2, 0.7, 0.2, 1] }}>
      {children}
    </M>
  );
}

/* ---------- number that counts up once visible ---------- */

export function CountUp({ value, decimals = 0, suffix = "", grouping = true }: {
  value: number; decimals?: number; suffix?: string; grouping?: boolean;
}) {
  const ref = useRef<HTMLSpanElement>(null);
  const inView = useInView(ref, { once: true, margin: "-40px" });
  const reduce = useReducedMotion();
  const fmt = (n: number) =>
    n.toLocaleString("en-US", { minimumFractionDigits: decimals, maximumFractionDigits: decimals, useGrouping: grouping });
  const [shown, setShown] = useState(fmt(value));
  useEffect(() => {
    if (!inView || reduce) return;
    const c = animate(0, value, { duration: 1.6, ease: [0.16, 1, 0.3, 1], onUpdate: (v) => setShown(fmt(v)) });
    return () => c.stop();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [inView, reduce, value]);
  return <span ref={ref}>{shown}{suffix}</span>;
}

/* ---------- copy to clipboard ---------- */

export function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button className="copy" type="button" aria-label={`Copy: ${text}`}
      onClick={async () => {
        try { await navigator.clipboard.writeText(text); setDone(true); setTimeout(() => setDone(false), 1400); } catch { /* clipboard blocked */ }
      }}>
      {done ? "Copied ✓" : label}
    </button>
  );
}

/* ---------- icons ---------- */

export function Arrow({ size = 12, color = "currentColor" }: { size?: number; color?: string }) {
  return (
    <svg className="arr" width={size} height={size} viewBox="0 0 10 10" aria-hidden="true">
      <path d="M1 5h7M5 1.7 8.3 5 5 8.3" fill="none" stroke={color} strokeWidth="1.8" />
    </svg>
  );
}

export function LogoMark({ size = 32 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 26 26" aria-hidden="true">
      <rect width="26" height="26" rx="6" fill="#f5661f" />
      <rect x="4" y="5" width="18" height="16" rx="3.5" fill="#161616" />
      <rect x="7.5" y="11" width="3" height="3" fill="#fff" />
      <rect x="15.5" y="11" width="3" height="3" fill="#fff" />
      <rect x="10.5" y="12" width="5" height="1" fill="#f5661f" />
    </svg>
  );
}

/* ---------- isometric voxels that stack up one by one ---------- */

export function Iso() {
  const reduce = useReducedMotion();
  const cubes: [number, number, number][] = [[1, 0, 0], [0, 1, 0], [1, 1, 0], [2, 1, 0], [1, 2, 0], [1, 1, 1], [2, 1, 1]];
  const order = [...cubes].sort((a, b) => a[0] + a[1] + a[2] - (b[0] + b[1] + b[2]) || a[2] - b[2]);
  const s = 9, ox = 32, oy = 30;
  const P = (x: number, y: number, z: number) => [ox + (x - y) * s * 0.87, oy + (x + y) * s * 0.5 - z * s];
  const pts = (a: number[][]) => a.map((p) => P(p[0], p[1], p[2]).map((n) => n.toFixed(1)).join(",")).join(" ");
  return (
    <motion.svg viewBox="0 0 64 64" animate={reduce ? undefined : { y: [0, -3, 0] }}
      transition={{ duration: 4, repeat: Infinity, ease: "easeInOut" }} aria-hidden="true">
      {order.map(([x, y, z], i) => {
        const top = [[x, y, z + 1], [x + 1, y, z + 1], [x + 1, y + 1, z + 1], [x, y + 1, z + 1]];
        const left = [[x, y + 1, z], [x + 1, y + 1, z], [x + 1, y + 1, z + 1], [x, y + 1, z + 1]];
        const right = [[x + 1, y, z], [x + 1, y + 1, z], [x + 1, y + 1, z + 1], [x + 1, y, z + 1]];
        return (
          <motion.g key={i} initial={reduce ? false : { opacity: 0, y: -14 }} whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }} transition={{ delay: 0.5 + i * 0.12, type: "spring", stiffness: 300, damping: 20 }}
            stroke="#3a3a3a" strokeWidth="0.9" strokeLinejoin="round">
            <polygon points={pts(left)} fill="#e2e2e2" />
            <polygon points={pts(right)} fill="#cfcfcf" />
            <polygon points={pts(top)} fill={i === order.length - 1 ? "#f5661f" : "#fafafa"} />
          </motion.g>
        );
      })}
    </motion.svg>
  );
}
