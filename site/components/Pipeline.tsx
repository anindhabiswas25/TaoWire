"use client";

import { motion, useInView, useReducedMotion } from "motion/react";
import { useEffect, useRef, useState } from "react";
import { pipeline } from "@/content/site";
import { Reveal } from "./primitives";

// Each scenario names the stage where the request is refused (-1: accepted).
const SCENARIOS = [
  { id: "ok", label: "Valid request", failAt: -1 },
  { id: "big", label: "100 MB body", failAt: 0 },
  { id: "sig", label: "Bad signature", failAt: 2 },
  { id: "replay", label: "Replayed nonce", failAt: 3 },
  { id: "perm", label: "No validator permit", failAt: 4 },
];
const STEP_MS = 650;

export default function Pipeline() {
  const [scen, setScen] = useState(0);
  const [pos, setPos] = useState(-1);
  const ref = useRef<HTMLDivElement>(null);
  const inView = useInView(ref, { margin: "-80px" });
  const reduce = useReducedMotion();
  const { failAt } = SCENARIOS[scen];
  const stages = pipeline.stages;
  const end = failAt === -1 ? stages.length - 1 : failAt;
  const done = pos >= end;

  // Walk the packet stage by stage; hold on the result, then replay.
  useEffect(() => {
    if (!inView) return;
    if (reduce) { setPos(end); return; }
    const t = setTimeout(() => setPos((p) => (p >= end ? -1 : p + 1)), done ? 2600 : pos < 0 ? 400 : STEP_MS);
    return () => clearTimeout(t);
  }, [pos, inView, end, done, reduce]);

  const pick = (i: number) => { setScen(i); setPos(-1); };
  const err = failAt >= 0 ? stages[failAt].fail : "";

  return (
    <section className="sec pad" id="pipeline">
      <div className="sec-head">
        <div className="sec-idx"><span className="sq" /><span><b>02</b> / Request pipeline</span></div>
        <Reveal>
          <h2 className="h2">{pipeline.title}</h2>
          <p className="lead">{pipeline.body}</p>
        </Reveal>
      </div>

      <div className="scen" role="tablist" aria-label="Request scenario">
        {SCENARIOS.map((s, i) => (
          <button key={s.id} role="tab" aria-selected={i === scen} className={`tab${i === scen ? " on" : ""}`} onClick={() => pick(i)}>
            {s.label}
          </button>
        ))}
      </div>

      <div className="stages" ref={ref}>
        {pos >= 0 && (
          <motion.span className="packet" aria-hidden="true"
            animate={{ left: `calc(${((pos + 0.5) / stages.length) * 100}% - 7px)`, rotate: pos * 90 }}
            initial={false} transition={{ type: "spring", stiffness: 220, damping: 22 }} />
        )}
        {stages.map((s, i) => {
          const failed = i === failAt && pos >= i;
          const cls = failed ? "fail" : i < pos || (i === pos && done) ? "pass" : i === pos ? "cur" : "";
          return (
            <div key={s.name} className={`stage ${cls}`}>
              <span className="led" />
              <span className="n">{String(i + 1).padStart(2, "0")}</span>
              <h4>{s.name}</h4>
              <p>{s.detail}</p>
              {failed && (
                <motion.span className="err" initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }}>{s.fail}</motion.span>
              )}
            </div>
          );
        })}
      </div>

      <div className="pipe-out" aria-live="polite">
        <span className="res">
          {!done ? (
            <><i style={{ background: "var(--orange)" }} />Checking stage {Math.max(pos + 1, 1)} of {stages.length}…</>
          ) : failAt === -1 ? (
            <><i style={{ background: "var(--ink)" }} />200 OK: answer signed with twresp/1, bound to the request&apos;s nonce and sender.</>
          ) : (
            <><i style={{ background: "#d43c0b" }} />Refused with {err}. Later stages never run.</>
          )}
        </span>
        <span className="note">fixed public error codes · spec Appendix A</span>
      </div>
    </section>
  );
}
