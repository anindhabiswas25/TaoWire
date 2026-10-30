"use client";

import { AnimatePresence, motion } from "motion/react";
import { useMemo, useState } from "react";
import { modules, type Module } from "@/content/site";
import { Arrow, Reveal } from "./primitives";

const CATS = ["All", "Runtime", "Security", "Migration"] as const;

function Mark({ kind }: { kind: Module["mark"] }) {
  switch (kind) {
    case "miner":
      return (
        <div className="wm-spaced">
          <svg width="34" height="40" viewBox="0 0 26 30" aria-hidden="true">
            <rect x="3" y="2" width="20" height="8" fill="#161616" /><rect x="3" y="11" width="20" height="8" fill="#3a3a3a" /><rect x="3" y="20" width="20" height="8" fill="#161616" />
            <rect x="6" y="5" width="2" height="2" fill="#f4f4f4" /><rect x="6" y="14" width="2" height="2" fill="#f4f4f4" /><rect x="6" y="23" width="2" height="2" fill="#f5661f" />
          </svg>
          <div className="t">MINER<small>SERVER KIT</small></div>
        </div>
      );
    case "validator":
      return (
        <div className="wm-light">
          <svg width="32" height="32" viewBox="0 0 22 22" aria-hidden="true">
            <path d="M17.5 6.5A8 8 0 1 0 19 13" fill="none" stroke="#161616" strokeWidth="2.4" />
            <rect x="15" y="2" width="3" height="3" fill="#161616" /><rect x="19" y="5" width="2.4" height="2.4" fill="#161616" /><rect x="18" y="0" width="2" height="2" fill="#161616" />
          </svg>
          Validator
        </div>
      );
    case "signed":
      return <div className="wm-stack">SIGNED<br />ANSWERS</div>;
    case "compat":
      return <div className="wm-bold">COMPAT</div>;
    case "conformance":
      return (
        <div className="wm-heavy">
          <svg width="34" height="20" viewBox="0 0 26 16" aria-hidden="true"><path d="M1.5 8.5 6 13 13 3M8.5 13 15.5 3h9" fill="none" stroke="#161616" strokeWidth="2.8" /></svg>
          CONFORMANCE
        </div>
      );
    case "migrate":
      return (
        <div className="wm-sans">
          <svg width="30" height="34" viewBox="0 0 22 26" aria-hidden="true">
            <path d="M11 1 21 6.5v13L11 25 1 19.5v-13Z" fill="#8a8a8a" />
            <path d="M11 1 21 6.5 11 12 1 6.5Z" fill="#c4c4c4" /><path d="M11 12v13L1 19.5v-13Z" fill="#3a3a3a" />
          </svg>
          Migrate
        </div>
      );
  }
}

export default function Modules() {
  const [cat, setCat] = useState<(typeof CATS)[number]>("All");
  const [q, setQ] = useState("");
  const shown = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return modules.filter((m) =>
      (cat === "All" || m.cat === cat) &&
      (!needle || `${m.name} ${m.cat} ${m.keywords} ${m.stats.flat().join(" ")}`.toLowerCase().includes(needle)));
  }, [cat, q]);

  return (
    <section className="sec pad" id="modules">
      <div className="sec-head">
        <div className="sec-idx"><span className="sq" /><span><b>03</b> / Modules</span></div>
        <Reveal>
          <h2 className="h2">Six modules, one secure default</h2>
          <p className="lead">Runtime for miners and validators, the security layer between them, and the tooling that brings a v10 subnet across.</p>
        </Reveal>
      </div>

      <div className="filters-row">
        <div className="scen" style={{ margin: 0 }} role="group" aria-label="Filter modules">
          {CATS.map((c) => (
            <button key={c} className={`tab${c === cat ? " on" : ""}`} aria-pressed={c === cat} onClick={() => setCat(c)}>{c}</button>
          ))}
        </div>
        <label className="search">
          <svg width="12" height="12" viewBox="0 0 10 10" aria-hidden="true"><circle cx="4.2" cy="4.2" r="3.2" fill="none" stroke="#5d5d5d" /><path d="M6.6 6.6 9.3 9.3" stroke="#5d5d5d" /></svg>
          <input type="search" placeholder="Search modules, e.g. redis, drand, v10" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search modules" />
        </label>
      </div>

      <motion.div className="cards" layout>
        <AnimatePresence mode="popLayout">
          {shown.map((m, i) => (
            <motion.article key={m.name} className="card" layout
              initial={{ opacity: 0, scale: 0.96, y: 16 }} animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.96 }} transition={{ duration: 0.35, delay: i * 0.04 }}>
              <span className="tag">{m.cat}</span>
              <motion.div className="mark" whileHover={{ scale: 1.04 }} transition={{ type: "spring", stiffness: 300, damping: 20 }}>
                <Mark kind={m.mark} />
              </motion.div>
              <div className="grid">
                {m.stats.map(([v, l]) => <div className="s" key={l}><b>{v}</b><span>{l}</span></div>)}
                <a className="go" href={m.href} aria-label={`${m.name} docs`}><Arrow size={13} /></a>
              </div>
            </motion.article>
          ))}
        </AnimatePresence>
        {shown.length === 0 && <p className="empty">No modules match “{q}”.</p>}
      </motion.div>
    </section>
  );
}
