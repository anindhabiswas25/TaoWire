"use client";

import { AnimatePresence, motion, useInView, useReducedMotion } from "motion/react";
import { Fragment, useEffect, useRef, useState, type ReactNode } from "react";
import { code, commands } from "@/content/site";
import { CopyButton, Reveal } from "./primitives";

/* ---------- tiny Python highlighter (keywords, strings, comments, decorators) ---------- */

const KW = new Set(["from", "import", "async", "def", "await", "return", "class", "for", "in", "if", "else", "and", "or", "not", "isinstance"]);

function highlight(src: string): ReactNode[] {
  const out: ReactNode[] = [];
  const re = /(#[^\n]*)|("(?:[^"\\]|\\.)*")|(@[\w.]+)|(\b[A-Za-z_]\w*\b)(?=\()|(\b[A-Za-z_]\w*\b)/g;
  let last = 0, m: RegExpExecArray | null, k = 0;
  while ((m = re.exec(src))) {
    if (m.index > last) out.push(src.slice(last, m.index));
    const [t] = m;
    const cls = m[1] ? "tk-c" : m[2] ? "tk-s" : m[3] ? "tk-d" : m[4] ? (KW.has(t) ? "tk-k" : "tk-f") : KW.has(t) ? "tk-k" : "";
    out.push(cls ? <span key={k++} className={cls}>{t}</span> : t);
    last = m.index + t.length;
  }
  out.push(src.slice(last));
  return out;
}

export function CodeTabs() {
  const [tab, setTab] = useState(0);
  const t = code.tabs[tab];
  return (
    <section className="sec pad" id="code">
      <div className="sec-head">
        <div className="sec-idx"><span className="sq" /><span><b>04</b> / Code</span></div>
        <Reveal><h2 className="h2">{code.title}</h2></Reveal>
      </div>
      <div className="code-grid">
        <div className="code-side" role="tablist" aria-label="Code samples">
          {code.tabs.map((c, i) => (
            <button key={c.id} role="tab" aria-selected={i === tab} className={`tab${i === tab ? " on" : ""}`} onClick={() => setTab(i)}>
              {c.label}
              <small>{c.caption}</small>
            </button>
          ))}
          <p className="note" style={{ marginTop: 8 }}>
            A complete working subnet (miner, validator, scoring, tests) is in examples/text-ops-subnet, and taowire init creates the same project for you.
          </p>
        </div>
        <Reveal className="term">
          <div className="term-bar">
            <span className="lights"><i /><i /><i /></span>{t.label}<span className="sp" />
            <span style={{ color: "var(--term-ink)" }}><CopyButton text={t.src} /></span>
          </div>
          <AnimatePresence mode="wait">
            <motion.pre key={t.id} initial={{ opacity: 0, x: 10 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -10 }} transition={{ duration: 0.22 }}>
              <code>{highlight(t.src)}</code>
            </motion.pre>
          </AnimatePresence>
        </Reveal>
      </div>
    </section>
  );
}

/* ---------- commands: a terminal that types each command ---------- */

const CYCLE_MS = 6500;

export function Commands() {
  const list = commands.list;
  const [i, setI] = useState(0);
  const [typed, setTyped] = useState(0);
  const [auto, setAuto] = useState(true);
  const ref = useRef<HTMLDivElement>(null);
  const inView = useInView(ref, { margin: "-80px" });
  const reduce = useReducedMotion();
  const c = list[i];
  const full = typed >= c.cmd.length;

  // Type the command one character at a time.
  useEffect(() => {
    if (!inView) return;
    if (reduce) { setTyped(c.cmd.length); return; }
    if (full) return;
    const t = setTimeout(() => setTyped((n) => n + 1), 28);
    return () => clearTimeout(t);
  }, [typed, full, inView, c.cmd.length, reduce]);

  // Move on to the next command until the visitor picks one.
  useEffect(() => {
    if (!auto || !inView || !full) return;
    const t = setTimeout(() => { setI((n) => (n + 1) % list.length); setTyped(0); }, CYCLE_MS);
    return () => clearTimeout(t);
  }, [auto, inView, full, list.length]);

  const pick = (n: number) => { setAuto(false); setI(n); setTyped(0); };

  return (
    <section className="sec pad" id="commands">
      <div className="sec-head">
        <div className="sec-idx"><span className="sq" /><span><b>05</b> / Commands</span></div>
        <Reveal>
          <h2 className="h2">{commands.title}</h2>
          <p className="lead">{commands.body}</p>
        </Reveal>
      </div>
      <div className="cmd-grid" ref={ref}>
        <div className="cmd-list" role="tablist" aria-label="taowire commands">
          {list.map((x, n) => (
            <button key={x.title} role="tab" aria-selected={n === i} className={n === i ? "on" : ""} onClick={() => pick(n)}>
              <span><span className="p">taowire</span>{x.title}</span>
              {n === i && auto && full && (
                <motion.span className="bar" initial={{ width: 0 }} animate={{ width: "100%" }} transition={{ duration: CYCLE_MS / 1000, ease: "linear" }} />
              )}
            </button>
          ))}
        </div>
        <div className="term">
          <div className="term-bar">
            <span className="lights"><i /><i /><i /></span>~/my-subnet — bash<span className="sp" />
            <span style={{ color: "var(--term-ink)" }}><CopyButton text={c.cmd} /></span>
          </div>
          <div className="screen" aria-live="polite">
            <div><span className="ps">$ </span>{c.cmd.slice(0, typed)}{!full && <span className="caret" />}</div>
            <AnimatePresence>
              {full && (
                <motion.div key={c.title} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.3 }}>
                  {c.lines.map((l, n) => (
                    <motion.div key={n} className="c" initial={{ opacity: 0, x: -6 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.1 + n * 0.12 }}>
                      # {l}
                    </motion.div>
                  ))}
                  {c.out && (
                    <motion.div style={{ marginTop: 12 }} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.2 + c.lines.length * 0.12 }}>
                      {c.out.map((o, n) => (
                        <Fragment key={n}>
                          {o.startsWith("$ ") ? <div><span className="ps">$ </span>{o.slice(2)}</div> : <div className="o">{o}</div>}
                        </Fragment>
                      ))}
                    </motion.div>
                  )}
                  <div style={{ marginTop: 12 }}><span className="ps">$ </span><span className="caret" /></div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>
      </div>
    </section>
  );
}
