"use client";

import { AnimatePresence, motion, useReducedMotion } from "motion/react";
import { useState } from "react";
import { REPO, VERSION, compat, cta, doc, footer, install, mcp, migration, quickstart, tested, ticker, why } from "@/content/site";
import { Arrow, CopyButton, CountUp, LogoMark, PixelText, Reveal } from "./primitives";

function Head({ n, label, title, body }: { n: string; label: string; title: string; body?: string }) {
  return (
    <div className="sec-head">
      <div className="sec-idx"><span className="sq" /><span><b>{n}</b> / {label}</span></div>
      <Reveal>
        <h2 className="h2">{title}</h2>
        {body && <p className="lead">{body}</p>}
      </Reveal>
    </div>
  );
}

export function Ticker() {
  const items = [...ticker, ...ticker];
  return (
    <div className="ticker" aria-label="Features">
      <div className="ticker-track">
        {items.map((t, i) => <span key={i} aria-hidden={i >= ticker.length}>{t}</span>)}
      </div>
    </div>
  );
}

export function Why() {
  return (
    <section className="sec pad" id="why">
      <Head n="01" label="Why TaoWire" title={why.title} />
      <div className="why-grid">
        <Reveal className="why-copy">{why.body.map((p) => <p key={p}>{p}</p>)}</Reveal>
        <div className="why-table">
          <table className="table">
            <thead><tr><th>&nbsp;</th><th>Plain v11 SDK</th><th>v11 + TaoWire</th></tr></thead>
            <tbody>
              {why.rows.map(([a, b, c], i) => (
                <motion.tr key={a} initial={{ opacity: 0, x: 14 }} whileInView={{ opacity: 1, x: 0 }}
                  viewport={{ once: true, margin: "-30px" }} transition={{ delay: i * 0.05 }}>
                  <td>{a}</td><td>{b}</td><td><span className="yes" />{c}</td>
                </motion.tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  );
}

export function Install() {
  const [tab, setTab] = useState(0);
  const l = install.langs[tab];
  return (
    <section className="sec pad" id="install">
      <Head n="06" label="Install" title={install.title} body={install.note} />
      <Reveal className="inst">
        <div className="inst-tabs" role="tablist" aria-label="Language">
          {install.langs.map((x, i) => (
            <button key={x.id} role="tab" aria-selected={i === tab} onClick={() => setTab(i)}>
              {x.label}
              {i === tab && <motion.span layoutId="inst-ul" className="ul" transition={{ type: "spring", stiffness: 400, damping: 34 }} />}
            </button>
          ))}
        </div>
        <div className="inst-body">
          <AnimatePresence mode="wait">
            <motion.div key={l.id} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }} transition={{ duration: 0.2 }} style={{ display: "grid", gap: 18 }}>
              <div className="inst-cmd">
                <code><span className="ps">$</span>{l.cmd}</code>
                <CopyButton text={l.cmd} />
              </div>
              <div className="inst-meta">
                <span><b style={{ fontWeight: 500 }}>{l.pkg}</b> · {l.what}</span>
                <a href={l.href}>Registry ↗</a>
              </div>
            </motion.div>
          </AnimatePresence>
          <p className="note">{install.extras}</p>
          <p className="note">
            Non-Python miners use a small local sidecar (taowire sidecar, loopback only, token-protected) for chain access. All four languages pass the same conformance vectors.
          </p>
        </div>
      </Reveal>
    </section>
  );
}

export function Quickstart() {
  return (
    <section className="sec pad" id="quickstart">
      <Head n="07" label="Quickstart" title={quickstart.title} body={quickstart.body} />
      <div className="steps">
        {quickstart.steps.map((s, i) => (
          <Reveal key={s.n} className="step" delay={(i % 3) * 0.08}>
            <div className="step-top"><span className="step-n">{s.n}</span><span className="step-t">{s.time}</span></div>
            <h4>{s.title}</h4>
            <pre><code>{s.cmd}</code></pre>
          </Reveal>
        ))}
      </div>
      <div style={{ marginTop: 22, display: "flex", gap: 12, flexWrap: "wrap" }}>
        <a className="btn primary cut" href={doc("docs/quickstart.md")}>FULL QUICKSTART <Arrow /></a>
        <span className="note" style={{ alignSelf: "center" }}>Machine times measured in docs/quickstart.md; add your own reading and typing time.</span>
      </div>
    </section>
  );
}

export function AgentsAndMigration() {
  const reduce = useReducedMotion();
  return (
    <section className="sec split" id="agents">
      <div>
        <div className="sec-idx" style={{ marginBottom: 18 }}><span className="sq" /><span><b>08</b> / AI agents (MCP)</span></div>
        <Reveal>
          <h2 className="h2">{mcp.title}</h2>
          <p className="lead">{mcp.body}</p>
        </Reveal>
        <Reveal className="inst-cmd" delay={0.1}>
          <code style={{ whiteSpace: "normal", wordBreak: "break-all" }}><span className="ps">$</span>{mcp.cmd}</code>
          <CopyButton text={mcp.cmd} />
        </Reveal>
        <div style={{ marginTop: 18 }}>
          <span className="note">Then ask:</span>
          {mcp.prompts.map((p) => <div key={p} className="prompt">{p}</div>)}
        </div>
        <div className="tools">
          {mcp.tools.map(([t, d]) => <div key={t}><code>{t}</code>{d}</div>)}
        </div>
        <p className="note" style={{ marginTop: 14 }}>{mcp.safe}</p>
      </div>

      <div id="migrate">
        <div className="sec-idx" style={{ marginBottom: 18 }}><span className="sq" /><span><b>09</b> / Migrating from v10</span></div>
        <Reveal>
          <h2 className="h2">{migration.title}</h2>
          <p className="lead">{migration.body}</p>
        </Reveal>
        <div className="flow" aria-hidden="true">
          <span className="node">v10 node</span>
          <span className="wire">
            {!reduce && [0, 1, 2].map((k) => (
              <motion.i key={k} animate={{ left: ["-10%", "110%"] }} transition={{ duration: 2.2, repeat: Infinity, delay: k * 0.73, ease: "linear" }} />
            ))}
          </span>
          <span className="node v11">TaoWire v11</span>
        </div>
        <div className="mig-points">
          {migration.points.map(([k, v], i) => (
            <Reveal key={k} delay={i * 0.06}><b>{k}</b><p>{v}</p></Reveal>
          ))}
        </div>
        <div className="inst-cmd" style={{ marginTop: 22, display: "block" }}>
          <code style={{ display: "block" }}><span className="ps">$</span>taowire migrate scan  path/to/your-subnet</code>
          <code style={{ display: "block" }}><span className="ps">$</span>taowire migrate apply path/to/your-subnet</code>
        </div>
        <div style={{ marginTop: 18 }}>
          <a className="btn ghost" href={doc("docs/migration-from-v10.md")}>MIGRATION GUIDE <Arrow /></a>
        </div>
      </div>
    </section>
  );
}

export function Tested() {
  return (
    <section className="sec pad" id="tested">
      <Head n="10" label="Tested" title={tested.title} body={tested.body} />
      <div className="stats-grid">
        {tested.stats.map((s, i) => (
          <Reveal key={s.label} delay={(i % 4) * 0.07}>
            <b><CountUp value={s.value} />{s.suffix && <small>{s.suffix}</small>}</b>
            <span className="lbl">{s.label}</span>
            <em>{s.note}</em>
          </Reveal>
        ))}
      </div>
      <div className="tested-foot">
        <p>{tested.fuzz}</p>
        <p className="warn">{tested.notYet}</p>
      </div>
      <div className="compat" style={{ marginTop: 34 }}>
        <span className="note">Compatibility</span>
        <table className="table" style={{ marginTop: 10 }}>
          <thead><tr>{compat.head.map((h) => <th key={h}>{h}</th>)}</tr></thead>
          <tbody><tr>{compat.row.map((c) => <td key={c}>{c}</td>)}</tr></tbody>
        </table>
      </div>
    </section>
  );
}

export function Cta() {
  const reduce = useReducedMotion();
  return (
    <section className="sec cta">
      <div>
        <Reveal className="cta-text">
          <span className="tri" />{cta.line1}<br /><mark>{cta.line2}</mark>
        </Reveal>
      </div>
      <div className="cta-plus">
        <motion.svg viewBox="0 0 84 74" aria-hidden="true">
          <motion.path d="M38 1.5h14a3 3 0 0 1 3 3V19a3 3 0 0 0 3 3h7a3 3 0 0 1 3 3v2a3 3 0 0 0 3 3h7a3 3 0 0 1 3 3v8a3 3 0 0 1-3 3H55a3 3 0 0 0-3 3v9a3 3 0 0 1-3 3h-6a3 3 0 0 0-3 3v7a3 3 0 0 1-3 3h-7a3 3 0 0 1-3-3V50a3 3 0 0 0-3-3H4.5a3 3 0 0 1-3-3v-6a3 3 0 0 1 3-3H32a3 3 0 0 0 3-3V4.5a3 3 0 0 1 3-3Z"
            fill="none" stroke="#9a9a9a" strokeWidth="1"
            initial={reduce ? false : { pathLength: 0 }} whileInView={{ pathLength: 1 }} viewport={{ once: true }}
            transition={{ duration: 2, ease: "easeInOut" }} />
        </motion.svg>
      </div>
      <div className="cta-btns">
        <a className="btn primary cut" href={cta.primary.href}>{cta.primary.label} <Arrow /></a>
        <a className="btn ghost" href={cta.secondary.href}>{cta.secondary.label} <Arrow /></a>
      </div>
    </section>
  );
}

export function Footer() {
  return (
    <footer className="foot">
      <div className="wrap">
        <div>
          <a className="logo" href="#top" aria-label="TaoWire home">
            <LogoMark size={32} />
            <span className="logo-text"><PixelText text="TAOWIRE" height={15} animated={false} /></span>
          </a>
          <p>Secure networking for Bittensor v11 subnets, and the way across from v10.</p>
          <p>{footer.feedback}</p>
          <div style={{ display: "flex", gap: 10, marginTop: 16, flexWrap: "wrap" }}>
            <a className="chip" href={`${REPO}/issues`}>Open an issue</a>
            <a className="chip" href={`${REPO}/security/advisories/new`}>Report a vulnerability</a>
          </div>
        </div>
        {footer.cols.map((c) => (
          <div key={c.title}>
            <h5>{c.title}</h5>
            <ul>{c.links.map(([l, p]) => <li key={p}><a href={doc(p)}>{l}</a></li>)}</ul>
          </div>
        ))}
      </div>
      <div className="foot-bottom">
        <div className="wrap" style={{ border: 0 }}>
          <span>TaoWire {VERSION} · Apache-2.0</span>
          <span>bittensor &gt;=11.3,&lt;12</span>
        </div>
      </div>
    </footer>
  );
}
