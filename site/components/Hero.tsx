"use client";

import { motion } from "motion/react";
import { REPO, hero, modules } from "@/content/site";
import { Arrow, CopyButton, CountUp, Iso, PixelText } from "./primitives";

function StatValue({ value, format }: { value: number; format: string }) {
  if (format === "ms") return <CountUp value={value} decimals={2} suffix=" ms" />;
  if (format === "s") return <CountUp value={value} decimals={2} suffix=" s" />;
  return <CountUp value={value} />;
}

export default function Hero() {
  const f = hero.featured;
  return (
    <section className="sec" id="top">
      <div className="hero-title">
        <div><h1 aria-label="TaoWire"><PixelText text="TAO_" blinkLast /></h1></div>
        <div aria-hidden="true"><PixelText text="WIRE" delay={0.35} /></div>
      </div>

      <div className="hero-grid">
        <div className="hero-left">
          <motion.p className="hero-eyebrow" initial={{ opacity: 0, x: -12 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.6 }}>
            <i />{hero.eyebrow}
          </motion.p>
          <motion.p className="hero-lead" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.8 }}>
            {hero.lead}
          </motion.p>
          <div className="hero-count">
            Modules
            <div><PixelText text={String(modules.length).padStart(2, "0")} height={34} delay={0.9} /></div>
          </div>
        </div>

        <div className="hero-mid">
          <div className="isobox">
            <span className="cb" style={{ left: 10, top: 10, borderRight: 0, borderBottom: 0 }} />
            <span className="cb" style={{ right: 10, top: 10, borderLeft: 0, borderBottom: 0 }} />
            <span className="cb" style={{ left: 10, bottom: 10, borderRight: 0, borderTop: 0 }} />
            <span className="cb" style={{ right: 10, bottom: 10, borderLeft: 0, borderTop: 0 }} />
            <Iso />
          </div>
          <div className="hero-install">
            Install the alpha
            <code>{hero.installCmd}</code>
            <span><CopyButton text={hero.installCmd} /></span>
          </div>
        </div>

        <motion.article className="feat" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.5, duration: 0.7 }}>
          <div className="feat-tags">
            {f.tags.map((t, i) => <span key={t} className={`chip${i === 0 ? " or" : ""}`}>{t}</span>)}
          </div>
          <div className="feat-body">
            <div className="feat-logo">
              <motion.svg width="40" height="40" viewBox="0 0 28 28" aria-hidden="true"
                animate={{ rotate: 360 }} transition={{ duration: 14, repeat: Infinity, ease: "linear" }}>
                <circle cx="14" cy="14" r="10.5" fill="none" stroke="#161616" strokeWidth="4.5" strokeDasharray="12.5 4" />
              </motion.svg>
              {f.title}
            </div>
            <p>{f.body}</p>
          </div>
          <div className="feat-stats">
            {f.stats.map((s) => (
              <div className="stat" key={s.label}>
                <b><StatValue value={s.value} format={s.format} /></b>
                <span className="lbl">{s.label}</span>
              </div>
            ))}
            <a className="arrow-cell" href={REPO} aria-label="TaoWire on GitHub"><Arrow size={14} /></a>
          </div>
        </motion.article>
      </div>

      <div className="alpha"><span className="chip or">ALPHA</span>{hero.alpha}</div>
    </section>
  );
}
