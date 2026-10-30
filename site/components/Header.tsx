"use client";

import { AnimatePresence, motion } from "motion/react";
import { useEffect, useState } from "react";
import { REPO, VERSION, doc, nav } from "@/content/site";
import { LogoMark, PixelText } from "./primitives";

export default function Header() {
  const [active, setActive] = useState<string>("");
  const [open, setOpen] = useState(false);

  // Highlight the nav entry of the section in view.
  useEffect(() => {
    const els = nav.map((n) => document.getElementById(n.id)).filter((e): e is HTMLElement => !!e);
    const io = new IntersectionObserver(
      (entries) => entries.forEach((e) => e.isIntersecting && setActive(e.target.id)),
      { rootMargin: "-45% 0px -50% 0px" },
    );
    els.forEach((e) => io.observe(e));
    return () => io.disconnect();
  }, []);

  return (
    <header className="hdr">
      <div className="wrap">
        <div className="hdr-cell">
          <a className="logo" href="#top" aria-label="TaoWire home">
            <LogoMark size={32} />
            <span className="logo-text"><PixelText text="TAOWIRE" height={15} animated={false} /></span>
          </a>
          <span className="ver">v{VERSION}</span>
        </div>
        <div className="hdr-cell hdr-mid">
          <nav className="nav" aria-label="Sections">
            {nav.map((n) => (
              <a key={n.id} href={`#${n.id}`} aria-current={active === n.id ? "true" : undefined}>
                {active === n.id && (
                  <>
                    <motion.span layoutId="br-tl" className="br tl" transition={{ type: "spring", stiffness: 400, damping: 32 }} />
                    <motion.span layoutId="br-br" className="br brr" transition={{ type: "spring", stiffness: 400, damping: 32 }} />
                  </>
                )}
                {n.label}
              </a>
            ))}
          </nav>
        </div>
        <div className="hdr-cell hdr-right">
          <a className="gh" href={REPO}>
            <span className="dots"><i /><i /><i /><i /></span>
            <span className="gh-label">GitHub</span>
          </a>
          <a className="btn primary cut" style={{ height: 36, padding: "0 16px", fontSize: 11 }} href={doc("docs/quickstart.md")}>
            GET STARTED
          </a>
          <button className="burger" aria-label="Menu" aria-expanded={open} onClick={() => setOpen((o) => !o)}>
            <svg width="14" height="10" viewBox="0 0 14 10" aria-hidden="true">
              <path d={open ? "M2 1l10 8M12 1 2 9" : "M0 1h14M0 5h14M0 9h14"} stroke="#161616" strokeWidth="1.6" />
            </svg>
          </button>
        </div>
      </div>
      <AnimatePresence>
        {open && (
          <motion.nav className="mnav" initial={{ height: 0, opacity: 0 }} animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }} style={{ overflow: "hidden" }}>
            {nav.map((n) => (
              <a key={n.id} href={`#${n.id}`} onClick={() => setOpen(false)}>{n.label}</a>
            ))}
            <a href={REPO}>GitHub ↗</a>
          </motion.nav>
        )}
      </AnimatePresence>
    </header>
  );
}
