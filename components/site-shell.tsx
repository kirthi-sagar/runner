"use client"

import { useState } from "react"
import Link from "next/link"
import { ArrowUpRight, Menu } from "lucide-react"

const productLinks = [
  ["Solutions", "/solutions"],
  ["Pricing", "/pricing"],
  ["Docs", "/docs"],
  ["Demo", "/demo"],
] as const

export function SiteHeader() {
  const [menuOpen, setMenuOpen] = useState(false)
  return (
    <header className="site-header">
      <div className="header-inner">
        <Link className="brand" href="/" aria-label="runner home">
          <span className="brand-mark">r</span><span>runner</span><span className="version">v0.4.0</span>
        </Link>
        <button className="mobile-menu" aria-label={menuOpen ? "Close navigation" : "Open navigation"} aria-expanded={menuOpen} type="button" onClick={() => setMenuOpen((open) => !open)}><Menu size={18} /></button>
        <nav className={`primary-nav${menuOpen ? " mobile-nav-open" : ""}`} aria-label="Main navigation">
          {productLinks.map(([label, href]) => <Link key={href} href={href}>{label}</Link>)}
          <details className="resources">
            <summary>Resources</summary>
            <div className="resource-menu">
              <Link href="/blog">Blog</Link><Link href="/faq">FAQ</Link><Link href="/security">Security</Link>
            </div>
          </details>
          <Link href="/about">About</Link>
        </nav>
        <div className="header-actions">
          <Link className="header-login" href="/login">Sign in</Link>
          <Link className="button button-primary button-small" href="/schedule">Schedule a call <ArrowUpRight size={14} /></Link>
        </div>
      </div>
    </header>
  )
}

