import Link from "next/link"
import { ArrowUpRight, Menu } from "lucide-react"

const links = [["Solutions", "/solutions"], ["Pricing", "/pricing"], ["Docs", "/docs"], ["Blog", "/blog"], ["Demo", "/demo"]]
export function SiteHeader() {
  return <header className="site-header"><div className="nav-wrap"><Link className="brand" href="/" aria-label="runner home"><span className="brand-mark">r</span><span>runner</span><span className="version">v0.4.0</span></Link><nav className="desktop-nav" aria-label="Main navigation">{links.map(([name, href]) => <Link key={href} href={href}>{name}</Link>)}<details className="nav-menu"><summary>Resources</summary><div className="menu-panel"><Link href="/faq">FAQ</Link><Link href="/security">Security</Link><Link href="/about">About</Link></div></details></nav><div className="nav-actions"><Link className="signin" href="/login">Sign in</Link><Link className="button button-small" href="/schedule">Schedule a call <ArrowUpRight size={16} /></Link><details className="mobile-menu"><summary aria-label="Open navigation"><Menu size={21} /></summary><div className="mobile-panel">{links.map(([name, href]) => <Link key={href} href={href}>{name}</Link>)}<Link href="/faq">FAQ</Link><Link href="/security">Security</Link><Link href="/login">Sign in</Link></div></details></div></div></header>
}
