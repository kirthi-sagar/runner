import Link from "next/link";
import { ArrowUpRight, Github } from "lucide-react";

const groups = [
  { title: "Explore", links: [["Solutions", "/solutions"], ["Pricing", "/pricing"], ["Interactive demo", "/demo"], ["About", "/about"]] },
  { title: "Learn", links: [["Documentation", "/docs"], ["Blog & guides", "/blog"], ["FAQ", "/faq"], ["GitHub repository", "https://github.com/kirthi-sagar/runner"]] },
  { title: "Trust", links: [["Security", "/security"], ["Privacy", "/privacy"], ["Terms", "/terms"], ["Sub-processors", "/sub-processors"]] },
];

export function SiteHeader() {
  return <header className="site-header"><div className="nav-wrap"><Link className="brand" href="/" aria-label="runner home"><span className="brand-mark">r</span><span>runner</span><span className="version">v0.4.0</span></Link><nav className="main-nav" aria-label="Main navigation"><Link href="/solutions">Solutions</Link><Link href="/pricing">Pricing</Link><Link href="/docs">Docs</Link><div className="nav-menu"><Link href="/blog">Resources <span aria-hidden="true">⌄</span></Link><div className="nav-dropdown"><Link href="/blog">Blog & guides</Link><Link href="/faq">FAQ</Link><Link href="/security">Security</Link></div></div><Link href="/demo">Demo</Link></nav><div className="nav-actions"><Link className="sign-in" href="/login">Sign in</Link><Link className="button button-small" href="/schedule">Schedule a call <ArrowUpRight aria-hidden="true" /></Link></div><details className="mobile-nav"><summary aria-label="Open navigation">Menu</summary><nav aria-label="Mobile navigation"><Link href="/solutions">Solutions</Link><Link href="/pricing">Pricing</Link><Link href="/docs">Docs</Link><Link href="/blog">Resources</Link><Link href="/demo">Demo</Link><Link href="/login">Sign in</Link><Link href="/schedule">Schedule a call</Link></nav></details></div></header>;
}

export function SiteFooter() {
  return <footer className="site-footer"><div className="footer-top"><div className="footer-brand"><Link className="brand" href="/"><span className="brand-mark">r</span><span>runner</span></Link><p>Keep your workstation responsive.<br />Put your own compute to work.</p><a className="repo-link" href="https://github.com/kirthi-sagar/runner"><Github aria-hidden="true" /> Open-source project <ArrowUpRight aria-hidden="true" /></a></div><div className="footer-groups">{groups.map((group) => <div className="footer-group" key={group.title}><h2>{group.title}</h2>{group.links.map(([label, href]) => <Link key={label} href={href}>{label}</Link>)}</div>)}</div></div><div className="footer-bottom"><span>© runner. Open source software.</span><span>Built around your machines, your keys, your control.</span></div></footer>;
}
