import Link from "next/link"

export function SiteFooter() {
  return (
    <footer className="footer">
      <div className="container footer-main">
        <div className="footer-about">
          <Link className="brand" href="/"><span className="brand-mark">r</span><span>runner</span></Link>
          <p>Open-source tools for background CI that respects the computer you work on.</p>
        </div>
        <div><h4>Product</h4><div className="footer-links"><Link href="/solutions">Solutions</Link><Link href="/pricing">Pricing</Link><Link href="/demo">Interactive demo</Link><Link href="/schedule">Schedule a call</Link></div></div>
        <div><h4>Documentation</h4><div className="footer-links"><Link href="/docs">Developer docs</Link><Link href="/faq">FAQ</Link><Link href="/blog">Engineering notes</Link><Link href="/security">Security architecture</Link></div></div>
        <div><h4>Security &amp; legal</h4><div className="footer-links"><Link href="/privacy">Privacy</Link><Link href="/terms">Terms</Link><Link href="/dpa">Data processing</Link><Link href="/sub-processors">Sub-processors</Link></div></div>
      </div>
      <div className="container footer-bottom"><span>© runner. Open source software.</span><span>Built for teams that want CI to stay in the background.</span></div>
    </footer>
  )
}
