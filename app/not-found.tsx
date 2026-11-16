import Link from "next/link"

export default function NotFound() {
  return <main className="page-hero"><div className="container"><span className="eyebrow">404 · Page not found</span><h1 style={{fontSize:54,marginTop:18}}>This page isn&apos;t here.</h1><p className="lead">The link may be outdated, or the page may have moved.</p><Link className="button button-primary" href="/">Return to runner home</Link></div></main>
}
