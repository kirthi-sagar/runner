import Link from "next/link"
import { Activity, ArrowDownRight, ArrowRight, Bot, Check, Cloud, Cpu, LockKeyhole, ShieldCheck, Zap } from "lucide-react"

const features = [
  { icon: Cpu, title: "Zero-freeze resource governor", body: "Protect your laptop or desktop during heavy builds. runner gives foreground apps like your browser and IDE priority.", href: "/solutions" },
  { icon: ShieldCheck, title: "Bring your own compute", body: "Pool workstations, spare office laptops, and trusted peers over encrypted WireGuard tunnels. No compute markup.", href: "/docs" },
  { icon: Cloud, title: "Bring your own cloud keys", body: "Connect DigitalOcean or Render credentials you control. Idle cloud instances scale down after five minutes.", href: "/pricing" },
  { icon: Bot, title: "Built for coding agents", body: "11 built-in MCP tools let terminal agents inspect capacity, coordinate work, and run tests safely.", href: "/docs" },
]

export default function HomePage() {
  return (
    <main>
      <section className="hero">
        <div className="hero-grid-lines" />
        <div className="container hero-grid">
          <div className="hero-copy">
            <span className="eyebrow"><i className="eyebrow-dot" /> Open-source runner supervisor</span>
            <h1>Cut Cloud CI Bills by 80%. <em>Never Freeze Your Workstations Again.</em></h1>
            <p className="lead">Run unlimited background GitHub Actions and AI coding tasks across your local PCs, idle office machines, and cloud credits—without slowing down your computer.</p>
            <div className="hero-actions"><Link className="button button-primary" href="/docs">Get started free <ArrowRight size={16} /></Link><Link className="button button-secondary" href="/schedule">Schedule a consultation</Link></div>
            <div className="trust-note"><Check size={15} /> Free and open source · Self-hosted · Bring your own compute</div>
          </div>
          <div className="hero-art" aria-label="Illustration of runner monitoring background tasks">
            <div className="monitor">
              <div className="monitor-top"><span className="monitor-lights"><i/><i/><i/></span><span>runner / host monitor</span><span className="monitor-status"><i/> RESPONSIVE</span></div>
              <div className="monitor-body">
                <div className="monitor-row"><span>Foreground apps</span><div className="mini-bar"><i style={{width:"91%"}} /></div><strong>priority</strong></div>
                <div className="monitor-row"><span>Build workers</span><div className="mini-bar"><i style={{width:"37%",background:"#76bd9a"}} /></div><strong>throttled</strong></div>
                <div className="monitor-row"><span>CPU pressure</span><div className="mini-bar"><i style={{width:"24%",background:"#76bd9a"}} /></div><strong>low</strong></div>
                <div className="monitor-row"><span>Memory headroom</span><div className="mini-bar"><i style={{width:"68%"}} /></div><strong>available</strong></div>
              </div>
              <div className="monitor-footer"><span>Background work is yielding to your desktop</span><b>GOVERNOR ACTIVE</b></div>
            </div>
            <div className="float-card float-card-top"><span className="float-icon"><Activity size={16}/></span><span><small>Host state</small><b>Responsive</b></span></div>
            <div className="float-card float-card-bottom"><span className="float-icon"><Zap size={16}/></span><span><small>Compute model</small><b>Your hardware, your keys</b></span></div>
          </div>
        </div>
      </section>

      <section className="stat-strip"><div className="container stat-strip-inner">
        <div className="stat-item"><strong>80%</strong><span>potential cloud CI savings*</span></div><i className="stat-divider" />
        <div className="stat-item"><strong>$0</strong><span>compute markup</span></div><i className="stat-divider" />
        <div className="stat-item"><strong>11</strong><span>built-in MCP agent tools</span></div><i className="stat-divider" />
        <div className="stat-item"><strong>5 min</strong><span>idle scale-to-zero window</span></div>
      </div></section>

      <section className="section"><div className="container">
        <div className="section-heading"><span className="eyebrow">Compute should work for you</span><h2>Keep the work moving.<br/>Keep your workstation usable.</h2><p>runner puts an intelligent governor between background jobs and the machine you use every day.</p></div>
        <div className="card-grid">{features.map(({icon:Icon,title,body,href}) => <article className="feature-card" key={title}><span className="feature-icon"><Icon size={20}/></span><h3>{title}</h3><p>{body}</p><Link className="feature-link" href={href}>Learn more <ArrowRight size={13}/></Link></article>)}</div>
        <p style={{marginTop:16,color:"var(--faint)",fontSize:11}}>*Savings depend on workload and available BYOC capacity; the 80% figure is a target, not a guaranteed result.</p>
      </div></section>

      <section className="section" style={{background:"var(--wash)"}}><div className="container split-section">
        <div><span className="eyebrow">One supervisor, your whole fleet</span><h2>Local machines.<br/>Cloud credits.<br/>One clear view.</h2><p className="lead" style={{fontSize:16}}>Share idle capacity across your own computers, then burst to cloud providers using credentials and budgets you control.</p><ul className="check-list"><li><Check/>Keep execution close to your source code</li><li><Check/>Use your own DigitalOcean or Render credits</li><li><Check/>Scale idle cloud workers down automatically</li></ul><Link className="feature-link" href="/solutions">Explore solutions <ArrowRight size={14}/></Link></div>
        <div className="code-panel"><div className="code-top"><span>runner / deployment model</span><span>BYOC + BYOK</span></div><div className="code-body"><div><span className="gray"># your machines</span></div><div><span className="blue">local:</span> laptop, desktop, office nodes</div><div><span className="blue">mesh:</span> trusted peers over WireGuard</div><div><span className="blue">cloud:</span> your DO / Render credentials</div><br/><div><span className="green">✓</span> compute billed by your provider</div><div><span className="green">✓</span> no runner compute surcharge</div><div><span className="green">✓</span> scale to zero after idle window</div></div></div>
      </div></section>

      <section className="section"><div className="container split-section">
        <div className="split-panel"><span className="eyebrow">Try the interactive demo</span><h2 style={{fontSize:32}}>See the governor respond to a heavy build.</h2><p style={{color:"var(--muted)"}}>Explore an illustrative monitor simulation before connecting real machines.</p><Link className="button button-primary" href="/demo">Open the demo <ArrowRight size={15}/></Link></div>
        <div><h3>Designed for a calmer CI workflow</h3><p style={{color:"var(--muted)"}}>Standard CI runners can consume the machine they share with your editor, browser, and AI coding tools. runner is built to keep background work in the background.</p><Link className="feature-link" href="/about">Why we built runner <ArrowDownRight size={14}/></Link></div>
      </div></section>

      <section className="section-tight"><div className="container"><div className="cta-band"><span className="eyebrow" style={{color:"#c9d7ff"}}>Start with the community tier</span><h2>Put idle compute to work.</h2><p>Free forever for individual developers and open-source maintainers. Your machines, your cloud account, your rules.</p><div className="hero-actions" style={{margin:0}}><Link className="button button-light" href="/docs">Get started free <ArrowRight size={15}/></Link><Link className="button" style={{borderColor:"#97abe6",color:"white"}} href="/pricing">Compare plans</Link></div></div></div></section>
    </main>
  )
}
