import type { Metadata } from "next"
import Link from "next/link"
import { notFound } from "next/navigation"
import { ArrowRight, BookOpen, Check, Cpu, ShieldCheck } from "lucide-react"
import DemoSimulator from "@/components/demo-simulator"
import ManagementPreview from "@/components/management-preview"

type PageInfo = { title: string; description: string; eyebrow: string; cards?: { title: string; description: string }[] }

const pages: Record<string, PageInfo> = {
  solutions: {
    eyebrow: "Solutions",
    title: "One supervisor for your CI fleet.",
    description: "Give foreground apps the compute they need, route background work across your own machines, and keep cloud costs in your control.",
    cards: [
      { title: "Independent developers & AI coders", description: "Run agent-driven commit and test cycles in the background while the resource governor prioritizes the browser, editor, and other interactive work." },
      { title: "Engineering teams & startups", description: "Put eligible idle workstations and LAN machines to work before bursting to cloud capacity. The 80% figure is a target, not a measured or guaranteed saving." },
      { title: "Security-conscious organizations", description: "Operate the control plane and workers in infrastructure you manage. Review isolation, network egress, and workload placement against your own threat model." },
    ],
  },
  about: {
    eyebrow: "About runner",
    title: "Background work should stay in the background.",
    description: "runner is an open-source project exploring how to run GitHub Actions workloads and AI coding jobs on developer-owned compute. It grew from a practical problem: high-velocity agent commit and test loops can make a workstation difficult to use. The project favors a focused host supervisor over requiring a Kubernetes runner controller.",
    cards: [
      { title: "Keep the workstation usable", description: "The Linux governor uses pressure signals and cgroup controls to reduce background CPU share under load, without freezing active tests." },
      { title: "Use compute you control", description: "Connect your own workstations, trusted LAN peers, and optional cloud accounts. Provider fees remain your responsibility." },
      { title: "Build in the open", description: "The repository contains the code and architecture notes. Review the current implementation and its platform requirements before deploying it." },
    ],
  },
  demo: {
    eyebrow: "Interactive demo",
    title: "See a background build respond to system pressure.",
    description: "Try an illustrative governor simulation. It shows a conceptual response path—not a benchmark or measurement from your computer.",
    cards: [],
  },
  schedule: {
    eyebrow: "Talk to the team",
    title: "Find the right setup for your fleet.",
    description: "Book time to discuss your CI workload, machine pool, and cloud capacity plans.",
    cards: [],
  },
  settings: {
    eyebrow: "Settings",
    title: "Settings need a live fleet connection.",
    description: "Connect an authenticated control plane to manage cloud spend, resource policy, and provider integrations.",
    cards: [{ title: "No changes made", description: "This preview cannot read or update fleet settings." }],
  },
  pricing: {
    eyebrow: "Pricing",
    title: "Free to start. Clear when you grow.",
    description: "The runner software is open source. You supply the compute and cloud provider accounts; runner does not add a compute markup.",
    cards: [
      { title: "Community", description: "Self-hosted, open source · BYOC and BYOK · Linux resource governor · Unprivileged job sandboxing where host support is available · MCP tools · LAN discovery · Optional five-minute cloud idle scale-down. Cloud provider charges are billed directly by your provider." },
      { title: "Enterprise", description: "Centralized fleet control · OIDC / SSO configuration · Custom cloud driver setup · Architecture consultation · Tamper-evident audit trail. Availability depends on your deployment and configuration." },
    ],
  },
  blog: {
    eyebrow: "Engineering notes",
    title: "Ideas for a better background-work loop.",
    description: "Product updates, implementation notes, and practical guidance for running CI on developer-owned machines.",
    cards: [
      { title: "Why builds should yield to your editor", description: "How to think about CPU pressure and foreground responsiveness on shared developer machines." },
      { title: "A practical guide to BYOC runners", description: "Understand the tradeoffs between local, pooled, and cloud-backed compute." },
      { title: "Giving coding agents a safer fleet interface", description: "What a focused set of MCP tools can do for background task coordination." },
    ],
  },
  docs: {
    eyebrow: "Developer documentation",
    title: "Run runner on your own terms.",
    description: "Start with the self-hosted control plane, connect a machine, and add capacity when your team needs it.",
    cards: [
      { title: "Developer & CI engineer track", description: "Install the self-hosted runner binary, connect a GitHub Actions workflow, verify the host with runner doctor, and use runner status or runner top to inspect resource pressure." },
      { title: "Team lead & administrator track", description: "Configure governor thresholds and machine capacity, enroll fleet nodes, set cloud provider credentials and spend ceilings, and configure OIDC when your deployment requires SSO." },
      { title: "Agent integration", description: "Run runner mcp over stdio and expose only the tools your terminal agent needs. The CLI and MCP server are local operator interfaces." },
      { title: "Cloud and mesh operations", description: "Connect optional DigitalOcean or Render capacity, review the idle scale-down policy, and explicitly approve trusted peers and donor resource caps." },
    ],
  },
  security: {
    eyebrow: "Security",
    title: "Your infrastructure. Your boundaries.",
    description: "runner is designed around self-hosting and operator-controlled compute. Review your deployment and network configuration before enrolling production machines.",
    cards: [
      { title: "Unprivileged process isolation", description: "The process sandbox uses unprivileged user, mount, and PID namespaces with an ephemeral tmpfs workspace where the host permits user namespaces. On restricted hosts, the documented fallback is governed direct execution; do not assume namespace isolation." },
      { title: "Restricted sandbox egress", description: "The sandbox network filter blocks RFC 1918, link-local metadata, and IPv6 unique-local destinations; the documented policy allows DNS and public HTTPS. Confirm the selected sandbox driver and host enforcement before production." },
      { title: "Scoped machine and job credentials", description: "Runner enrollment issues a per-node bearer token. GitHub Actions jobs use just-in-time runner configuration. Protect enrollment tokens, keep the control plane private, and re-enroll a node when its token must be rotated." },
      { title: "Tamper-evident audit trail", description: "The enterprise audit module writes JSONL entries linked by SHA-256 and can verify the chain. This is not a third-party certification or a substitute for your organization's audit controls." },
    ],
  },
  faq: {
    eyebrow: "FAQ",
    title: "A few things worth knowing.",
    description: "Answers about the model, costs, and what to expect before connecting a machine.",
    cards: [
      { title: "Why is runner free for individual developers?", description: "The community tier is open source and self-hosted. You bring the machines and any provider accounts, so there is no runner compute resale fee." },
      { title: "Do you mark up our cloud compute costs?", description: "No. Optional DigitalOcean or Render capacity uses credentials you configure in your own control plane. Your provider bills you directly." },
      { title: "Why can normal CI make a computer feel frozen?", description: "Background jobs can compete with interactive apps for CPU and memory. runner's Linux governor reads pressure signals and adjusts cgroup CPU weight; the impact varies by workload and host." },
      { title: "Does runner read our proprietary source code?", description: "Jobs execute on the workers you configure. Choose trusted, isolated hosts and review where your workflow checks out source; do not send private repositories to an untrusted peer." },
      { title: "What does the demo show?", description: "The interactive demo is an illustrative monitor simulation, not a benchmark or a live reading from your hardware." },
      { title: "Is sign-in enabled on this preview?", description: "No. Authentication was intentionally skipped. Do not enter credentials here; account persistence is not configured." },
    ],
  },
  privacy: {
    eyebrow: "Legal",
    title: "Privacy overview.",
    description: "This is a starter privacy page for the self-hosted runner software. Review and replace it with terms that reflect your actual deployment and data practices before publication.",
    cards: [
      { title: "Essential cookies only", description: "These website pages do not install advertising pixels or analytics tags and do not sell personal data. The control-plane OIDC flow may set an essential session cookie when enabled by its operator." },
      { title: "Self-hosted operation", description: "When you operate runner yourself, you control the server, logs, and connected infrastructure. Workflow execution occurs on the workers you configure; your deployment determines where source and artifacts travel." },
      { title: "Third-party booking", description: "The schedule page embeds Cal.com. If you use it, Cal.com processes data under its own terms and privacy policy." },
    ],
  },
  terms: {
    eyebrow: "Legal",
    title: "Terms of use.",
    description: "This placeholder is not legal advice or production-ready terms. Have counsel prepare terms for the entity, service, and jurisdictions that apply before launch.",
    cards: [
      { title: "Software license", description: "Review the license included with the source repository for the applicable open-source terms." },
      { title: "Service terms", description: "Define service availability, acceptable use, support scope, liability, and termination with qualified counsel." },
    ],
  },
  dpa: {
    eyebrow: "Legal",
    title: "Data processing addendum.",
    description: "A data processing addendum must match the actual service, subprocessors, and processing instructions. This page is a placeholder and is not a binding DPA.",
    cards: [{ title: "Data minimization and local compute", description: "A final DPA must describe your actual deployment, subprocessors, retention, and processing instructions. The runner project is self-hosted; operators select the workers and optional cloud providers used for jobs." }],
  },
  "sub-processors": {
    eyebrow: "Legal",
    title: "Sub-processor information.",
    description: "The self-hosted runner software does not imply a hosted processing service. List any providers used by your own deployment here before making production privacy commitments.",
    cards: [
      { title: "Cal.com", description: "Used for the optional scheduling embed on this website. Booking data is subject to Cal.com’s own privacy and service terms." },
      { title: "Hosting infrastructure", description: "The website is built for deployment on Vercel. Document the hosting region, logs, and retention settings of the production deployment." },
      { title: "Operator-configured cloud providers", description: "DigitalOcean and Render are optional providers configured directly by each operator. They bill the operator and are not resold by runner." },
    ],
  },
  login: { eyebrow: "Account access", title: "Sign-in is not enabled on this preview.", description: "Authentication was intentionally skipped. This page will not accept or store passwords. Configure a secure authentication service before enabling account access.", cards: [{ title: "Preview safety", description: "No account was created, and no credentials are being collected. Return to the public site or review the self-hosted setup guide." }] },
  register: { eyebrow: "Create an account", title: "Account creation is not enabled yet.", description: "This preview does not have authentication or user-data storage configured. No registration details should be entered here.", cards: [{ title: "Continue without an account", description: "The open-source control plane can be self-hosted. See the setup guide for the current project workflow." }] },
  "forgot-password": { eyebrow: "Account access", title: "Password recovery is unavailable.", description: "There is no authentication provider connected to this preview, so password reset is not active.", cards: [{ title: "Need help?", description: "Contact the administrator of your self-hosted runner deployment." }] },
  dashboard: { eyebrow: "Fleet overview · preview", title: "Connect the control plane to see your fleet.", description: "This website preview is not connected to a live runner backend. It does not show fabricated machines, jobs, or cost data.", cards: [{ title: "Live data unavailable", description: "Connect this frontend to an authenticated runner API to populate fleet health, active tasks, and spend." }, { title: "Authentication skipped", description: "This preview is not suitable for private fleet data. Account access and authorization are not configured." }] },
  account: { eyebrow: "Account", title: "Account settings are unavailable.", description: "This preview has no identity provider or persistent user database configured. No profile changes can be saved.", cards: [{ title: "Authentication skipped", description: "Enable a secure identity provider before exposing user settings." }] },
  "account/settings": { eyebrow: "Account settings", title: "Profile settings are not connected.", description: "There is no signed-in account on this preview. Profile information is not stored or editable.", cards: [{ title: "No account data", description: "Authentication and per-user persistence must be configured before this area is enabled." }] },
  "account/users": { eyebrow: "Team members", title: "Team management is unavailable.", description: "User membership and roles are not configured on this preview.", cards: [{ title: "No user directory", description: "Connect an identity provider and a user-scoped data store before managing members." }] },
  "account/users/invite": { eyebrow: "Invite a teammate", title: "Invitations are not enabled.", description: "This preview cannot send invitations or persist membership changes.", cards: [{ title: "No invitations sent", description: "Team access requires configured authentication, email delivery, and authorization." }] },
  "settings/cloud-spend": { eyebrow: "Cloud spend", title: "Cloud budgets need a live fleet connection.", description: "Spend data and budget controls are not connected in this preview.", cards: [{ title: "No spend data", description: "Connect your provider-backed runner API before displaying or changing cloud budgets." }] },
  "settings/policy": { eyebrow: "Policy", title: "Resource policy is not connected.", description: "This preview cannot read or change governor policy on a host.", cards: [{ title: "No changes made", description: "Policy changes require an authenticated connection to the runner control plane." }] },
  "settings/integrations": { eyebrow: "Integrations", title: "Integrations are not connected.", description: "No cloud credentials or external provider integrations are loaded in this preview.", cards: [{ title: "Bring your own keys", description: "Configure cloud providers in your self-hosted control plane. Do not paste credentials into this website preview." }] },
  unauthorized: { eyebrow: "Access denied", title: "You do not have access to this resource.", description: "Ask your runner administrator to verify your account and permissions.", cards: [{ title: "No session", description: "Sign-in is not configured in this preview." }] },
  "500": { eyebrow: "Server error", title: "Something went wrong.", description: "The request could not be completed. Try again later or check your deployment logs.", cards: [{ title: "Need help?", description: "Visit the documentation to review the self-hosted setup and troubleshooting notes." }] },
}

const pageTitles = Object.fromEntries(Object.entries(pages).map(([path, page]) => [path, page.title]))

export async function generateStaticParams() {
  return Object.keys(pages).map((slug) => ({ slug: slug.split("/") }))
}

export async function generateMetadata({ params }: { params: Promise<{ slug: string[] }> }): Promise<Metadata> {
  const { slug } = await params
  const key = slug.join("/")
  const page = pages[key]
  if (!page) return { title: "Page not found" }
  return { title: pageTitles[key], description: page.description }
}

export default async function ContentPage({ params }: { params: Promise<{ slug: string[] }> }) {
  const { slug } = await params
  const key = slug.join("/")
  const page = pages[key]
  if (!page) notFound()

  return <main>
    <section className="page-hero"><div className="container"><div className="breadcrumb"><Link href="/">Home</Link><span>/</span><span>{page.eyebrow}</span></div><span className="eyebrow">{page.eyebrow}</span><h1 style={{maxWidth:850,marginTop:17,fontSize:"clamp(38px,5vw,58px)"}}>{page.title}</h1><p className="lead">{page.description}</p></div></section>
    {key === "demo" ? <DemoPage /> : key === "schedule" ? <SchedulePage /> : key === "dashboard" ? <DashboardPage page={page} /> : <ContentBody page={page} path={key} />}
  </main>
}

function ContentBody({ page, path }: { page: PageInfo; path: string }) {
  const cardList = page.cards ?? []
  if (["faq", "privacy", "terms", "dpa", "sub-processors"].includes(path)) {
    return <section className="page-content"><div className="container prose">{path === "faq" ? <div className="faq-list">{cardList.map((card) => <details className="faq-item" key={card.title}><summary>{card.title}</summary><p>{card.description}</p></details>)}</div> : <><div className="callout callout-warning">Draft content: review with qualified counsel and replace with policies that reflect your actual service before production.</div>{cardList.map((card) => <section key={card.title}><h2>{card.title}</h2><p>{card.description}</p></section>)}</>}</div></section>
  }
  if (["login", "register", "forgot-password"].includes(path)) {
    return <section className="page-content"><div className="container" style={{display:"grid",gridTemplateColumns:"minmax(0,480px) minmax(0,1fr)",gap:45,alignItems:"start"}}><AuthNotice path={path}/><aside className="info-card"><span className="feature-icon"><ShieldCheck size={19}/></span><h3>Authentication is intentionally off</h3><p>No passwords or personal account data are collected in this preview. Enable the configured identity provider before exposing these routes with real users.</p></aside></div></section>
  }
  if (["account", "account/settings", "account/users", "account/users/invite", "settings/cloud-spend", "settings/policy", "settings/integrations"].includes(path)) return <ManagementPreview path={path}/>

  if (path === "pricing") return <section className="page-content"><div className="container"><div className="price-grid">{cardList.map((card,index) => <article className={`price-card ${index ? "enterprise" : ""}`} key={card.title}><span className="tier-pill">{index ? "For teams" : "For developers"}</span><h3>{card.title}</h3><p className="price-label">{index ? "Contact us" : "Self-hosted · Open source"}</p><div className="price-value">{index ? "Custom" : "$0"}</div><p className="price-label">{index ? "Custom engagement" : "Free forever"}</p><ul className="check-list">{card.description.split(" · ").map((item) => <li key={item}><Check size={16}/>{item}</li>)}</ul><Link className="button button-secondary" style={{marginTop:22}} href={index ? "/schedule" : "/docs"}>{index ? "Schedule a Call" : "Install Free"} <ArrowRight size={14}/></Link></article>)}</div><div className="info-card" style={{marginTop:24}}><span className="eyebrow">BYOC &amp; BYOK guarantee</span><h3 style={{marginTop:12}}>Your hardware and cloud credits stay yours.</h3><p>Bring your own machines and provider credentials. runner provides the supervisor and governance software; provider usage is billed directly by the provider, with no runner compute markup.</p></div><p style={{marginTop:18,color:"var(--muted)",fontSize:12}}>The 80% cloud CI reduction shown on the homepage is a target, not a measured or guaranteed saving.</p></div></section>
  return <section className="page-content"><div className="container"><div className="content-grid">{cardList.map((card,index) => <article className="info-card" key={card.title}><span className="feature-icon">{path === "docs" ? <BookOpen size={19}/> : path === "security" ? <ShieldCheck size={19}/> : <Cpu size={19}/>}</span><h3>{card.title}</h3><p>{card.description}</p></article>)}</div>{path === "docs" ? <div className="code-panel" style={{marginTop:24}}><div className="code-top"><span>Install the community build</span><a href="https://github.com/kirthi-sagar/runner#60-second-quickstart" target="_blank" rel="noreferrer">Read the source instructions</a></div><pre className="code-body" style={{margin:0,whiteSpace:"pre-wrap"}}>curl -fsSL https://raw.githubusercontent.com/kirthi-sagar/runner/main/install.sh | sh</pre><p style={{padding:"0 20px 18px",margin:0,color:"var(--muted)",fontSize:12}}>The repository install script verifies the downloaded binary checksum. Review the script and platform prerequisites before running it.</p></div> : null}<div style={{marginTop:34}}><Link className="button button-primary" href={path === "docs" ? "/demo" : "/schedule"}>{path === "docs" ? "Explore the demo" : "Talk with us"}<ArrowRight size={15}/></Link></div></div></section>
}

function AuthNotice({ path }: { path: string }) {
  const isRegister = path === "register"
  const isRecovery = path === "forgot-password"
  return <div className="form-card"><span className="tier-pill">Preview mode</span><h2 style={{fontSize:24,marginTop:15}}>{isRegister ? "Create account" : isRecovery ? "Reset password" : "Sign in"}</h2><p style={{color:"var(--muted)",fontSize:13}}>This form is disabled because authentication was skipped for this preview. Do not enter passwords or personal information.</p><label htmlFor="email">Email</label><input id="email" type="email" placeholder="you@company.com" disabled autoComplete="email"/><label htmlFor="password">Password</label><input id="password" type="password" placeholder="Not available in preview" disabled autoComplete={isRegister ? "new-password" : "current-password"}/><button className="button button-primary" type="button" disabled style={{opacity:.55,cursor:"not-allowed"}}>{isRegister ? "Create account" : isRecovery ? "Send reset link" : "Sign in"}</button>{!isRegister && !isRecovery ? <button className="button button-secondary" type="button" disabled style={{width:"100%",marginTop:9,opacity:.55,cursor:"not-allowed"}}>Continue with SSO</button> : null}<p style={{margin:"14px 0 0",fontSize:12,color:"var(--muted)"}}>Authentication is not configured. See <Link style={{color:"var(--blue)"}} href="/docs">the self-hosted setup guide</Link>.</p></div>
}

function SchedulePage() {
  return <section className="page-content"><div className="container"><div className="section-heading"><h2>Let&apos;s talk through your setup.</h2><p>Book a conversation about fleet rollout, cloud capacity, or your team&apos;s resource policy.</p></div><div style={{minHeight:560,border:"1px solid var(--line)",background:"var(--wash)",overflow:"hidden"}}><iframe title="Cal.com scheduling" src="https://cal.com" style={{display:"block",width:"100%",height:560,border:0,background:"white"}} loading="lazy" allow="camera; microphone; payment"/><p style={{padding:"0 18px 18px",color:"var(--muted)",fontSize:12}}>Scheduling is hosted by Cal.com. If the embedded page is unavailable, <a href="https://cal.com" target="_blank" rel="noreferrer" style={{color:"var(--blue)",textDecoration:"underline"}}>open Cal.com in a new tab</a>.</p></div></div></section>
}

function DashboardPage({ page }: { page: PageInfo }) {
  return <section className="page-content"><div className="container"><div className="dashboard-grid"><div className="kpi"><span>Connected nodes</span><strong>—</strong></div><div className="kpi"><span>Active jobs</span><strong>—</strong></div><div className="kpi"><span>Cloud burst nodes</span><strong>—</strong></div><div className="kpi"><span>Governor status</span><strong>—</strong></div></div><div className="info-card" style={{marginTop:22}}><h3>Pressure Stall Information</h3><div className="dashboard-grid"><div className="kpi"><span>CPU · avg10</span><strong>—</strong></div><div className="kpi"><span>Memory · avg10</span><strong>—</strong></div><div className="kpi"><span>Disk I/O · avg10</span><strong>—</strong></div><div className="kpi"><span>Scale-to-zero</span><strong>—</strong></div></div></div><div className="table-wrap" style={{marginTop:22}}><table><thead><tr><th>Node ID</th><th>Status</th><th>Active jobs</th><th>Supported providers</th></tr></thead><tbody><tr><td className="empty-row" colSpan={4}>{page.cards?.[0]?.description}</td></tr></tbody></table></div><div className="callout callout-warning" style={{marginTop:18}}>No live fleet data is displayed. Connect an authenticated control plane before exposing node or job information.</div></div></section>
}

function DemoPage() {
  return <section className="page-content"><div className="container"><div className="callout" style={{marginBottom:24}}>Illustrative simulation only. This does not read your computer or represent a measured benchmark.</div><DemoSimulator/><div style={{marginTop:30}}><h2 style={{fontSize:27}}>What this simulation represents</h2><p className="lead" style={{fontSize:15}}>When load rises, a governor can reduce the share available to background workers. Actual behavior depends on the host, workload, policy, and system implementation.</p><Link className="feature-link" href="/docs">Read the setup guide <ArrowRight size={14}/></Link></div></div></section>
}
