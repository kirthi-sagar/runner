"use client"

import { useState } from "react"
import { Activity, Cpu, Play, RotateCcw } from "lucide-react"

export default function DemoSimulator() {
  const [running, setRunning] = useState(false)
  const [step, setStep] = useState(0)
  const timer = async () => {
    if (running) return
    setRunning(true)
    setStep(1)
    await new Promise((resolve) => setTimeout(resolve, 650))
    setStep(2)
    await new Promise((resolve) => setTimeout(resolve, 650))
    setStep(3)
    setRunning(false)
  }
  const reset = () => { setStep(0); setRunning(false) }
  const foreground = step === 0 ? 68 : step === 1 ? 92 : 100
  const worker = step === 0 ? 36 : step === 1 ? 74 : step === 2 ? 29 : 20
  const status = step === 0 ? "Ready to simulate" : step === 1 ? "A heavy build raises host pressure" : step === 2 ? "Background worker yields capacity" : "Foreground responsiveness preserved"
  return <div className="simulator" aria-live="polite">
    <section className="sim-panel"><span className="eyebrow"><Activity size={14}/> Host resource monitor</span><h2 style={{fontSize:25,marginTop:12}}>Illustrative workstation</h2><div className="sim-meter"><span>Foreground apps</span><div className="sim-track"><span style={{width:`${foreground}%`,background:"var(--blue)"}}/></div><span className="sim-readout">{foreground}%</span></div><div className="sim-meter"><span>Build worker</span><div className="sim-track"><span style={{width:`${worker}%`,background:step > 1 ? "#65ad87" : "#6d8ff0"}}/></div><span className="sim-readout" style={{color:step > 1 ? "var(--green)" : "var(--blue)"}}>{worker}%</span></div><div className="sim-meter"><span>System headroom</span><div className="sim-track"><span style={{width:`${step > 1 ? 62 : step === 1 ? 14 : 54}%`,background:"#91a1b2"}}/></div><span className="sim-readout" style={{color:"var(--muted)"}}>{step > 1 ? "62%" : step === 1 ? "14%" : "54%"}</span></div><div className="sim-status" style={{background:step === 1 ? "#fff4e2" : undefined,color:step === 1 ? "#85530c" : undefined}}><Cpu size={15} style={{verticalAlign:"-3px",marginRight:7}}/>{status}</div><div className="hero-actions" style={{margin:"18px 0 0"}}><button className="button button-primary" onClick={timer} disabled={running || step === 3}><Play size={14}/>{running ? "Simulating…" : step === 3 ? "Simulation complete" : "Simulate heavy build"}</button><button className="button button-secondary" onClick={reset}><RotateCcw size={14}/> Reset</button></div></section>
    <aside className="sim-panel"><span className="eyebrow">Simulation timeline</span><div style={{display:"grid",gap:19,marginTop:22}}>{["Normal desktop use","Heavy build starts","Governor reduces background share","Interactive work stays prioritized"].map((label,index) => <div key={label} style={{display:"flex",gap:12,alignItems:"flex-start",color:index <= step && step > 0 ? "var(--ink)" : "var(--faint)"}}><span style={{display:"grid",placeItems:"center",width:24,height:24,flex:"0 0 24px",border:`1px solid ${index <= step && step > 0 ? "#88c2a0" : "var(--line)"}`,background:index <= step && step > 0 ? "var(--green-soft)" : "white",fontSize:11,fontWeight:700}}>{index + 1}</span><span style={{fontSize:13}}>{label}</span></div>)}</div><p style={{marginTop:24,color:"var(--muted)",fontSize:12}}>Illustrative values for UI demonstration. Not a live measurement or performance guarantee.</p></aside>
  </div>
}
