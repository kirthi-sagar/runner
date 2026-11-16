import type { Metadata, Viewport } from "next"
import "./globals.css"
import { SiteHeader } from "../components/site-header"
import { SiteFooter } from "../components/site-footer"

export const metadata: Metadata = {
  title: { default: "runner — CI that leaves your workstation responsive", template: "%s — runner" },
  description: "An open-source design for running GitHub Actions across local, peer, and cloud machines while protecting foreground apps.",
}
export const viewport: Viewport = { themeColor: "#fbfcfa", width: "device-width", initialScale: 1, userScalable: true }

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body><SiteHeader /><main>{children}</main><SiteFooter /></body></html>
}
