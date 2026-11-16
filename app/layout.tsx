import type { Metadata, Viewport } from "next"
import { SiteHeader } from "@/components/site-shell"
import { SiteFooter } from "@/components/site-footer"
import "./globals.css"

export const metadata: Metadata = {
  title: {
    default: "runner — CI that stays out of your way",
    template: "%s — runner",
  },
  description: "Protect your workstation from heavy CI builds and put idle compute to work with runner, the open-source GitHub Actions runner supervisor.",
  applicationName: "runner",
  robots: { index: true, follow: true },
}

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  themeColor: "#f7f9fc",
}

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en-US">
      <body>
        <SiteHeader />
        {children}
        <SiteFooter />
      </body>
    </html>
  )
}
