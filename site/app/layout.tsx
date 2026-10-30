import type { Metadata, Viewport } from "next";
import { Archivo_Black, Inter, JetBrains_Mono, Michroma } from "next/font/google";
import "./globals.css";

const sans = Inter({ subsets: ["latin"], weight: ["300", "400", "500", "600", "700"], variable: "--font-sans" });
const mono = JetBrains_Mono({ subsets: ["latin"], weight: ["400", "500"], variable: "--font-mono" });
const black = Archivo_Black({ subsets: ["latin"], weight: "400", variable: "--font-black" });
const wide = Michroma({ subsets: ["latin"], weight: "400", variable: "--font-wide" });

export const metadata: Metadata = {
  title: "TaoWire — secure networking for Bittensor v11 subnets",
  description:
    "Signed HTTP miner server, validator client and scoring loop for Bittensor v11 subnets, plus the migration path from v10. Python, TypeScript, Go and Rust.",
  openGraph: {
    title: "TaoWire",
    description: "Secure networking for Bittensor v11 subnets, and the way across from v10.",
    type: "website",
  },
  icons: { icon: "/icon.svg" },
};

export const viewport: Viewport = { themeColor: "#e6e6e6", width: "device-width", initialScale: 1 };

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${sans.variable} ${mono.variable} ${black.variable} ${wide.variable}`}>
      <body>{children}</body>
    </html>
  );
}
