import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "PolicyProof",
  description: "GenLayer AI consensus for evidence-backed compliance attestations.",
  icons: {
    icon: "/favicon.svg",
    shortcut: "/favicon.svg",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="antialiased">{children}</body>
    </html>
  );
}
