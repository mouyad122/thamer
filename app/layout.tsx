import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Web Security Scanner",
  description:
    "Automated, non-random website security scanner producing a real Automated Security Score and PDF report.",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body className="min-h-screen antialiased">{children}</body>
    </html>
  );
}
