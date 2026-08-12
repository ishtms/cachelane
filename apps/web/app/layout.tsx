import type { Metadata, Viewport } from "next";

import "./styles.css";

export const metadata: Metadata = {
  title: "CacheLane",
  description: "Unreal-native crash analytics and symbolication",
};

export const viewport: Viewport = {
  colorScheme: "dark",
  themeColor: "#07090d",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
