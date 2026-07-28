import type { NextConfig } from "next";
import path from "node:path";

const nextConfig: NextConfig = {
  reactStrictMode: true,
  serverExternalPackages: ["playwright-core", "playwright"],
  outputFileTracingRoot: path.join(__dirname),
};

export default nextConfig;
