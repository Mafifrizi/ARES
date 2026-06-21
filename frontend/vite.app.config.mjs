import process from "node:process";

import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const apiOrigin = process.env.VITE_API_ORIGIN ?? "http://127.0.0.1:8080";
const wsOrigin = apiOrigin.replace(/^http/, "ws");

export default defineConfig({
  plugins: [react()],
  base: "/dashboard/",
  server: {
    proxy: {
      "/auth": apiOrigin,
      "/campaigns": apiOrigin,
      "/modules": apiOrigin,
      "/reports": apiOrigin,
      "/telemetry": apiOrigin,
      "/graph": apiOrigin,
      "/security": apiOrigin,
      "/strategy": apiOrigin,
      "/edr": apiOrigin,
      "/templates": apiOrigin,
      "/health": apiOrigin,
      "/ws": {
        target: wsOrigin,
        ws: true,
      },
    },
  },
});
