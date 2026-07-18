import process from "node:process";

import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const apiOrigin = process.env.VITE_API_ORIGIN ?? "http://127.0.0.1:8080";
const wsOrigin = apiOrigin.replace(/^http/, "ws");

function dashboardBasePathRedirect() {
  return {
    name: "dashboard-base-path-redirect",
    configureServer(server) {
      server.middlewares.use((request, response, next) => {
        const requestUrl = new URL(request.url ?? "/", "http://localhost");
        if (requestUrl.pathname !== "/dashboard") {
          next();
          return;
        }

        response.statusCode = 302;
        response.setHeader("Location", `/dashboard/${requestUrl.search}`);
        response.end();
      });
    },
  };
}

export default defineConfig({
  plugins: [dashboardBasePathRedirect(), react()],
  base: "/dashboard/",
  server: {
    proxy: {
      "/auth": apiOrigin,
      "/campaigns": apiOrigin,
      "/modules": apiOrigin,
      "/reports": apiOrigin,
      "/stats": apiOrigin,
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
