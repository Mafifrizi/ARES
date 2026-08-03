import process from "node:process";
import { URL } from "node:url";

import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const apiOrigin = process.env.VITE_API_ORIGIN ?? "http://127.0.0.1:8080";
const wsOrigin = apiOrigin.replace(/^http/, "ws");

function apiProxy() {
  return {
    target: apiOrigin,
    changeOrigin: false,
  };
}

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
      "/auth": apiProxy(),
      "/campaigns": apiProxy(),
      "/modules": apiProxy(),
      "/reports": apiProxy(),
      "/stats": apiProxy(),
      "/telemetry": apiProxy(),
      "/graph": apiProxy(),
      "/security": apiProxy(),
      "/strategy": apiProxy(),
      "/edr": apiProxy(),
      "/templates": apiProxy(),
      "/health": apiProxy(),
      "/ws": {
        target: wsOrigin,
        changeOrigin: false,
        ws: true,
      },
    },
  },
});
