import type { Config } from "tailwindcss";

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        sans: ["'Space Grotesk'", "system-ui", "-apple-system", "sans-serif"],
        mono: ["'JetBrains Mono'", "ui-monospace", "monospace"]
      },
      colors: {
        ink: "#111827",
        panel: "#ffffff",
        line: "#d7dde8",
        accent: "#b91c1c"
      }
    }
  },
  plugins: []
} satisfies Config;
