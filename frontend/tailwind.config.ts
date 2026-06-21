import type { Config } from "tailwindcss";

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
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
