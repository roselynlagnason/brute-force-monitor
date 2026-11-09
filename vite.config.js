import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { resolve } from "node:path";

export default defineConfig({
  plugins: [react()],
  // Multi-page build: the public login page AND the admin console must both be
  // built, otherwise /admin.html does not exist in production (dist/).
  build: {
    rolldownOptions: {
      input: {
        main: resolve(import.meta.dirname, "index.html"),
        admin: resolve(import.meta.dirname, "admin.html"),
      },
    },
  },
  server: { host: true, proxy: { "/api": "http://localhost:3001" } }
});
