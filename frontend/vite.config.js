import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    host: true,
    port: 5173,
    // Docker on Windows doesn't forward file-change events into containers,
    // so Vite polls for changes instead. This makes live reload work.
    watch: { usePolling: true, interval: 500 },
  },
});
