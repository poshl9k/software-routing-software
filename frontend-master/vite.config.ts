import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import { resolve } from "node:path";

export default defineConfig({
  plugins: [react()],
  server: { proxy: { "/api": { target: "http://127.0.0.1:8000", changeOrigin: false } } },
  build: {
    outDir: process.env.VS_MASTER_STATIC_DIR ? resolve(process.env.VS_MASTER_STATIC_DIR) : "dist",
    rollupOptions: { output: { manualChunks: { react: ["react", "react-dom", "react-router-dom"], mui: ["@mui/material", "@emotion/react", "@emotion/styled"] } } },
  },
  test: { environment: "jsdom", setupFiles: ["./setup.ts"], clearMocks: true },
});
