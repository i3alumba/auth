import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  base: "/static/sso/ui/",
  build: {
    outDir: "../sso/static/sso/ui",
    emptyOutDir: true,
    rollupOptions: {
      input: "src/main.tsx",
      output: {
        entryFileNames: "login.js",
        chunkFileNames: "[name].js",
        assetFileNames: "login.[ext]",
      },
    },
  },
});
