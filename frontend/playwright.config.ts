import { defineConfig } from "@playwright/test";
export default defineConfig({
  testDir: "./tests",
  use: {
    baseURL: "http://127.0.0.1:4178",
    launchOptions: {
      executablePath:
        process.env.CHROMIUM_PATH || "/usr/bin/google-chrome-stable",
    },
  },
  webServer: {
    command: "node tests/server.mjs",
    port: 4178,
    reuseExistingServer: false,
  },
});
