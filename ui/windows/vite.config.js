import { defineConfig } from "vite";

export default defineConfig({
  base: "./",
  build: {
    outDir: "../../internal/desktopui/dist",
    emptyOutDir: true,
    sourcemap: false,
    target: "es2020"
  }
});
