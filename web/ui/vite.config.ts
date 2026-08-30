import { resolve } from "node:path";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  base: "/ui/",
  plugins: [react()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    rollupOptions: {
      input: {
        chat: resolve(__dirname, "chat.html"),
        studio: resolve(__dirname, "studio.html"),
        admin: resolve(__dirname, "admin.html")
      }
    }
  }
});
