import "dotenv/config"
import { defineConfig } from "drizzle-kit"

export default defineConfig({
  dialect: "postgresql",
  schema: "./src/db/schema.ts",
  out: "./drizzle",
  dbCredentials: {
    url: process.env.NEON_DATABASE_URL!,
  },
  // Make `drizzle-kit push` non-destructive — show diffs and require approval.
  strict: true,
  verbose: true,
})
