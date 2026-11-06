/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import path from 'path';
import express from 'express';
import dotenv from 'dotenv';
dotenv.config();

import { 
  createApp, 
  validateStartupEnvironment, 
  getErrorMessage 
} from './src/server/app.ts';

export { createApp, validateStartupEnvironment };

/**
 * Boots the full-stack Project Bilanx application server.
 * Handles Vite middleware integration in development and static asset serving in production.
 */
export async function startServer(port: number = parseInt(process.env.PORT || '3000', 10)) {
  validateStartupEnvironment();
  const app = createApp({ isTest: false });

  // Integrate Vite dynamically in development mode, or serve static folder in production
  if (process.env.NODE_ENV !== "production") {
    console.log("[Vite Controller] Starting Vite development server mode...");
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    console.log("[Production Controller] Serving static assets from dist/ directory...");
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  const server = app.listen(port, "0.0.0.0", () => {
    console.log(`[Credentials Hub Server] Server booted locally and listening on http://0.0.0.0:${port}`);
  });

  return server;
}

// Auto-start server when invoked as main script (dev: tsx server.ts, prod: node dist/server.cjs)
const isDirectRun = Boolean(
  process.argv[1] &&
  (process.argv[1].endsWith('server.ts') || process.argv[1].endsWith('server.cjs'))
);

if (isDirectRun) {
  startServer().catch(err => {
    console.error("[Startup Failure] Failed to start custom Express Full-Stack server: ", getErrorMessage(err));
    process.exit(1);
  });
}
