import express from "express";
import { createServer as createViteServer } from "vite";

async function startServer() {
  const app = express();
  const PORT = Number(process.env.PORT || 3000);

  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  }

  app.get("/api/*", (_req, res) => {
    res.status(502).json({
      detail: "No local mock API is available. Configure VITE_FASTAPI_BASE_URL to point to FastAPI.",
    });
  });

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Frontend shell listening on http://localhost:${PORT}`);
  });
}

startServer();
