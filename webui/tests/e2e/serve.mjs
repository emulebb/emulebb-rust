import { createServer } from "vite";

const host = process.env.X_LOCAL_IP || "127.0.0.1";
const port = 4174;

const server = await createServer({
  server: {
    host,
    port,
    strictPort: true
  }
});

await server.listen();
server.printUrls();

const close = async () => {
  await server.close();
  process.exit(0);
};

process.on("SIGINT", () => {
  void close();
});
process.on("SIGTERM", () => {
  void close();
});
