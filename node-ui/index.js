const { startUI } = require("./ui");

startUI().catch((err) => {
  console.error("Fatal error:", err?.message || err);
  process.exit(1);
});
