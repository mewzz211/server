// server.js
// The "database" backend. Both the Discord bot and the Roblox game talk to this.
//
// Setup:
//   npm init -y
//   npm install express better-sqlite3 cors
//   node server.js
//
// Env vars (create a .env file or set them in your host's dashboard):
//   BOT_API_KEY   - a secret string only your Discord bot knows. Protects /api/generate-key.
//   PORT          - optional, defaults to 3000

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const Database = require("better-sqlite3");

const PORT = process.env.PORT || 3000;
const BOT_API_KEY = process.env.BOT_API_KEY || "change-this-secret";
const KEY_TTL_MS = 3 * 60 * 1000; // keys expire 10 minutes after being generated

const app = express();
app.use(express.json());
app.use(cors());

const db = new Database("keys.db");
db.exec(`
  CREATE TABLE IF NOT EXISTS keys (
    key TEXT PRIMARY KEY,
    discord_id TEXT,
    created_at INTEGER,
    expires_at INTEGER,
    used INTEGER DEFAULT 0,
    used_by_roblox_id TEXT
  )
`);

function generateKey() {
  // e.g. AB12-CD34-EF56
  const raw = crypto.randomBytes(6).toString("hex").toUpperCase();
  return `${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8, 12)}`;
}

// Middleware: only the Discord bot may call generate-key
function requireBotAuth(req, res, next) {
  if (req.header("x-api-key") !== BOT_API_KEY) {
    return res.status(401).json({ error: "unauthorized" });
  }
  next();
}

// Called by the Discord bot when someone runs /getkey
app.post("/api/generate-key", requireBotAuth, (req, res) => {
  const { discordId } = req.body;
  if (!discordId) return res.status(400).json({ error: "missing discordId" });

  const key = generateKey();
  const now = Date.now();
  db.prepare(
    `INSERT INTO keys (key, discord_id, created_at, expires_at, used) VALUES (?, ?, ?, ?, 0)`
  ).run(key, discordId, now, now + KEY_TTL_MS);

  res.json({ key, expiresInSeconds: KEY_TTL_MS / 1000 });
});

// Called by the Roblox game when a player submits a key
app.post("/api/validate-key", (req, res) => {
  const { key, robloxUserId } = req.body;
  if (!key || !robloxUserId) {
    return res.status(400).json({ valid: false, reason: "missing fields" });
  }

  const row = db.prepare(`SELECT * FROM keys WHERE key = ?`).get(key.trim().toUpperCase());

  if (!row) return res.json({ valid: false, reason: "invalid key" });
  if (row.used) return res.json({ valid: false, reason: "key already used" });
  if (Date.now() > row.expires_at) return res.json({ valid: false, reason: "key expired" });

  db.prepare(
    `UPDATE keys SET used = 1, used_by_roblox_id = ? WHERE key = ?`
  ).run(String(robloxUserId), row.key);

  res.json({ valid: true });
});

app.get("/api/health", (req, res) => res.json({ ok: true }));

app.listen(PORT, () => console.log(`Key server running on port ${PORT}`));
