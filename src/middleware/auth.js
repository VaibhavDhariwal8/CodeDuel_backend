const jwt = require("jsonwebtoken");
const pool = require("../db");

async function requireAuth(req, res, next) {
  const header = req.headers.authorization;

  if (!header?.startsWith("Bearer ")) {
    return res.status(401).json({ error: "missing token" });
  }

  // TODO: Replace jwt.decode() with proper Supabase JWKS verification (ES256)
  const payload = jwt.decode(header.slice(7));

  if (!payload?.sub) {
    return res.status(401).json({ error: "invalid token" });
  }

  const {
    rows: [user],
  } = await pool.query(
    `
    SELECT is_admin, is_banned
    FROM users
    WHERE id = $1
    `,
    [payload.sub],
  );

  if (!user) {
    return res.status(401).json({ error: "no profile found" });
  }

  if (user.is_banned) {
    return res.status(403).json({ error: "account banned" });
  }

  req.userId = payload.sub;
  req.user = user;

  next();
}

function requireAdmin(req, res, next) {
  if (!req.user?.is_admin) {
    return res.status(403).json({
      error: "admin only",
    });
  }

  next();
}

module.exports = {
  requireAuth,
  requireAdmin,
};
