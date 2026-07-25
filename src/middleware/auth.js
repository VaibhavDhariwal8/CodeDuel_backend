const verifySupabaseToken = require("../utils/verifySupabaseToken");
const pool = require("../db");

async function requireAuth(req, res, next) {
  try {
    const header = req.headers.authorization;

    if (!header?.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "missing token",
      });
    }

    const payload = await verifySupabaseToken(header.slice(7));

    const {
      rows: [user],
    } = await pool.query(
      `
      select is_admin, is_banned
      from users
      where id = $1
      `,
      [payload.sub],
    );

    if (!user) {
      return res.status(401).json({
        error: "no profile found",
      });
    }

    if (user.is_banned) {
      return res.status(403).json({
        error: "account banned",
      });
    }

    req.userId = payload.sub;
    req.user = user;

    next();
  } catch (err) {
    console.error("JWT VERIFY ERROR:", err);

    return res.status(401).json({
      error: "invalid token",
    });
  }
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
