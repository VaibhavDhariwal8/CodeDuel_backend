const jwt = require("jsonwebtoken");
const pool = require("../db");

async function requireAuth(req, res, next) {
  try {
    const header = req.headers.authorization;

    if (!header?.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "missing token",
      });
    }

    const payload = jwt.verify(
      header.slice(7),
      process.env.SUPABASE_JWT_SECRET,
      {
        algorithms: ["HS256"],
      },
    );

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
    if (err.name === "TokenExpiredError" || err.name === "JsonWebTokenError") {
      return res.status(401).json({
        error: "invalid token",
      });
    }

    next(err);
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
