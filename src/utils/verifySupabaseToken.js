const { createRemoteJWKSet, jwtVerify } = require("jose");

const JWKS = createRemoteJWKSet(
  new URL(
    `https://${process.env.SUPABASE_PROJECT_REF}.supabase.co/auth/v1/.well-known/jwks.json`,
  ),
);

async function verifySupabaseToken(token) {
  const { payload } = await jwtVerify(token, JWKS, {
    issuer: `https://${process.env.SUPABASE_PROJECT_REF}.supabase.co/auth/v1`,
    audience: "authenticated",
  });

  return payload;
}

module.exports = verifySupabaseToken;
