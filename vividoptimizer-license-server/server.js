// VividOptimizer license server — SellAuth Dynamic Delivery -> Keygen
const crypto = require("crypto");
const express = require("express");

const {
  KEYGEN_ACCOUNT,
  KEYGEN_PRODUCT_TOKEN,
  KEYGEN_POLICY_ID,
  SELLAUTH_PRODUCT_ID,
  SELLAUTH_WEBHOOK_SECRET,
  PORT = 10000,
} = process.env;

const missing = [
  "KEYGEN_ACCOUNT",
  "KEYGEN_PRODUCT_TOKEN",
  "KEYGEN_POLICY_ID",
  "SELLAUTH_PRODUCT_ID",
  "SELLAUTH_WEBHOOK_SECRET",
].filter((k) => !process.env[k]);
if (missing.length) console.error("MISSING ENV VARS:", missing.join(", "));

const app = express();

// Idempotency: same order retried by SellAuth gets the same key back.
// (In-memory: resets if Render restarts/sleeps. Fine for testing; see notes.)
const delivered = new Map(); // orderId -> key

// Download link sent to the buyer under their key (same pattern as the other Vivid apps).
// The installer is committed directly into the vivid-zip repo and served via
// raw.githubusercontent.com -- GitHub Releases isn't usable from this environment.
const DOWNLOAD_URL =
  process.env.VIVIDOPTIMIZER_DOWNLOAD_URL ||
  "https://raw.githubusercontent.com/exetoreo/vivid-zip/main/VividOptimizerSetup.exe";
const withDownload = (key) => (DOWNLOAD_URL ? `${key}\n${DOWNLOAD_URL}` : key);

function verifySignature(rawBody, header) {
  if (!header || !SELLAUTH_WEBHOOK_SECRET) return false;
  const expected = crypto
    .createHmac("sha256", SELLAUTH_WEBHOOK_SECRET)
    .update(rawBody)
    .digest("hex");
  const got = String(header).trim().replace(/^sha256=/i, "");
  const a = Buffer.from(expected, "utf8");
  const b = Buffer.from(got, "utf8");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// Field names in SellAuth's payload weren't confirmed, so look in several places.
function pick(obj, paths) {
  for (const p of paths) {
    const v = p.split(".").reduce((o, k) => (o == null ? o : o[k]), obj);
    if (v !== undefined && v !== null && v !== "") return v;
  }
  return null;
}

async function mintLicense(orderId, email) {
  const res = await fetch(
    `https://api.keygen.sh/v1/accounts/${KEYGEN_ACCOUNT}/licenses`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${KEYGEN_PRODUCT_TOKEN}`,
        "Content-Type": "application/vnd.api+json",
        Accept: "application/vnd.api+json",
      },
      body: JSON.stringify({
        data: {
          type: "licenses",
          attributes: { metadata: { sellauthOrderId: String(orderId), email: email || null } },
          relationships: {
            policy: { data: { type: "policies", id: KEYGEN_POLICY_ID } },
          },
        },
      }),
    }
  );
  const text = await res.text();
  if (!res.ok) throw new Error(`Keygen ${res.status}: ${text}`);
  const key = JSON.parse(text)?.data?.attributes?.key;
  if (!key) throw new Error(`Keygen returned no key: ${text}`);
  return key;
}

app.get("/", (_req, res) => res.send("VividOptimizer license server OK"));

app.post(
  "/webhook/sellauth",
  express.raw({ type: "*/*", limit: "1mb" }),
  async (req, res) => {
    const raw = req.body; // Buffer
    const sig = req.get("X-Signature");
    console.log("---- webhook received ----");
    console.log("headers:", JSON.stringify(req.headers));
    console.log("raw body:", raw.toString("utf8"));

    if (!verifySignature(raw, sig)) {
      console.error("Signature check FAILED (header:", sig, ")");
      return res.status(401).send("Invalid signature");
    }

    let payload;
    try {
      payload = JSON.parse(raw.toString("utf8"));
    } catch {
      return res.status(400).send("Bad JSON");
    }

    const orderId = pick(payload, [
      "invoice_id", "invoice.id", "order_id", "order.id", "id", "unique_id", "invoice.unique_id",
    ]);
    const email = pick(payload, [
      "email", "customer_email", "customer.email", "invoice.email", "invoice.customer.email",
    ]);
    const productId = pick(payload, [
      "product_id", "product.id", "item.product_id", "item.product.id", "invoice.item.product_id",
    ]);
    console.log("parsed:", { orderId, email, productId });

    if (productId && String(productId) !== String(SELLAUTH_PRODUCT_ID)) {
      console.error("Unexpected product id:", productId);
      return res.status(400).send("Unexpected product");
    }
    if (!orderId) {
      console.error("No order id found in payload — fix field names above.");
      return res.status(400).send("No order id");
    }

    try {
      if (delivered.has(String(orderId))) {
        console.log("Repeat delivery for order", orderId);
        return res.type("text/plain").send(withDownload(delivered.get(String(orderId))));
      }
      const key = await mintLicense(orderId, email);
      delivered.set(String(orderId), key);
      console.log("Minted license for order", orderId);
      return res.type("text/plain").send(withDownload(key));
    } catch (err) {
      console.error("License generation error:", err.message);
      return res.status(500).send("License generation failed, please contact support");
    }
  }
);

app.listen(PORT, () =>
  console.log(`VividOptimizer License Server (sellauth webhook) listening on port ${PORT}`)
);
