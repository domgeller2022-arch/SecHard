/**
 * The vulnerable/safe twin cases for the rule matrix (P3.2, A-15/A-16). One module so the CLI
 * regression (rule-twins.test.ts) and the manifest sync (rule-manifest.test.ts) read the same
 * table without the manifest test re-running the audit.
 */

export interface TwinCase {
  readonly name: string;
  readonly file: string;
  readonly rule: string;
  readonly expect: 'fires' | 'silent';
  readonly content: string;
}

export const CASES: readonly TwinCase[] = [
  {
    name: 'a15-sql-binding-safe', file: 'a15-sql-safe.ts', rule: 'hardening.taint-sql-injection', expect: 'silent',
    content: 'import express from "express";\nconst app = express();\napp.get("/u", (req, res) => {\n  pool.query("SELECT * FROM users WHERE id = $1", [req.query.id]).then((r) => res.json(r.rows));\n});\n',
  },
  {
    name: 'a15-sql-concat', file: 'a15-sql-unsafe.ts', rule: 'hardening.taint-sql-injection', expect: 'fires',
    content: 'import express from "express";\nconst app = express();\napp.get("/u", (req, res) => {\n  pool.query("SELECT * FROM users WHERE id = " + req.query.id).then((r) => res.json(r.rows));\n});\n',
  },
  {
    name: 'a15-stripe-verified', file: 'a15-stripe-verified.ts', rule: 'hardening.stripe-webhook-unverified', expect: 'silent',
    content: 'import express from "express";\nconst app = express();\napp.post("/webhook", async (req, res) => {\n  const body = await req.text();\n  const event = stripe.webhooks.constructEvent(body, req.headers["stripe-signature"] as string, secret);\n  if (event.type === "checkout.session.completed") { grant(event.data.object); }\n  res.json({ ok: true });\n});\n',
  },
  {
    name: 'a15-stripe-unverified', file: 'a15-stripe-unverified.ts', rule: 'hardening.stripe-webhook-unverified', expect: 'fires',
    content: 'import express from "express";\nconst app = express();\napp.post("/webhook", async (req, res) => {\n  const event = JSON.parse((await req.text()).toString());\n  if (event.type === "checkout.session.completed") { grant(event.data.object); }\n  res.json({ ok: true });\n});\n',
  },
  {
    name: 'a15-path-literal', file: 'a15-path-literal.ts', rule: 'hardening.path-traversal-concat', expect: 'silent',
    content: 'import fs from "fs";\nimport path from "path";\nconst p = fs.readFileSync(path.join("/var/data", "config.json"), "utf8");\n',
  },
  {
    name: 'a15-path-tainted', file: 'a15-path-tainted.ts', rule: 'hardening.taint-path-traversal', expect: 'fires',
    content: 'import express from "express";\nimport fs from "fs";\nimport path from "path";\nconst app = express();\napp.get("/f", (req, res) => {\n  const p = fs.readFileSync(path.join("/var/data", req.params.file), "utf8");\n  res.send(p);\n});\n',
  },
  {
    name: 'a16-xss-interpolated', file: 'a16-xss-interpolated.tsx', rule: 'hardening.taint-xss-innerhtml', expect: 'fires',
    content: 'export function Preview({ req }: { req: Request }) {\n  return <div dangerouslySetInnerHTML={{ __html: `<div class="preview">${req.query.x}</div>` }} />;\n}\n',
  },
  {
    name: 'a16-xss-literal', file: 'a16-xss-literal.tsx', rule: 'hardening.taint-xss-innerhtml', expect: 'silent',
    content: 'export function Preview() {\n  return <div dangerouslySetInnerHTML={{ __html: `<div class="preview">hello</div>` }} />;\n}\n',
  },
  {
    name: 'a16-formdata-split', file: 'a16-formdata-split.ts', rule: 'hardening.taint-sql-injection', expect: 'fires',
    content: 'import express from "express";\nconst app = express();\napp.post("/upload", async (req, res) => {\n  const body = await req.formData();\n  const f = body.get("filename");\n  db.execute("INSERT INTO files VALUES (\'" + f + "\')");\n  res.json({ ok: true });\n});\n',
  },
  {
    name: 'a16-py-sql-assigned', file: 'a16-py-sql-assigned.py', rule: 'hardening.taint-sql-injection-python', expect: 'fires',
    content: "from flask import Flask, request\napp = Flask(__name__)\n\n@app.route(\"/u\")\ndef users():\n    q = f\"SELECT * FROM users WHERE name = '{request.args.get('name')}'\"\n    cur.execute(q)\n    return cur.fetchall()\n",
  },
  {
    name: 'a16-py-sql-binding-safe', file: 'a16-py-sql-safe.py', rule: 'hardening.taint-sql-injection-python', expect: 'silent',
    content: 'from flask import Flask, request\napp = Flask(__name__)\n\n@app.route("/safe")\ndef safe():\n    cur.execute("SELECT * FROM users WHERE name = %s", (request.args.get("name"),))\n    return cur.fetchall()\n',
  },
  {
    name: 'a16-py-requests-ssrf', file: 'a16-py-requests-ssrf.py', rule: 'hardening.taint-ssrf-python', expect: 'fires',
    content: 'import requests\nfrom flask import Flask, request\napp = Flask(__name__)\n\n@app.route("/fetch")\ndef fetch():\n    return requests.get(request.args.get("url")).text\n',
  },
  {
    name: 'a16-py-requests-ssrf-safe', file: 'a16-py-requests-safe.py', rule: 'hardening.taint-ssrf-python', expect: 'silent',
    content: 'import requests\n\nDESTINATION = "https://api.example.invalid/v1/report"\n\n\ndef report():\n    return requests.get(DESTINATION, timeout=5).text\n',
  },
  {
    name: 'a16-py-sendfile', file: 'a16-py-sendfile.py', rule: 'hardening.taint-path-traversal-python', expect: 'fires',
    content: 'from flask import Flask, request, send_file\napp = Flask(__name__)\n\n@app.route("/dl")\ndef dl():\n    return send_file("/data/" + request.args.get("p"))\n',
  },
  {
    name: 'a16-py-sendfile-safe', file: 'a16-py-sendfile-safe.py', rule: 'hardening.taint-path-traversal-python', expect: 'silent',
    content: 'from flask import Flask, send_file\napp = Flask(__name__)\n\n\n@app.route("/invoice")\ndef invoice():\n    return send_file("/data/invoice-template.pdf")\n',
  },
  {
    name: 'a16-cookie-omitted', file: 'a16-cookie-omitted.ts', rule: 'hardening.cookie-missing-attributes', expect: 'fires',
    content: 'import express from "express";\nconst app = express();\napp.post("/login", (req, res) => {\n  res.cookie("session", req.body.token);\n  res.json({ ok: true });\n});\n',
  },
  {
    name: 'a16-cookie-safe', file: 'a16-cookie-safe.ts', rule: 'hardening.cookie-missing-attributes', expect: 'silent',
    content: 'import express from "express";\nconst app = express();\napp.post("/login", (req, res) => {\n  res.cookie("session", req.body.token, { httpOnly: true, secure: true });\n  res.json({ ok: true });\n});\n',
  },
  {
    name: 'a16-cors-reflection', file: 'a16-cors-reflection.ts', rule: 'hardening.cors-origin-reflection', expect: 'fires',
    content: 'import express from "express";\nconst app = express();\napp.use((req, res, next) => {\n  res.set("Access-Control-Allow-Origin", req.headers.origin);\n  next();\n});\n',
  },
  {
    name: 'a16-cors-allowlist', file: 'a16-cors-allowlist.ts', rule: 'hardening.cors-origin-reflection', expect: 'silent',
    content: 'import express from "express";\nconst app = express();\nconst allowed = ["https://app.example"];\napp.use((req, res, next) => {\n  const origin = String(req.headers.origin ?? "");\n  res.set("Access-Control-Allow-Origin", allowed.includes(origin) ? origin : allowed[0]);\n  next();\n});\n',
  },
];
