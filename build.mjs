// Build: config.json + src/ + static/ -> dist/ (a static site, served as is).
//
// esbuild bundles src/upload.ts (+ age-encryption) into one ES module served under CSP
// script-src 'self'. Deliberately UNMINIFIED + sourcemapped: an E2EE client's shipped bytes
// should stay readable and 1:1-traceable to this source. Deploy-time values come from
// config.json: the recipient and sizes are injected into the script (define); recipient,
// onion and size cap are stamped into the HTML so they show without JavaScript too.
import { build, context } from "esbuild";
import { copyFileSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { Encrypter } from "age-encryption";

const cfg = JSON.parse(readFileSync("config.json", "utf8"));
new Encrypter().addRecipient(cfg.recipient); // throws on a malformed key: fail the build, not the user
if (!/^[a-z2-7]{56}\.onion$/.test(cfg.onion)) throw new Error(`config.json: bad onion hostname ${cfg.onion}`);
if (!(cfg.maxGiB > 0) || !(cfg.chunkMiB > 0)) throw new Error("config.json: maxGiB and chunkMiB must be positive");

mkdirSync("dist", { recursive: true });
const stamp = (s) =>
  s.replaceAll("__RECIPIENT__", cfg.recipient).replaceAll("__ONION__", cfg.onion).replaceAll("__MAX_GIB__", String(cfg.maxGiB));
for (const page of ["index.html", "result.html"]) writeFileSync(`dist/${page}`, stamp(readFileSync(`src/${page}`, "utf8")));
for (const f of readdirSync("static")) copyFileSync(`static/${f}`, `dist/${f}`);

const options = {
  entryPoints: { upload: "src/upload.ts" },
  outdir: "dist",
  bundle: true,
  format: "esm",
  target: "es2022",
  minify: false,
  sourcemap: true,
  legalComments: "inline",
  logLevel: "info",
  define: {
    __RECIPIENT__: JSON.stringify(cfg.recipient),
    __MAX_BYTES__: String(cfg.maxGiB * 1024 ** 3),
    __CHUNK_BYTES__: String(cfg.chunkMiB * 1024 ** 2),
  },
};

if (process.argv.includes("--watch")) {
  const ctx = await context(options);
  await ctx.watch();
} else {
  await build(options);
}
