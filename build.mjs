// config.json + src/ + static/ -> dist/, a static site served as is.
// Unminified and sourcemapped on purpose: the shipped bytes must stay traceable to this source.
// Config values enter the script via define and the HTML via stamped placeholders, so they
// show without JavaScript too.
import { build, context } from "esbuild";
import { copyFileSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { Encrypter } from "age-encryption";

const cfg = JSON.parse(readFileSync("config.json", "utf8"));
new Encrypter().addRecipient(cfg.recipient); // a malformed key fails the build
if (!/^[a-z2-7]{56}\.onion$/.test(cfg.onion)) throw new Error(`config.json: bad onion hostname ${cfg.onion}`);
if (!(cfg.maxGiB > 0) || !(cfg.chunkMiB > 0)) throw new Error("config.json: maxGiB and chunkMiB must be positive");

rmSync("dist", { recursive: true, force: true }); // dist is exactly this build
mkdirSync("dist");
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
