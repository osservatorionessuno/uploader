// upload.osservatorionessuno.org — anonymous drop box.
// 1. Encrypt the file in the browser with age to the configured recipient, unless it already
//    starts with the age header (encrypted at home). The server checks the header anyway.
// 2. Upload the ciphertext in chunks (tus-style: POST creates, PATCH appends at Upload-Offset,
//    HEAD reports the current offset) while it is still being produced: the encryptor folds
//    finished bytes into a growing Blob and the uploader sends each full chunk as soon as it
//    exists, so the total time is max(encrypt, upload) rather than the sum. On a network error
//    we wait for the network, ask the server where it got to, and resume from there. The
//    ciphertext lives in that Blob for the life of the tab, so a page reload starts over.
import { Encrypter } from "age-encryption";

declare const __CHUNK_BYTES__: number; // config.json chunkMiB; the server's per-request body cap must allow it
const CHUNK = __CHUNK_BYTES__;
const WINDOW = 64 * 1024 * 1024; // max unconfirmed ciphertext held in memory; encryption pauses beyond it
const STALL_MS = 30000;
const AGE_MAGIC = ["age-encryption.org/v1", "-----BEGIN AGE ENCRYPTED FILE-----"];
const ID = /^[a-f0-9]{32}$/;

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
declare const __RECIPIENT__: string; // injected by build.mjs from config.json
declare const __MAX_BYTES__: number;  // same cap the server enforces (413); checked here first for a clear message
const recipient = __RECIPIENT__;

// ---- i18n: all copy, including every outcome message, is duplicated in the HTML under
// lang="it"/"en" and toggled by CSS on <html lang>. The script only moves numbers and ids
// into slots. English unless the browser says Italian (Tor Browser always says en-US,
// hence the manual toggle in the nav bar).
const html = document.documentElement;
html.lang = navigator.language.toLowerCase().startsWith("it") ? "it" : "en";
$("lang").addEventListener("click", (e) => { e.preventDefault(); html.lang = html.lang === "it" ? "en" : "it"; });

const drop = $("drop");
const fileInput = $<HTMLInputElement>("file");
const status = $("status");
const upBar = $<HTMLProgressElement>("up-bar");
const upText = $("up-text");
const cancelBtn = $<HTMLButtonElement>("cancel");
const lost = $("lost");
const notice = $<HTMLDialogElement>("notice");
notice.addEventListener("close", () => { status.hidden = true; });

// The one message component: reveal the block for `key`, put `detail` (upload id or error
// text) in the code slot, open as a modal. Success is "done", everything else is an error.
function show(key: string, detail = "") {
  notice.querySelectorAll<HTMLElement>("[data-key]").forEach((el) => (el.hidden = el.dataset.key !== key));
  $("ref").textContent = detail;
  notice.className = key === "done" ? "ok" : "err";
  notice.showModal();
}
// The page ships with the "JavaScript is off" notice open and the drop box hidden; swap them now.
notice.close();
notice.querySelector("form")!.hidden = false;
drop.hidden = false;

let cancelled = false;
let aborter = new AbortController(); // cancels sleeps, waits and control requests of the current run
let currentXhr: XMLHttpRequest | null = null;
let currentId: string | null = null;

const fmt = (b: number) =>
  b < 1024 * 1024 ? `${(b / 1024).toFixed(0)} KiB` : `${(b / 1024 / 1024).toFixed(1)} MiB`;

// Drives the <progress> + readout: "42% · 300.0 MiB / 700.0 MiB · 12.3 MiB/s · ~33s".
// Redraws at most every 100ms; the speed is measured over the last 5 seconds.
function meter(bar: HTMLProgressElement, text: HTMLElement, total: number) {
  const samples: [number, number][] = []; // last 5s of [time, bytes]
  let shown = 0;
  return {
    update(done: number) {
      const now = performance.now();
      if (now - shown < 100 && done < total) return;
      shown = now;
      samples.push([now, done]);
      while (samples.length > 1 && now - samples[0][0] > 5000) samples.shift();
      const [t0, b0] = samples[0];
      const speed = now > t0 ? ((done - b0) / (now - t0)) * 1000 : 0;
      bar.value = done / total;
      text.textContent =
        `${Math.round((done / total) * 100)}% · ${fmt(done)} / ${fmt(total)} · ${fmt(speed)}/s` +
        (speed > 0 ? ` · ~${Math.round((total - done) / speed)}s` : "");
    },
    reset() { samples.length = 0; },
  };
}

// ---- drag & drop / file picker ---------------------------------------------
drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
drop.addEventListener("dragleave", () => drop.classList.remove("over"));
drop.addEventListener("drop", (e) => {
  e.preventDefault();
  drop.classList.remove("over");
  const f = e.dataTransfer?.files[0];
  if (f) void run(f);
});
fileInput.addEventListener("change", () => {
  const f = fileInput.files?.[0];
  if (f) void run(f);
});
cancelBtn.addEventListener("click", () => {
  cancelled = true;
  aborter.abort();
  currentXhr?.abort();
  if (currentId) void fetch(`/up/${currentId}`, { method: "DELETE" }).catch(() => {});
});
// A reload would throw away the in-memory ciphertext mid-transfer; ask first.
addEventListener("beforeunload", (e) => { if (drop.hidden) e.preventDefault(); });

// ---- phase 1: encrypt -------------------------------------------------------
// The ciphertext as it is being produced and consumed. `blob` holds bytes [base, base+size):
// the encryptor folds finished bytes in CHUNK-sized steps (Response.blob() would keep everything
// on the JS heap; a Blob lives in the browser's blob storage), the uploader waits on
// `available()` for the range it needs and `drop()`s what the server has confirmed. Holding
// more than WINDOW unconfirmed bytes makes `space()` block, which stops the encryptor from
// pulling more plaintext, so memory stays bounded whatever the file size.
class Ciphertext {
  blob = new Blob();
  base = 0; // absolute offset of blob[0]; everything before it was confirmed by the server and dropped
  done = false;
  error: Error | null = null;
  private wake: (() => void) | null = null;
  private wakeSpace: (() => void) | null = null;
  private parts: Uint8Array<ArrayBuffer>[] = [];
  private pending = 0;

  push(chunk: Uint8Array<ArrayBuffer>) {
    this.parts.push(chunk);
    this.pending += chunk.byteLength;
    if (this.pending >= CHUNK) this.fold();
  }
  finish() { this.fold(); this.done = true; this.notify(); }
  fail(e: Error) { this.error = e; this.notify(); this.wakeSpace?.(); this.wakeSpace = null; }
  slice(start: number, end: number) { return this.blob.slice(start - this.base, end - this.base); }
  /** Forget everything before `upTo` (confirmed by the server). */
  drop(upTo: number) {
    if (upTo <= this.base) return;
    this.blob = this.blob.slice(upTo - this.base);
    this.base = upTo;
    this.wakeSpace?.(); this.wakeSpace = null;
  }
  private fold() {
    this.blob = new Blob([this.blob, ...this.parts]);
    this.parts = [];
    this.pending = 0;
    this.notify();
  }
  private notify() { this.wake?.(); this.wake = null; }
  /** Resolves once `blob` reaches `end`, or production has finished. */
  async available(end: number) {
    while (this.base + this.blob.size < end && !this.done && !this.error) await new Promise<void>((r) => (this.wake = r));
    if (this.error) throw this.error;
  }
  /** Resolves once fewer than WINDOW unconfirmed bytes are held (backpressure for the producer). */
  async space() {
    while (this.blob.size + this.pending >= WINDOW && !this.error) await new Promise<void>((r) => (this.wakeSpace = r));
    if (this.error) throw this.error;
  }
}

// Starts encrypting `file`; returns the ciphertext being produced and its final size (age
// computes it from the plaintext size, so Upload-Length is known before the first byte).
async function encrypt(file: File): Promise<{ ct: Ciphertext; total: number }> {
  const enc = new Encrypter();
  enc.addRecipient(recipient);
  let painted = 0;
  const counted = file.stream().pipeThrough(
    new TransformStream<Uint8Array, Uint8Array>({
      async transform(chunk, ctl) {
        if (aborter.signal.aborted) throw new Error("cancelled");
        ctl.enqueue(chunk);
        // The pipeline runs on promise continuations and never lets the browser paint;
        // yield one macrotask every ~100ms so the upload bar and its readout actually move.
        if (performance.now() - painted > 100) {
          await new Promise((r) => setTimeout(r));
          painted = performance.now();
        }
      },
    }),
  );
  const out = await enc.encrypt(counted);
  const ct = new Ciphertext();
  (async () => {
    for (const r = (out as ReadableStream<Uint8Array<ArrayBuffer>>).getReader(); ; ) {
      await ct.space(); // not reading = backpressure all the way up to file.stream()
      const { done, value } = await r.read();
      if (done) return ct.finish();
      ct.push(value);
    }
  })().catch((e) => ct.fail(e as Error));
  return { ct, total: out.size(file.size) };
}

async function isAge(file: Blob): Promise<boolean> {
  const head = new TextDecoder().decode(await file.slice(0, 40).arrayBuffer());
  return AGE_MAGIC.some((m) => head.startsWith(m));
}

// ---- phase 2: resumable chunked upload ---------------------------------------
// Only two failures are retried: a network error ("network") and 409 (offset mismatch,
// resynced via HEAD). Anything else - other HTTP statuses, a server answering with
// offsets that make no sense - aborts the transfer instead of guessing.
type HttpError = Error & { status?: number };
const httpError = (what: string, status: number): HttpError => Object.assign(new Error(`${what}: HTTP ${status}`), { status });
const retryable = (e: Error) => e.message === "network" || (e as HttpError).status === 409;

async function api(method: string, path: string, headers: Record<string, string> = {}): Promise<Response> {
  const r = await fetch(path, { method, headers, cache: "no-store", signal: aborter.signal })
    .catch(() => { throw new Error(cancelled ? "cancelled" : "network"); });
  if (!r.ok) throw httpError(`${method} ${path}`, r.status);
  return r;
}

// Server-reported offset, checked against what we can know locally.
function offsetFrom(value: string | null, min: number, max: number): number {
  const n = Number(value);
  if (value === null || !Number.isInteger(n) || n < min || n > max) throw new Error(`bad Upload-Offset: ${value}`);
  return n;
}

function patch(id: string, offset: number, chunk: Blob, onProgress: (sent: number) => void): Promise<number> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    currentXhr = xhr;
    xhr.open("PATCH", `/up/${id}`);
    xhr.setRequestHeader("Upload-Offset", String(offset));
    xhr.setRequestHeader("Content-Type", "application/offset+octet-stream");
    // Tor circuits can stall silently instead of resetting: treat 30s without upload
    // progress as a network error so the resume path kicks in.
    let stall = setTimeout(() => xhr.abort(), STALL_MS);
    xhr.upload.onprogress = (e) => {
      clearTimeout(stall);
      stall = setTimeout(() => xhr.abort(), STALL_MS);
      onProgress(offset + e.loaded);
    };
    xhr.onloadend = () => clearTimeout(stall);
    xhr.onload = () => {
      if (xhr.status !== 204) return reject(httpError("PATCH", xhr.status));
      const want = offset + chunk.size; // a 204 means the whole chunk was appended, nothing else is acceptable
      try { resolve(offsetFrom(xhr.getResponseHeader("Upload-Offset"), want, want)); } catch (e) { reject(e); }
    };
    xhr.onerror = () => reject(new Error("network"));
    xhr.onabort = () => reject(new Error(cancelled ? "cancelled" : "network")); // our own stall abort resumes
    xhr.send(chunk);
  });
}

// Both resolve early (rejecting) when the user cancels, so cancel takes effect at once
// instead of after a 30s backoff.
const sleep = (ms: number) =>
  new Promise<void>((resolve, reject) => {
    const t = setTimeout(resolve, ms);
    aborter.signal.addEventListener("abort", () => { clearTimeout(t); reject(new Error("cancelled")); }, { once: true });
  });
const online = () =>
  navigator.onLine
    ? Promise.resolve()
    : new Promise<void>((resolve, reject) => {
        addEventListener("online", () => resolve(), { once: true, signal: aborter.signal });
        aborter.signal.addEventListener("abort", () => reject(new Error("cancelled")), { once: true });
      });

async function upload(ct: Ciphertext, total: number): Promise<string> {
  const id = (await (await api("POST", "/up", { "Upload-Length": String(total) })).json()).id;
  if (typeof id !== "string" || !ID.test(id)) throw new Error("bad upload id");
  currentId = id;
  let offset = 0;
  let backoff = 1000;
  const m = meter(upBar, upText, total);
  while (offset < total) {
    if (cancelled) throw new Error("cancelled");
    try {
      const end = Math.min(offset + CHUNK, total);
      await ct.available(end); // encryption may still be ahead of us or not
      if (ct.done && ct.base + ct.blob.size !== total) throw new Error(`ciphertext is ${ct.base + ct.blob.size} bytes, announced ${total}`);
      offset = await patch(id, offset, ct.slice(offset, end), m.update);
      ct.drop(offset); // confirmed by the server: never needed again, even on resume
      backoff = 1000;
    } catch (e) {
      if (cancelled || !retryable(e as Error)) throw e;
      $("backoff").textContent = String(backoff / 1000);
      upText.hidden = true;
      lost.hidden = false;
      await sleep(backoff);
      backoff = Math.min(backoff * 2, 30000);
      await online();
      try {
        // The server only appends, so its offset is at least what it last confirmed to us; bytes
        // below ct.base are gone on our side, a smaller answer means the server lost data.
        offset = offsetFrom((await api("HEAD", `/up/${id}`)).headers.get("Upload-Offset"), ct.base, total);
        m.reset();
        lost.hidden = true;
        upText.hidden = false;
      } catch (e) {
        if (!retryable(e as Error)) throw e; // e.g. 404: the partial is gone, no point retrying
      }
    }
  }
  // Cancel may have landed while we were sleeping above, after the server already had every
  // byte: the loop then exits on its own and must not finalize a transfer the user gave up on.
  if (cancelled) throw new Error("cancelled");
  await api("POST", `/up/${id}/done`);
  return id;
}

// ---- orchestration ------------------------------------------------------------
async function run(file: File) {
  cancelled = false;
  aborter = new AbortController();
  drop.hidden = true;
  status.hidden = false;
  cancelBtn.hidden = false;
  lost.hidden = true;
  upText.hidden = false;
  upBar.value = 0;
  upText.textContent = "";
  let source: { ct: Ciphertext; total: number } | undefined;
  try {
    if (await isAge(file)) {
      // Already carries the age header (encrypted at home): send it as is.
      const ct = new Ciphertext();
      ct.blob = file;
      ct.finish();
      source = { ct, total: file.size };
    } else {
      source = await encrypt(file);
    }
    if (source.total > __MAX_BYTES__) throw httpError("size", 413);
    show("done", await upload(source.ct, source.total));
  } catch (e) {
    aborter.abort(); // stop the encryptor too if the upload is what failed
    source?.ct.fail(e as Error); // and release anything waiting on the ciphertext
    if (cancelled) status.hidden = true; // back to the empty drop box, nothing to report
    else if ((e as HttpError).status === 413) show("tooBig");
    else show("error", (e as Error).message);
  } finally {
    cancelBtn.hidden = true;
    currentXhr = currentId = null;
    fileInput.value = "";
    drop.hidden = false;
  }
}
