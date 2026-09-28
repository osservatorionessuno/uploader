// Anonymous drop box: encrypt in the browser with age, upload in resumable chunks.
// Encryption and upload overlap. The encryptor folds ciphertext into a growing Blob; the
// uploader sends each full chunk as soon as it exists and drops what the server confirmed;
// beyond WINDOW unconfirmed bytes the encryptor pauses, so memory is bounded. On a network
// error: wait, ask the server its offset, resume. A page reload starts over.
// Protocol: POST /up, PATCH /up/<id> at Upload-Offset, HEAD /up/<id>, POST /up/<id>/done.
import { Encrypter } from "age-encryption";

declare const __CHUNK_BYTES__: number; // chunkMiB in config.json; must fit the server's per-request body cap
const CHUNK = __CHUNK_BYTES__;
const WINDOW = 64 * 1024 * 1024; // unconfirmed ciphertext kept in memory before the encryptor pauses
const STALL_MS = 30000;
const AGE_MAGIC = ["age-encryption.org/v1", "-----BEGIN AGE ENCRYPTED FILE-----"];
const ID = /^[a-f0-9]{32}$/;

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
declare const __RECIPIENT__: string; // from config.json via build.mjs
declare const __MAX_BYTES__: number; // same cap as the server; checked first for a clear message
const recipient = __RECIPIENT__;

// All copy is in the HTML twice (lang="it"/"en"); CSS shows one by <html lang>, the script
// only fills slots. English unless the browser says Italian; Tor Browser always says en-US,
// hence the toggle.
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

// Reveal one [data-key] block of the dialog, fill the code slot, open as a modal.
function show(key: string, detail = "") {
  notice.querySelectorAll<HTMLElement>("[data-key]").forEach((el) => (el.hidden = el.dataset.key !== key));
  $("ref").textContent = detail;
  notice.className = key === "done" ? "ok" : "err";
  notice.showModal();
}
// Without JavaScript the page shows the notice and hides the drop box; swap them.
notice.close();
notice.querySelector("form")!.hidden = false;
drop.hidden = false;

let cancelled = false;
let aborter = new AbortController(); // aborts sleeps, waits and control requests of this run
let currentXhr: XMLHttpRequest | null = null;
let currentId: string | null = null;

const fmt = (b: number) =>
  b < 1024 * 1024 ? `${(b / 1024).toFixed(0)} KiB` : `${(b / 1024 / 1024).toFixed(1)} MiB`;

// <progress> + readout "42% · 300.0 MiB / 700.0 MiB · 12.3 MiB/s · ~33s".
// Redraws at most every 100ms; speed over the last 5s.
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
// A reload discards the unconfirmed ciphertext; ask first.
addEventListener("beforeunload", (e) => { if (drop.hidden) e.preventDefault(); });

// ---- phase 1: encrypt -------------------------------------------------------
// Ciphertext in flight. `blob` holds bytes [base, base+size): the encryptor pushes, the
// uploader waits on available(), slices, and drop()s confirmed bytes; space() blocks the
// producer beyond WINDOW. A Blob lives outside the JS heap, unlike Response.blob()'s buffers.
class Ciphertext {
  blob = new Blob();
  base = 0; // absolute offset of blob[0]; earlier bytes were confirmed and dropped
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
  /** Waits while WINDOW or more unconfirmed bytes are held. */
  async space() {
    while (this.blob.size + this.pending >= WINDOW && !this.error) await new Promise<void>((r) => (this.wakeSpace = r));
    if (this.error) throw this.error;
  }
}

// Starts encrypting `file`. age derives the final size up front, so Upload-Length is known too.
async function encrypt(file: File): Promise<{ ct: Ciphertext; total: number }> {
  const enc = new Encrypter();
  enc.addRecipient(recipient);
  let painted = 0;
  const counted = file.stream().pipeThrough(
    new TransformStream<Uint8Array, Uint8Array>({
      async transform(chunk, ctl) {
        if (aborter.signal.aborted) throw new Error("cancelled");
        ctl.enqueue(chunk);
        // The stream pipeline never yields to the event loop; give the browser a paint every ~100ms.
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
      await ct.space(); // not reading = backpressure up to file.stream()
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
// Retried: network errors and 409 (offset resynced via HEAD). Everything else aborts.
type HttpError = Error & { status?: number };
const httpError = (what: string, status: number): HttpError => Object.assign(new Error(`${what}: HTTP ${status}`), { status });
const retryable = (e: Error) => e.message === "network" || (e as HttpError).status === 409;

async function api(method: string, path: string, headers: Record<string, string> = {}): Promise<Response> {
  const r = await fetch(path, { method, headers, cache: "no-store", signal: aborter.signal })
    .catch(() => { throw new Error(cancelled ? "cancelled" : "network"); });
  if (!r.ok) throw httpError(`${method} ${path}`, r.status);
  return r;
}

// Server-reported offset, bounded by what we know.
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
    // Tor circuits can stall silently: no progress for STALL_MS counts as a network error.
    let stall = setTimeout(() => xhr.abort(), STALL_MS);
    xhr.upload.onprogress = (e) => {
      clearTimeout(stall);
      stall = setTimeout(() => xhr.abort(), STALL_MS);
      onProgress(offset + e.loaded);
    };
    xhr.onloadend = () => clearTimeout(stall);
    xhr.onload = () => {
      if (xhr.status !== 204) return reject(httpError("PATCH", xhr.status));
      const want = offset + chunk.size; // 204 means the whole chunk was appended
      try { resolve(offsetFrom(xhr.getResponseHeader("Upload-Offset"), want, want)); } catch (e) { reject(e); }
    };
    xhr.onerror = () => reject(new Error("network"));
    xhr.onabort = () => reject(new Error(cancelled ? "cancelled" : "network")); // stall abort resumes, user abort cancels
    xhr.send(chunk);
  });
}

// Reject on cancel so it takes effect at once, not after the backoff.
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
      await ct.available(end); // may wait for the encryptor
      if (ct.done && ct.base + ct.blob.size !== total) throw new Error(`ciphertext is ${ct.base + ct.blob.size} bytes, announced ${total}`);
      offset = await patch(id, offset, ct.slice(offset, end), m.update);
      ct.drop(offset); // confirmed: never needed again
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
        // The server only appends; below ct.base we hold nothing, a smaller answer means it lost data.
        offset = offsetFrom((await api("HEAD", `/up/${id}`)).headers.get("Upload-Offset"), ct.base, total);
        m.reset();
        lost.hidden = true;
        upText.hidden = false;
      } catch (e) {
        if (!retryable(e as Error)) throw e; // e.g. 404: the partial is gone
      }
    }
  }
  // A cancel during the sleep above can leave the loop by its condition; never finalize then.
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
      // already age-encrypted: send as is
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
    aborter.abort(); // stop the encryptor too
    source?.ct.fail(e as Error); // release waiters
    if (cancelled) status.hidden = true; // back to the drop box
    else if ((e as HttpError).status === 413) show("tooBig");
    else show("error", (e as Error).message);
  } finally {
    cancelBtn.hidden = true;
    currentXhr = currentId = null;
    fileInput.value = "";
    drop.hidden = false;
  }
}
