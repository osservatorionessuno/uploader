# uploader

A static web page for receiving files anonymously. Files are encrypted in the
browser with [age](https://age-encryption.org/) to a fixed public key before
upload. The server receives ciphertext only.

The page is a single TypeScript bundle with one runtime dependency,
[age-encryption](https://github.com/FiloSottile/typage), and no server-side
code of its own. Any backend that implements the protocol below can serve it.
The reference deployment is Lua on nginx at upload.osservatorionessuno.org.

## Behaviour

- A dropped file is encrypted with age (X25519, ChaCha20-Poly1305) and uploaded
  in chunks while encryption is still running. Memory use is bounded: at most
  64 MiB of unconfirmed ciphertext is held at any time.
- A file that already starts with the age header is sent unchanged.
- Uploads survive network loss. After an error the client waits for the network,
  asks the server how many bytes it holds, and resumes from there. A chunk that
  makes no progress for 30 seconds is treated as lost.
- Without JavaScript the page shows a plain form that accepts a file encrypted
  with age beforehand.
- The interface is in English and Italian. Italian is chosen when the browser
  reports it; a toggle in the header switches at any time.

## Configuration

`config.json` is read at build time. All values end up in the generated files.

| Key | Meaning |
|---|---|
| `recipient` | age public key (`age1…`) the browser encrypts to. Validated by age at build time. |
| `onion` | Onion service hostname shown on the page. |
| `maxGiB` | Maximum upload size. The server enforces its own limit; keep them equal. |
| `chunkMiB` | Upload chunk size. The server's per-request body limit must allow it. |

## Build

```
npm install
npm run check   # type check
npm run build   # config.json + src/ + static/ -> dist/
```

`dist/` is the deployable site: `index.html`, `upload.js` with its source map,
`result.html` (rendered by the server for the no-JavaScript form), the
stylesheets and the logo. The bundle is not minified.

`static/style.css`, `static/navbar.css` and `static/logo.svg` are copies of the
same files in the Osservatorio Nessuno website repository, kept in sync by hand.

## Protocol

The client speaks a subset of [tus](https://tus.io/). State on the server is
one partial file per upload; there is no database.

| Request | Response |
|---|---|
| `POST /up` with `Upload-Length` | `201 {"id": "<32 hex>"}`. `400` without a length, `413` above the limit. |
| `HEAD /up/<id>` | `200` with `Upload-Offset`, the number of bytes held. `404` if unknown. |
| `PATCH /up/<id>` with `Upload-Offset` and body | `204` with the new `Upload-Offset`. `409` with the current offset on mismatch. |
| `POST /up/<id>/done` | `200 {"id","size"}` once size equals the declared length and the file starts with the age header. `409` if incomplete, `400` if not an age file. |
| `DELETE /up/<id>` | `204`. |
| `POST /up/form` (multipart) | No-JavaScript path. Stores the file part if it is an age file and returns `result.html` with `__CLASS__` set to `ok`, `err` or `big` and `__ID__` to the id. |

A server must apply the offset check and the append as one atomic step per id,
and must not accept `done` for a partial whose size differs from the declared
length. The client retries only on network errors and `409`.

## Development

```
python3 dev/mock_server.py            # reference backend on http://127.0.0.1:8089, serves dist/
dev/smoke.sh [base_url]               # protocol acceptance test against any backend
```

The mock injects faults through environment variables: `FLAKY` (fraction of
chunks reset mid-request), `STALL` (fraction that hang), `RATE` (bytes per
second), `MAX` (size limit in bytes).

## Security properties

- The server never sees plaintext, file names or the key. It sees ciphertext,
  sizes and timing.
- The page loads no third-party resources and runs under
  `default-src 'none'; script-src 'self'; style-src 'self'`.
- The build output is intended to be signed and verified with
  [WEBCAT](https://webcat.tech/).
- Client-side encryption requires JavaScript. In Tor Browser at the "Safest"
  level it does not run; the no-JavaScript form remains available.
