# uploader

An anonymous, end-to-end encrypted file uploader. Files are encrypted in the
browser with [age](https://age-encryption.org/) to a recipient public key fixed
at build time, then uploaded in chunks; a file that is already age-encrypted is
sent as is. The frontend is [typage](https://github.com/FiloSottile/typage) with
a thin wrapper, the backend is Lua on nginx (OpenResty) and can notify a Telegram
chat on each completed upload. There is no inherent
size limit, since nothing is held in full on either side, and uploads resume
automatically after network failures.

## Configuration

`config.json`, read at build time. The committed file is an example.

| Key | Meaning |
|---|---|
| `recipient` | age public key (`age1…`) the browser encrypts to |
| `onion` | onion service hostname shown on the page |
| `maxGiB` | upload size limit; the server must enforce the same |
| `chunkMiB` | upload chunk size; the server's request body limit must allow it |

## Build

```
npm install
npm run check   # type check
npm run build   # config.json + src/ + static/ -> dist/
```

`dist/` is the site to serve. It is not committed, as it depends on the configuration.
