# Vellum — a notebook app for iPad

A paper-first notebook web app tuned for Apple Pencil: pressure-sensitive ink,
multiple pages and notebooks, four paper styles, optional PIN lock with
real AES-256 encryption, and offline install as a home-screen app (PWA).
All data is stored locally on-device (IndexedDB) — nothing is uploaded anywhere.

## Try it right now (fastest)
Just open `index.html` in Safari on your iPad — everything works locally,
no server needed for testing on desktop, but **installing to the home screen
requires it to be served over HTTPS** (see below).

## Put it on your iPad home screen (recommended)

Since you already have GitHub Pages running at `khoanguyen-seiken.github.io`,
the easiest path is a new repo there:

1. Create a new GitHub repo, e.g. `vellum-notebook`.
2. Add all the files in this folder to the repo root and push.
3. In the repo's **Settings → Pages**, set source to the `main` branch, root folder.
4. Wait a minute, then visit `https://khoanguyen-seiken.github.io/vellum-notebook/`
   in **Safari on the iPad**.
5. Tap the **Share** button → **Add to Home Screen**.
6. Open it from the home screen icon — it now runs full-screen like a native
   app and works offline after the first load.

```bash
# from this folder
git init
git remote add origin https://github.com/khoanguyen-seiken/vellum-notebook.git
git add .
git commit -m "Vellum notebook app"
git push -u origin main
```

## Using it

- **Pen / Highlighter / Eraser / Lasso** — bottom-left tool dock.
- **Color & width** — swatches and slider in the dock; tap the rainbow swatch
  for a custom color.
- **Undo / Redo** — bottom-right.
- **Pages** — arrows and `+` in the top bar; the grid icon shows all pages as
  thumbnails (tap to jump, hover/tap ✕ to delete).
- **Notebooks** — the book icon opens your notebook library; you can create
  and switch between multiple notebooks.
- **⋯ menu** — paper style (blank / lined / dot grid / graph), export the
  current page as a PNG, rename, clear or delete a page.
- By default only **Apple Pencil** (and mouse, for testing) draws, so resting
  your palm on the screen doesn't leave marks. Turn on "Draw with finger too"
  in the menu if you want finger-drawing as well.

## Files

- `index.html` — app shell
- `style.css` — design system (dark bookbinding chrome, warm paper canvas)
- `app.js` — drawing engine, storage, and UI logic
- `manifest.json`, `sw.js` — PWA install + offline support
- `icon-192.png`, `icon-512.png` — home screen icons

## Notes / things you may want to extend later

- Storage is per-browser (IndexedDB), so it won't sync between devices —
  there's no backend. If you want iCloud-style sync later, that would mean
  adding a small backend or using CloudKit JS.
- The lasso tool is intentionally simple: select strokes, then delete them.
- Everything is vanilla HTML/CSS/JS — no build step, easy to keep hacking on.

## Security & the PIN lock

By default your notebooks are private simply because everything stays on
your iPad (no server, no sync) — the same protection as any note living in
your device's storage.

If you want a stronger guarantee, open the **⋯ menu → Set up PIN lock**:

- You choose a PIN (4–12 digits).
- The app derives an AES-256 key from your PIN (PBKDF2, 150,000 iterations,
  a random salt per device) using the browser's built-in Web Crypto API.
- Every notebook is encrypted with that key before it's written to
  IndexedDB — the raw stored bytes are ciphertext, not readable text.
- The key only ever lives in memory for the current session. Reloading the
  page, closing the tab, or tapping **Lock now** clears it, so you're asked
  for the PIN again next time.
- **There's no PIN recovery.** Nothing about your PIN is stored anywhere —
  that's what makes the encryption real. If you forget it, that notebook's
  data can't be decrypted. (You can always turn the lock off from an
  unlocked session, or start a fresh notebook.)
- You can change the PIN or turn the lock off anytime from the same menu —
  both re-encrypt (or decrypt) all your notebooks automatically.
