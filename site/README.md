# TaoWire landing page

Next.js (App Router) + TypeScript + [Motion](https://motion.dev) for animations.

```bash
npm install
npm run dev      # http://localhost:3000 with hot reload
npm run build    # production build
npm run start    # serve the production build
npm run lint     # TypeScript check
```

- **Copy:** every word and number is in `content/site.ts`, sourced from the repo's README, `docs/` and the CLI.
  Update the repo first, then this file.
- **Design:** `app/globals.css` (tokens on `:root`); components in `components/`.
- **Hosting:** works as-is on Vercel or any Node host (`npm run build && npm run start`). For a
  plain static host, add `output: "export"` to `next.config.ts` and upload the `out/` folder.
- Animations respect `prefers-reduced-motion`.
