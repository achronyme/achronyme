# Achronyme Docs

[![Deploy Docs](https://github.com/achronyme/achronyme/actions/workflows/docs.yml/badge.svg)](https://github.com/achronyme/achronyme/actions/workflows/docs.yml)
[![Built with Starlight](https://astro.badg.es/v2/built-with-starlight/tiny.svg)](https://starlight.astro.build)

Documentation site for the [Achronyme](https://github.com/achronyme/achronyme) ZK programming language, built with Astro and Starlight.

---

## Features

- **Markdown & MDX support** — Write documentation using standard Markdown or interactive MDX components
- **Static Site Generation** — Fast page loads and optimized assets out of the box
- **Starlight theme** — Beautiful, responsive documentation template with search and navigation

---

## Development

All commands are run from the `docs/` directory:

```bash
# Install dependencies
pnpm install

# Start local dev server at localhost:4321
pnpm dev

# Build the production site to ./dist/
pnpm build

# Preview the build locally
pnpm preview
```

---

## Project Structure

```
docs/
├── src/
│   ├── assets/             Images to be embedded in Markdown
│   └── content/
│       └── docs/           Documentation pages (.md or .mdx)
├── public/                 Static assets like favicons
├── astro.config.mjs        Astro configuration
├── package.json            Dependencies and scripts
└── tsconfig.json           TypeScript configuration
```

---

## License

GPL-3.0
