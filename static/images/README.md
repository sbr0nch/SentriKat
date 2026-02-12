# SentriKat Branding Assets

Place your branding images in this folder:

| File | Size | Usage |
|------|------|-------|
| `favicon.svg` | Vector | SVG favicon (preferred by modern browsers) |
| `favicon.ico` | 16/32/48 | Browser tab icon (legacy fallback) |
| `favicon-16x16.png` | 16x16 | Small favicon |
| `favicon-32x32.png` | 32x32 | Standard favicon |
| `favicon-128x128.png` | 128x128 | Default logo in app |
| `favicon.png` | 3060x3178 | Source PNG (transparent background) |
| `favicon-white.svg` | Vector | White SVG variant for dark backgrounds |
| `logo-192.png` | 192x192 | PWA icon / Apple touch icon |
| `logo-512.png` | 512x512 | Large PWA icon |
| `logo-dark.png` | 512x512 | White logo for dark theme |

## Dark Mode

- In **light mode**: black logo on transparent background (default)
- In **dark mode**: CSS filter (`brightness(0) invert(1)`) automatically converts the logo to white

## Regenerating Assets

All favicon/logo PNGs are generated from `favicon.png` (the source image).
The `favicon-white.svg` and `logo-dark.png` are inverted (white) variants.

## Usage in App

The app automatically looks for:
- `/static/images/favicon.svg` - SVG favicon (preferred)
- `/static/images/favicon.ico` - Browser favicon (fallback)
- `/static/images/favicon-128x128.png` - Default branding logo
