#!/bin/bash
# Download vendor assets for offline/on-premise deployment
# Run this during Docker build or manually before deployment
set -e

STATIC_DIR="${1:-static/vendor}"
mkdir -p "$STATIC_DIR/css" "$STATIC_DIR/js" "$STATIC_DIR/fonts"

echo "Downloading vendor assets to $STATIC_DIR..."

# Bootstrap 5.3.2 CSS
curl -sL -o "$STATIC_DIR/css/bootstrap.min.css" \
  "https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" 2>/dev/null && \
  echo "  [OK] Bootstrap CSS" || echo "  [SKIP] Bootstrap CSS (download failed)"

# Bootstrap 5.3.2 JS Bundle
curl -sL -o "$STATIC_DIR/js/bootstrap.bundle.min.js" \
  "https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js" 2>/dev/null && \
  echo "  [OK] Bootstrap JS" || echo "  [SKIP] Bootstrap JS (download failed)"

# Bootstrap Icons 1.11.0
curl -sL -o "$STATIC_DIR/css/bootstrap-icons.min.css" \
  "https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.min.css" 2>/dev/null && \
  echo "  [OK] Bootstrap Icons CSS" || echo "  [SKIP] Bootstrap Icons CSS (download failed)"

# Bootstrap Icons fonts (WOFF2)
curl -sL -o "$STATIC_DIR/fonts/bootstrap-icons.woff2" \
  "https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/fonts/bootstrap-icons.woff2" 2>/dev/null && \
  echo "  [OK] Bootstrap Icons WOFF2" || echo "  [SKIP] Bootstrap Icons WOFF2 (download failed)"

curl -sL -o "$STATIC_DIR/fonts/bootstrap-icons.woff" \
  "https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/fonts/bootstrap-icons.woff" 2>/dev/null && \
  echo "  [OK] Bootstrap Icons WOFF" || echo "  [SKIP] Bootstrap Icons WOFF (download failed)"

# Fix Bootstrap Icons CSS to reference local fonts
if [ -f "$STATIC_DIR/css/bootstrap-icons.min.css" ]; then
  sed -i 's|url("./fonts/|url("../fonts/|g' "$STATIC_DIR/css/bootstrap-icons.min.css"
fi

# Chart.js 4.4.1
curl -sL -o "$STATIC_DIR/js/chart.umd.min.js" \
  "https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js" 2>/dev/null && \
  echo "  [OK] Chart.js" || echo "  [SKIP] Chart.js (download failed)"

# Inter Font (self-hosted CSS with embedded WOFF2)
cat > "$STATIC_DIR/css/inter-font.css" << 'FONTCSS'
/* Inter Font - Self-hosted fallback */
/* Uses system font stack as graceful fallback if font files unavailable */
@font-face {
  font-family: 'Inter';
  font-style: normal;
  font-weight: 300;
  font-display: swap;
  src: local('Inter Light'), local('Inter-Light');
}
@font-face {
  font-family: 'Inter';
  font-style: normal;
  font-weight: 400;
  font-display: swap;
  src: local('Inter Regular'), local('Inter-Regular');
}
@font-face {
  font-family: 'Inter';
  font-style: normal;
  font-weight: 500;
  font-display: swap;
  src: local('Inter Medium'), local('Inter-Medium');
}
@font-face {
  font-family: 'Inter';
  font-style: normal;
  font-weight: 600;
  font-display: swap;
  src: local('Inter SemiBold'), local('Inter-SemiBold');
}
@font-face {
  font-family: 'Inter';
  font-style: normal;
  font-weight: 700;
  font-display: swap;
  src: local('Inter Bold'), local('Inter-Bold');
}
@font-face {
  font-family: 'Inter';
  font-style: normal;
  font-weight: 800;
  font-display: swap;
  src: local('Inter ExtraBold'), local('Inter-ExtraBold');
}
FONTCSS
echo "  [OK] Inter font CSS (system-local fallback)"

echo ""
echo "Vendor assets download complete."
echo "Files in $STATIC_DIR:"
find "$STATIC_DIR" -type f -exec ls -lh {} \; 2>/dev/null | awk '{print "  " $5 " " $NF}'
