#!/usr/bin/env bash
# Download the browser engines used by the differential test suite and the
# probe regeneration script.
#
# Chrome: uses an installed Google Chrome/Chromium (set CLOBBER_CHROME_PATH to
# override). Firefox and WebKit: downloaded as Playwright builds into
# .browsers/, which is gitignored.
set -euo pipefail

cd "$(dirname "$0")/.."
mkdir -p .browsers

PW_VERSION="$(node -e "console.log(require('playwright-core/package.json').version)" 2>/dev/null || echo 1.56)"
echo "playwright-core version: ${PW_VERSION}"

# Read revisions from playwright's browsers.json so the URLs are correct.
FIREFOX_REV="$(node -e "const b=require('playwright-core/browsers.json');console.log(b.browsers.find(x=>x.name==='firefox').revision)")"
WEBKIT_REV="$(node -e "const b=require('playwright-core/browsers.json');console.log(b.browsers.find(x=>x.name==='webkit').revision)")"

ARCH="$(uname -m)"
case "$ARCH" in
  arm64) MAC_ARCH="arm64" ;;
  x86_64) MAC_ARCH="" ;;
  *) MAC_ARCH="" ;;
esac

fetch() {
  local url="$1" out="$2"
  if [ -s "$out" ]; then echo "already present: $out"; return; fi
  echo "downloading $url"
  curl -fL --retry 3 -o "$out" "$url"
}

if [ ! -d .browsers/firefox ]; then
  fetch "https://cdn.playwright.dev/dbazure/download/playwright/builds/firefox/${FIREFOX_REV}/firefox-mac${MAC_ARCH:+-$MAC_ARCH}.zip" .browsers/firefox.zip
  (cd .browsers && unzip -q -o firefox.zip -d firefox && rm firefox.zip)
fi
if [ ! -f .browsers/pw_run.sh ]; then
  fetch "https://cdn.playwright.dev/dbazure/download/playwright/builds/webkit/${WEBKIT_REV}/webkit-mac-15${MAC_ARCH:+-$MAC_ARCH}.zip" .browsers/webkit.zip
  (cd .browsers && unzip -q -o webkit.zip && rm webkit.zip)
fi

chmod +x .browsers/pw_run.sh 2>/dev/null || true
echo "done. Chrome path: ${CLOBBER_CHROME_PATH:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"
