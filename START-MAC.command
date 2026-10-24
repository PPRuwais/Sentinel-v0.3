#!/bin/sh
cd "$(dirname "$0")" || exit 1
if ! command -v node >/dev/null 2>&1; then
  echo 'Install Node.js LTS from https://nodejs.org then run this file again.'
  read -r answer
  exit 1
fi
printf '\nOpen http://localhost:3000 after the server is ready.\n'
node server.mjs
