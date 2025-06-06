#!/bin/sh

set -ex

npm install -g wasm-pack

# Build the Rust project using wasm-pack


# This example requires to *not* create ES modules, therefore we pass the flag
# `--target no-modules`
wasm-pack build --target web --out-dir ./page/public/pkg 