#!/bin/sh

set -ex

set -ex
curl https://sh.rustup.rs -sSf | sh -s -- -y && . "$HOME/.cargo/env"

# Build the Rust project using wasm-pack


# This example requires to *not* create ES modules, therefore we pass the flag
# `--target no-modules`
npx wasm-pack build --target web --out-dir ./page/public/pkg --release 