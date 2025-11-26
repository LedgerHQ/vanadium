#!/usr/bin/env bash
set -e

# Ensure we are in the directory of the script
cd "$(dirname "$0")"

(cd app && cargo clean)
(cd client && cargo clean)

if [ "$1" == "--check" ]; then
    TARGET_DIR=$(mktemp -d)
    trap "rm -rf $TARGET_DIR" EXIT
else
    TARGET_DIR="generate"
    # Regenerate template
    rm -rf "$TARGET_DIR"
    mkdir "$TARGET_DIR"
fi

cp -r app client README.md vapp.code-workspace "$TARGET_DIR"

# Remove Cargo.lock files to avoid committing them in the template
rm -f "$TARGET_DIR/app/Cargo.lock"
rm -f "$TARGET_DIR/client/Cargo.lock"

# Replace fixed values with templating placeholders
sed -i 's/name = "vnd-template"/name = "{{project-app-crate}}"/g' "$TARGET_DIR/app/Cargo.toml"
sed -i 's/package = "vnd-template-client"/package = "{{project-client-crate}}"/g' "$TARGET_DIR/app/Cargo.toml"
sed -i 's/name = "vnd_template_client"/name = "{{project-client-lib-binary}}"/g' "$TARGET_DIR/client/Cargo.toml"
sed -i 's/name = "vnd_template_cli"/name = "{{project-cli-binary}}"/g' "$TARGET_DIR/client/Cargo.toml"
sed -i 's/"vnd-template"/"{{project-app-crate}}"/g' "$TARGET_DIR/client/src/main.rs"

if [ "$1" == "--check" ]; then
    if diff -r generate "$TARGET_DIR"; then
        echo "Template is up to date."
    else
        echo "Template is not up to date. Please run ./update-template.sh"
        exit 1
    fi
fi
