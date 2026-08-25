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

# Copy the workspace root manifest (app and client are workspace members)
cp Cargo.toml "$TARGET_DIR/Cargo.toml"
# The `generate` folder only exists in this repo, not in generated projects
sed -i '/^exclude = \["generate"\]$/d' "$TARGET_DIR/Cargo.toml"

# Rename Cargo.toml to Cargo.toml.liquid in the root, `app` and `client` folders
# cargo-generate automatically removes this extension when generating a new project
mv "$TARGET_DIR/Cargo.toml" "$TARGET_DIR/Cargo.toml.liquid"
mv "$TARGET_DIR/app/Cargo.toml" "$TARGET_DIR/app/Cargo.toml.liquid"
mv "$TARGET_DIR/client/Cargo.toml" "$TARGET_DIR/client/Cargo.toml.liquid"

# Replace fixed values with templating placeholders
sed -i 's/name = "vnd-template"/name = "{{project-app-crate}}"/g' "$TARGET_DIR/app/Cargo.toml.liquid"
sed -i 's/package = "vnd-template-client"/package = "{{project-client-crate}}"/g' "$TARGET_DIR/app/Cargo.toml.liquid"
sed -i 's/name = "vnd-template-client"/name = "{{project-client-crate}}"/g' "$TARGET_DIR/client/Cargo.toml.liquid"
sed -i 's/name = "vnd_template_client"/name = "{{project-client-lib-binary}}"/g' "$TARGET_DIR/client/Cargo.toml.liquid"
sed -i 's/name = "vnd_template_cli"/name = "{{project-cli-binary}}"/g' "$TARGET_DIR/client/Cargo.toml.liquid"
sed -i 's/"vnd-template"/"{{project-app-crate}}"/g' "$TARGET_DIR/client/src/main.rs"
sed -i 's/use vnd_template_client/use {{project-client-lib-binary}}/g' "$TARGET_DIR/client/src/main.rs"

if [ "$1" == "--check" ]; then
    if diff -r generate "$TARGET_DIR"; then
        echo "Template is up to date."
    else
        echo "Template is not up to date. Please run ./update-template.sh"
        exit 1
    fi
fi
