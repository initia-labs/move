---
id: move-language
title: Move Language
custom_edit_url: https://github.com/initia-labs/move/edit/aptos-move/README.md
---


This project is forked from [Aptos Move](https://github.com/aptos-labs/aptos-core/tree/main/third_party/move) to avoid multi-standard of move language.

## How to fetch latest changes from aptos-core

```shell
# make new subtree branch with latest changes
git subtree split --prefix=third_party/move -b aptos-move

# merge latest changes into our branch
git switch initia-move
git merge aptos-move
```

## How to validate changes

```shell
cargo test \
 --package move-vm-integration-tests \
 --package move-cli \
 --package move-unit-test \
 --package move-compiler \
 --package move-analyzer \
 --package move-stdlib \
 --package move-package \
 --package move-binary-format \
 --package move-bytecode-verifier \
 -- --skip prove
```
