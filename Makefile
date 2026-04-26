CARGO := cargo
WASM_BINDGEN := wasm-bindgen
WASM_OPT := wasm-opt
WASM_OPT_FLAGS := --enable-bulk-memory --enable-nontrapping-float-to-int -O
WASM_TARGET := wasm32-unknown-unknown
TARGET_DIR := target/$(WASM_TARGET)/release
PKG_DIR := pkg
CRATE_NAME := xwing_wasm_rs
CARGO_FLAGS := -C target-feature=+simd128 -C opt-level=3

VERSION := $(shell grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')

# Rust

.PHONY: check build test clean

check:
	$(CARGO) check

build:
	$(CARGO) build --release

test:
	$(CARGO) test

# WASM Tests

.PHONY: test-wasm test-all

test-wasm:
	RUSTFLAGS="$(CARGO_FLAGS)" wasm-pack test --node --features wasm,talc

test-all: test test-wasm

# WASM Build

.PHONY: wasm wasm-clean

wasm:
	RUSTFLAGS="$(CARGO_FLAGS)" $(CARGO) build --target $(WASM_TARGET) --release --features wasm,talc
	@mkdir -p $(PKG_DIR)/bundler $(PKG_DIR)/web $(PKG_DIR)/node
	$(WASM_BINDGEN) --target bundler --out-dir $(PKG_DIR)/bundler --out-name xwing $(TARGET_DIR)/$(CRATE_NAME).wasm
	$(WASM_BINDGEN) --target web --out-dir $(PKG_DIR)/web --out-name xwing $(TARGET_DIR)/$(CRATE_NAME).wasm
	$(WASM_BINDGEN) --target nodejs --out-dir $(PKG_DIR)/node --out-name xwing $(TARGET_DIR)/$(CRATE_NAME).wasm
	@mv $(PKG_DIR)/bundler/xwing_bg.wasm $(PKG_DIR)/xwing_bg.wasm
	@rm -f $(PKG_DIR)/web/xwing_bg.wasm $(PKG_DIR)/node/xwing_bg.wasm
	$(WASM_OPT) $(WASM_OPT_FLAGS) $(PKG_DIR)/xwing_bg.wasm -o $(PKG_DIR)/xwing_bg.wasm
	@node -e "['bundler','web','node'].forEach(d=>{const f='$(PKG_DIR)/'+d+'/xwing.js';require('fs').writeFileSync(f,require('fs').readFileSync(f,'utf8').replace(/xwing_bg\.wasm/g,'../xwing_bg.wasm'))})"
	@rm -f $(PKG_DIR)/bundler/package.json $(PKG_DIR)/web/package.json $(PKG_DIR)/node/package.json
	@rm -f $(PKG_DIR)/bundler/.gitignore $(PKG_DIR)/web/.gitignore $(PKG_DIR)/node/.gitignore
	@cp README.md $(PKG_DIR)/README.md
	@cp LICENSE-MIT $(PKG_DIR)/LICENSE-MIT
	@cp LICENSE-APACHE $(PKG_DIR)/LICENSE-APACHE
	@cp scripts/tpl/index.js.template $(PKG_DIR)/index.js
	@cp scripts/tpl/index.d.ts $(PKG_DIR)/index.d.ts
	@node -e "\
	   const pkg = {\
	      name: 'xwing-wasm-rs',\
	      version: '$(VERSION)',\
	      description: 'X-Wing hybrid KEM (ML-KEM-768 + X25519) via Rust/WASM',\
	      license: 'MIT OR Apache-2.0',\
	      repository: { type: 'git', url: 'https://github.com/UneBaguette/xwing.wasm' },\
	      main: 'index.js',\
	      types: 'index.d.ts',\
	      exports: { '.': {\
	         node: { require: './node/xwing.js', import: './index.js' },\
	         import: './index.js',\
	         default: './web/xwing.js'\
	      }},\
	      files: ['bundler/', 'web/', 'node/', 'index.js', 'index.d.ts', 'xwing_bg.wasm', 'README.md', 'LICENSE-MIT', 'LICENSE-APACHE'],\
	      keywords: ['xwing', 'x-wing', 'kem', 'post-quantum', 'ml-kem', 'x25519', 'wasm', 'crypto']\
	   };\
	   require('fs').writeFileSync('./$(PKG_DIR)/package.json', JSON.stringify(pkg, null, 2) + '\n');"

wasm-clean:
	rm -rf $(PKG_DIR)

# Publish

.PHONY: publish-wasm

publish-wasm: wasm
	cd $(PKG_DIR) && npm publish --access public

# All

.PHONY: all clean-all

all: check test-all wasm

clean-all: wasm-clean
	$(CARGO) clean