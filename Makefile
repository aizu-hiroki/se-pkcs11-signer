# se-pkcs11-signer build helpers.
#
# No code-signing entitlements are required: Secure Enclave keys are stored as
# CryptoKit blob files, not in the keychain. Ad-hoc signing (the swiftc/Go
# default) is sufficient.

SHELL := /bin/bash

CONFIG      ?= release
BUILD_DIR   := .build/$(CONFIG)
DYLIB       := $(BUILD_DIR)/libse-pkcs11-signer.dylib
KEYGEN      := $(BUILD_DIR)/se-pkcs11-signer-keygen

INSTALL_DIR ?= /usr/local/lib/se-pkcs11-signer
KEY_DIR     ?= $(HOME)/.se-pkcs11-signer/keys
TOKEN_LABEL ?= Secure Enclave

.PHONY: help build symbols clean install csr install-cert print-config

.DEFAULT_GOAL := help

help:
	@echo "usage: make <target>"
	@echo
	@echo "  build         build the dylib and keygen CLI"
	@echo "  symbols       list the dylib's exported C_* PKCS#11 symbols"
	@echo "  clean         remove build artifacts"
	@echo "  install       install the built dylib to a system location"
	@echo "  csr           create a Secure Enclave key and emit a CSR for your CA"
	@echo "  install-cert  install a CA-issued certificate and print the spire agent config"
	@echo "  print-config  print the spire agent plugin_data block for an existing key"

build:
	swift build -c $(CONFIG)

symbols: build
	nm -gU $(DYLIB) | grep " _C_"

clean:
	swift package clean

# Copies the built dylib to a system location. Runs with sudo since the
# target directory should not be writable by unprivileged users: whoever can
# replace this file controls what signs with the Secure Enclave key.
install: build
	@read -e -p "install directory [$(INSTALL_DIR)]: " dir; \
	dir=$${dir:-$(INSTALL_DIR)}; \
	dest="$$dir/libse-pkcs11-signer.dylib"; \
	echo "installing -> $$dest (sudo required)"; \
	sudo mkdir -p "$$dir"; \
	sudo cp "$(DYLIB)" "$$dest"; \
	sudo chown root:wheel "$$dest"; \
	sudo chmod 644 "$$dest"; \
	echo "done."; \
	echo "module_path for the spire agent config: $$dest"

# Creates the Secure Enclave key (if it doesn't already exist) and emits a
# PKCS#10 CSR. Hand the CSR to your CA, then run 'make install-cert'.
csr: build
	@read -e -p "key dir [$(KEY_DIR)]: " dir; dir=$${dir:-$(KEY_DIR)}; \
	read -p "key label: " label; \
	if [ -z "$$label" ]; then echo "error: label is required" >&2; exit 1; fi; \
	read -p "CSR common name (CN) [$$label]: " cn; cn=$${cn:-$$label}; \
	read -p "SPIFFE/URI SAN(s), comma-separated (blank to skip): " uri_csv; \
	read -p "DNS SAN(s), comma-separated (blank to skip): " dns_csv; \
	read -e -p "output CSR path [./$$label.csr]: " out; out=$${out:-./$$label.csr}; \
	if [ ! -f "$$dir/$$label.sekey" ]; then \
		echo "no existing key for label '$$label', creating..."; \
		"$(KEYGEN)" create --label "$$label" --dir "$$dir" || exit 1; \
	fi; \
	san_args=(); \
	if [ -n "$$uri_csv" ]; then IFS=',' read -ra uris <<< "$$uri_csv"; \
		for u in "$${uris[@]}"; do san_args+=(--uri "$$u"); done; fi; \
	if [ -n "$$dns_csv" ]; then IFS=',' read -ra dnss <<< "$$dns_csv"; \
		for d in "$${dnss[@]}"; do san_args+=(--dns "$$d"); done; fi; \
	"$(KEYGEN)" csr --label "$$label" --dir "$$dir" --cn "$$cn" --out "$$out" "$${san_args[@]}"; \
	echo; \
	echo "hand $$out to your CA, then run: make install-cert"

# Installs a certificate received from the CA next to the key it was issued
# for, then prints the spire agent plugin_data block.
install-cert:
	@read -e -p "key dir [$(KEY_DIR)]: " dir; dir=$${dir:-$(KEY_DIR)}; \
	read -p "key label: " label; \
	if [ -z "$$label" ]; then echo "error: label is required" >&2; exit 1; fi; \
	if [ ! -f "$$dir/$$label.sekey" ]; then echo "error: no such key: $$dir/$$label.sekey" >&2; exit 1; fi; \
	read -e -p "path to certificate from CA: " cert; \
	if [ -z "$$cert" ] || [ ! -f "$$cert" ]; then echo "error: certificate file not found: $$cert" >&2; exit 1; fi; \
	dest="$$dir/$$label.crt.pem"; \
	cp "$$cert" "$$dest"; \
	echo "installed certificate -> $$dest"; \
	echo; \
	$(MAKE) --no-print-directory print-config _KEY_DIR="$$dir" _LABEL="$$label" _CERT_PATH="$$dest"

# Prints the spire agent NodeAttestor "x509pop_pkcs11" plugin_data block for
# an existing key (and, if present, its installed certificate).
print-config: build
	@dir="$(_KEY_DIR)"; label="$(_LABEL)"; cert="$(_CERT_PATH)"; \
	if [ -z "$$label" ]; then \
		read -e -p "key dir [$(KEY_DIR)]: " d; dir=$${d:-$(KEY_DIR)}; \
		read -p "key label: " label; \
	fi; \
	if [ -z "$$label" ]; then echo "error: label is required" >&2; exit 1; fi; \
	sekey="$$dir/$$label.sekey"; \
	if [ ! -f "$$sekey" ]; then echo "error: no such key: $$sekey" >&2; exit 1; fi; \
	if [ -z "$$cert" ]; then cert="$$dir/$$label.crt.pem"; fi; \
	if [ ! -f "$$cert" ]; then \
		read -e -p "certificate path [$$cert]: " c; cert=$${c:-$$cert}; \
	fi; \
	keyid=$$("$(KEYGEN)" list --dir "$$dir" | sed -n "s/^  $$label: id=\(.*\)$$/\1/p"); \
	read -e -p "installed dylib path [$(INSTALL_DIR)/libse-pkcs11-signer.dylib]: " modpath; \
	modpath=$${modpath:-$(INSTALL_DIR)/libse-pkcs11-signer.dylib}; \
	read -p "token label [$(TOKEN_LABEL)]: " tlabel; tlabel=$${tlabel:-$(TOKEN_LABEL)}; \
	echo; \
	echo 'NodeAttestor "x509pop_pkcs11" {'; \
	echo '  plugin_cmd  = "/usr/local/bin/spire-plugin-pkcs11-agent"'; \
	echo '  plugin_data {'; \
	echo "    module_path      = \"$$modpath\""; \
	echo "    token_label      = \"$$tlabel\""; \
	echo "    key_id           = \"$$keyid\""; \
	echo "    key_label        = \"$$label\""; \
	echo "    certificate_path = \"$$cert\""; \
	echo '  }'; \
	echo '}'
