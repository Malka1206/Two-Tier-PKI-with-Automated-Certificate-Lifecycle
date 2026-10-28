# =============================================================================
# Two-Tier PKI - Makefile (README section 9)
#
#   make init                 build the whole PKI (root, intermediate, OCSP cert,
#                             server cert, client cert "alice", CRLs)
#   make up / make down       start / stop the OCSP responder and Nginx (mTLS)
#   make test                 run the full test suite
#   make revoke CN=<name>     revoke a certificate and regenerate the CRL
#   make clean                delete all generated PKI material
#
# The root key passphrase must be provided through the environment
# (PKI_ROOT_PASS or PKI_ROOT_PASS_FILE), see pki-tool.
# =============================================================================

SHELL    := bash
PKI_DIR  ?= pki
NGINX    ?= nginx
OPENSSL  ?= openssl
OCSP_PORT ?= 2560

TOOL     := bash ./pki-tool --pki-dir $(PKI_DIR)
RUN_DIR  := $(PKI_DIR)/run
NGX_DIR  := $(PKI_DIR)/nginx

# True when something accepts connections on the Nginx port. Used instead of
# `kill -0` on the Nginx pid file, because under Git Bash the pid written by the
# native Windows nginx.exe is not a process that `kill` can see.
NGX_UP    = (exec 3<>/dev/tcp/127.0.0.1/8443) 2>/dev/null

# Absolute path of the Nginx prefix (native Windows form under Git Bash).
NGX_ABS   = $$(cd $(NGX_DIR) && { pwd -W 2>/dev/null || pwd; })

.PHONY: init up down test revoke clean nginx-prepare

init:
	@$(TOOL) init-root
	@$(TOOL) init-intermediate
	@$(TOOL) gen-ocsp-cert
	@$(TOOL) issue --profile server --cn web.lab.local --san DNS:web.lab.local,IP:127.0.0.1
	@$(TOOL) issue --profile client --cn alice
	@$(TOOL) gen-crl
	@$(TOOL) gen-crl --root

# Copies the PKI files Nginx needs and generates its runtime configuration.
nginx-prepare:
	@test -f $(PKI_DIR)/servers/web.lab.local.crt || { echo "PKI not initialised: run 'make init' first"; exit 1; }
	@mkdir -p $(NGX_DIR)/certs $(NGX_DIR)/logs $(NGX_DIR)/temp
	@cat $(PKI_DIR)/servers/web.lab.local.crt $(PKI_DIR)/intermediate/intermediate.crt > $(NGX_DIR)/certs/server.crt
	@cp -f $(PKI_DIR)/servers/web.lab.local.key $(NGX_DIR)/certs/server.key
	@cp -f $(PKI_DIR)/ca-chain.crt $(NGX_DIR)/certs/ca-chain.crt
	@cp -f $(PKI_DIR)/crl-chain.pem $(NGX_DIR)/certs/crl-chain.pem
	@abs="$(NGX_ABS)"; \
	  sed "s#/etc/nginx/certs#$$abs/certs#g" services/nginx/nginx.conf > $(NGX_DIR)/nginx.conf

up: nginx-prepare
	@mkdir -p $(RUN_DIR)
	@if [ -f $(RUN_DIR)/ocsp.pid ] && kill -0 "$$(cat $(RUN_DIR)/ocsp.pid)" 2>/dev/null; then \
	  echo "OCSP responder already running"; \
	else \
	  nohup $(OPENSSL) ocsp -index $(PKI_DIR)/intermediate/index.txt \
	    -port $(OCSP_PORT) \
	    -rsigner $(PKI_DIR)/ocsp/ocsp.crt -rkey $(PKI_DIR)/ocsp/ocsp.key \
	    -CA $(PKI_DIR)/intermediate/intermediate.crt \
	    > $(RUN_DIR)/ocsp.log 2>&1 & echo $$! > $(RUN_DIR)/ocsp.pid; \
	  echo "OCSP responder started on port $(OCSP_PORT)"; \
	fi
	@abs="$(NGX_ABS)"; \
	if $(NGX_UP); then \
	  echo "Nginx already running on port 8443 (use 'make down' first to restart it)"; \
	else \
	  $(NGINX) -p "$$abs/" -c "$$abs/nginx.conf" && echo "Nginx started on https://web.lab.local:8443/"; \
	fi

down:
	@if [ -f $(NGX_DIR)/nginx.conf ] && [ -f $(NGX_DIR)/logs/nginx.pid ]; then \
	  abs="$(NGX_ABS)"; \
	  $(NGINX) -p "$$abs/" -c "$$abs/nginx.conf" -s stop 2>/dev/null && echo "Nginx stopped" || true; \
	fi
	@if [ -f $(RUN_DIR)/ocsp.pid ]; then \
	  kill "$$(cat $(RUN_DIR)/ocsp.pid)" 2>/dev/null && echo "OCSP responder stopped" || true; \
	  rm -f $(RUN_DIR)/ocsp.pid; \
	fi

test:
	@bash tests/run-all.sh

# make revoke CN=alice [REASON=keyCompromise]
revoke:
	@test -n "$(CN)" || { echo "usage: make revoke CN=<name> [REASON=<reason>]"; exit 1; }
	@cert=""; \
	for d in clients servers codesign; do \
	  if [ -f $(PKI_DIR)/$$d/$(CN).crt ]; then cert=$(PKI_DIR)/$$d/$(CN).crt; break; fi; \
	done; \
	[ -n "$$cert" ] || { echo "no certificate found for CN=$(CN)"; exit 1; }; \
	serial="$$($(OPENSSL) x509 -in $$cert -noout -serial | cut -d= -f2)"; \
	$(TOOL) revoke --serial $$serial $(if $(REASON),--reason $(REASON)) && \
	$(TOOL) gen-crl
	@# 'openssl ocsp' reloads its database only after answering a request, so send a
	@# throwaway query to make the next real answer reflect this revocation.
	@if [ -f $(RUN_DIR)/ocsp.pid ] && kill -0 "$$(cat $(RUN_DIR)/ocsp.pid)" 2>/dev/null; then \
	  $(OPENSSL) ocsp -issuer $(PKI_DIR)/intermediate/intermediate.crt -serial 0x01 -no_nonce \
	    -url http://127.0.0.1:$(OCSP_PORT) >/dev/null 2>&1 || true; \
	fi
	@if [ -d $(NGX_DIR)/certs ]; then \
	  cp -f $(PKI_DIR)/crl-chain.pem $(NGX_DIR)/certs/crl-chain.pem; \
	  if $(NGX_UP); then \
	    abs="$(NGX_ABS)"; \
	    $(NGINX) -p "$$abs/" -c "$$abs/nginx.conf" -s reload && sleep 1 && echo "Nginx reloaded with the new CRL"; \
	  fi; \
	fi

clean: down
	@test -n "$(PKI_DIR)" && test "$(PKI_DIR)" != "/" || { echo "refusing to clean '$(PKI_DIR)'"; exit 1; }
	@rm -rf $(PKI_DIR)
	@echo "Deleted $(PKI_DIR)"
