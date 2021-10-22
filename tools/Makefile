.PHONY: churn clean clean_auth clean_cache secrets_authority update_cache_churn

AUTH_DIR=authority-private
AUTH_ID=$(AUTH_DIR)/authority_identity_key
AUTH_SIGN=$(AUTH_DIR)/authority_signing_key
AUTH_CERT=$(AUTH_DIR)/certificate.txt
AUTH_AUTH=$(AUTH_DIR)/authority.txt
CACHE_DIR=directory-cache
CACHE_CERT=$(CACHE_DIR)/certificate.txt
CACHE_AUTH=$(CACHE_DIR)/authority.txt
CACHE_CONS=$(CACHE_DIR)/consensus.txt
CACHE_MICRO=$(CACHE_DIR)/microdescriptors.txt

all: update_cache

clean_auth:
	rm -rf $(AUTH_DIR)

authority: pip_install $(AUTH_ID) $(AUTH_SIGN) $(AUTH_CERT) $(AUTH_AUTH)
$(AUTH_ID) $(AUTH_SIGN) $(AUTH_CERT) $(AUTH_AUTH):
ifeq ($(DIR_AUTH_PASSWORD), )
	$(error Environment variable DIR_AUTH_PASSWORD is undefined or invalid.)
endif
	mkdir -p $(AUTH_DIR)
	./gen_fresh_dirinfo.py generate-certificate \
		--authority-identity-key $(AUTH_ID) \
		--authority-signing-key $(AUTH_SIGN) \
		--authority-certificate $(AUTH_CERT) \
		--authority-v3ident $(AUTH_AUTH)

clean_cache:
	rm -rf $(CACHE_DIR)

update_cache: clean_cache cache

cache: $(CACHE_CERT) $(CACHE_AUTH) $(CACHE_CONS) $(CACHE_MICRO)
$(CACHE_CERT) $(CACHE_AUTH) $(CACHE_CONS) $(CACHE_MICRO):
	$(MAKE) authority
	mkdir -p $(CACHE_DIR)
	cp $(AUTH_CERT) $(AUTH_AUTH) $(CACHE_DIR)
	./gen_fresh_dirinfo.py generate-dirinfo \
		--authority-signing-key $(AUTH_SIGN) \
		--authority-certificate $(CACHE_CERT) \
		--consensus $(CACHE_CONS) \
		--microdescriptors $(CACHE_MICRO)

churn: cache
	./gen_fresh_dirinfo.py compute-churn \
		--consensus $(CACHE_DIR)/consensus.txt \
		--churn $(CACHE_DIR)/churn.txt

pip_install: requirements.txt
	pip3 install -qr requirements.txt
	touch pip_install

clean: clean_cache clean_auth

secrets_authority: $(AUTH_DIR)
	tar cjf auth.tgz $(AUTH_DIR) $(CACHE_DIR)/{certificate.txt,authority.txt}
	base64 -i auth.tgz
	rm auth.tgz
	echo $$DIR_AUTH_PASSWORD

# This updates the CACHE_DIR directory:
# - fully every Monday or if the consensus is missing
# - creating a new churn.txt on every day
# It supposes that the
CHURN_WEEK_FILE = $(CACHE_DIR)/churn_week
CHURN_WEEK := $(shell date +%Y_%W)
update_cache_churn: $(CHURN_WEEK_FILE)
	if grep -v $(CHURN_WEEK) $(CHURN_WEEK_FILE); then \
		rm -f $(CACHE_DIR)/*; \
	fi
	if [ $$( date +%w ) = 1 ]; then \
  		rm -f $(CACHE_DIR)/*; \
	fi
	$(MAKE) churn $(CHURN_WEEK_FILE)

$(CHURN_WEEK_FILE):
	echo $(CHURN_WEEK) > $@
