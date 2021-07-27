.PHONY: certificate dirinfo check-password

AUTH_DIR=authority-private
DIR_CACHE=directory-cache

all: dirinfo

$(AUTH_DIR): pip_install check-password
	mkdir -p $(AUTH_DIR)
	mkdir -p $(DIR_CACHE)
	./gen_fresh_dirinfo.py generate-certificate \
		--authority-identity-key $(AUTH_DIR)/authority_identity_key \
		--authority-signing-key $(AUTH_DIR)/authority_signing_key \
		--authority-certificate $(DIR_CACHE)/certificate.txt \
		--authority-v3ident $(DIR_CACHE)/authority.txt

dirinfo: $(AUTH_DIR)
	./gen_fresh_dirinfo.py generate-dirinfo \
		--authority-signing-key $(AUTH_DIR)/authority_signing_key \
		--authority-certificate $(DIR_CACHE)/certificate.txt \
		--consensus $(DIR_CACHE)/consensus.txt \
		--microdescriptors $(DIR_CACHE)/microdescriptors.txt

pip_install: requirements.txt
	pip3 install -qr requirements.txt
	touch pip_install

check-password:
ifeq ($(DIR_AUTH_PASSWORD), )
	$(error Environment variable DIR_AUTH_PASSWORD is undefined or invalid.)
endif
