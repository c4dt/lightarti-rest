all:	directory-cache

directory-cache: pip
	@if [[ ! -f authority_certificate ]]; then \
	  echo "Please copy authority_* files to this directory"; \
	  false; \
	fi
	mkdir -f directory
	./gen_fresh_dirinfo.py
	mv consensus.txt microdescriptors.txt directory

pip:
	pip3 install -qr requirements.txt

