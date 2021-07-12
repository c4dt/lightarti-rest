all:	directory-cache

authority_certificate:
	@echo "Please copy authority_* files to this directory"
	exit 1

directory-cache: authority_certificate pip_install
	mkdir -p directory-cache
	./gen_fresh_dirinfo.py generate-dirinfo --consensus directory-cache/consensus.txt --microdescriptors directory-cache/microdescriptors.txt

pip_install: requirements.txt
	pip3 install -qr requirements.txt
	touch pip_install

