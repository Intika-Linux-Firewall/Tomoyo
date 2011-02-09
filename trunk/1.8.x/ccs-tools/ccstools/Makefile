all:
	$(MAKE) -C sbin all
	$(MAKE) -C usr_sbin all
	$(MAKE) -C usr_lib_ccs all

install: all
	$(MAKE) -C sbin install
	$(MAKE) -C usr_sbin install
	$(MAKE) -C usr_lib_ccs install
	$(MAKE) -C usr_share_man install

clean:
	$(MAKE) -C sbin clean
	$(MAKE) -C usr_sbin clean
	$(MAKE) -C usr_lib_ccs clean

.PHONY: clean install
