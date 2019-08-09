short_ver = 2
long_ver = $(shell (git describe --tags --long '--match=v*' 2>/dev/null || echo $(short_ver)-0-unknown) | cut -c2-)

MODULE_big = amcheck_next
OBJS       = bloomfilter.o verify_nbtree.o $(WIN32RES)

EXTENSION  = amcheck_next
DATA       = amcheck_next--1.sql amcheck_next--2.sql amcheck_next--1--2.sql
PGFILEDESC = "amcheck_next - functions for verifying relation integrity"
DOCS       = README.md
REGRESS    = install_amcheck_next check_btree

ifdef USE_PGXS
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
else
subdir = contrib/cube
top_builddir = ../..
include $(top_builddir)/src/Makefile.global
include $(top_srcdir)/contrib/contrib-global.mk
endif

DEBUILD_ROOT = /tmp/amcheck

deb:
	mkdir -p $(DEBUILD_ROOT) && rm -rf $(DEBUILD_ROOT)/*
	rsync -Ca --exclude=build/* ./ $(DEBUILD_ROOT)/
	cd $(DEBUILD_ROOT) && make -f debian/rules orig
	cd $(DEBUILD_ROOT) && debuild -us -uc -sa
	cp -a /tmp/amcheck_* /tmp/postgresql-[91]* build/
