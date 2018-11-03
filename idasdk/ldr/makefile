_CFLAGS=-Ipe
include ../allmake.mak

ALLDIRS := aif         \
           amiga       \
           aof         \
           aout        \
           dos         \
           dump        \
           geos        \
           hex         \
           hpsom       \
           intelomf    \
           javaldr     \
           mas         \
           nlm         \
           os9         \
           pilot       \
           qnx         \
           rt11        \
           script_ldrs \
           snes        \
           w32run      \

ifndef __X64__
ALLDIRS=
endif

.PHONY: $(ALLDIRS)
all:    $(ALLDIRS)

$(ALLDIRS):
	@$(MAKE) -C $@

clean:: $(addprefix clean-,$(ALLDIRS))

clean-%::
	$(MAKE) -s -C $* clean
