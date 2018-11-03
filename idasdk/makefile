include allmake.mak
ifndef __UNIX__
  CFGFILE := makeenv_vc.mak
  ENV := env
endif

ALLDIRS=module ldr plugins

.PHONY: env $(ALLDIRS) all

all: $(ENV) allbin

env:
	@$(MAKE) -f $(CFGFILE)

allbin: $(ENV) $(ALLDIRS)

$(ALLDIRS): $(ENV)
	$(MAKE) -C $@
###

clean:: $(addprefix clean-,$(ALLDIRS))

clean-%::
	$(MAKE) -s -C $* clean

clean-all::
	$(MAKE) -s NDEBUG=  __EA64__=  __X64__=  clean
	$(MAKE) -s NDEBUG=  __EA64__=  __X64__=1 clean
	$(MAKE) -s NDEBUG=  __EA64__=1 __X64__=1 clean
	$(MAKE) -s NDEBUG=1 __EA64__=  __X64__=  clean
	$(MAKE) -s NDEBUG=1 __EA64__=  __X64__=1 clean
	$(MAKE) -s NDEBUG=1 __EA64__=1 __X64__=1 clean

build-all-opt:
	$(MAKE) -s NDEBUG=1 __EA64__=  __X64__=
	$(MAKE) -s NDEBUG=1 __EA64__=  __X64__=1
	$(MAKE) -s NDEBUG=1 __EA64__=1 __X64__=1
