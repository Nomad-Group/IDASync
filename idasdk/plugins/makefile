include ../allmake.mak

# do not compile examples by default
ifdef PLUGIN_EXAMPLES
  EXAMPLES:=ex_1argtype ex_colors1 ex_colors2 ex_colors3 ex_debidc ex_events1 \
	    ex_events2 ex_extract ex_graph ex_lvars ex_procext
endif

SAMPLES:=vcsample ugraph ugraph2 ugraph3 mtsample formsample formchooser \
	 funclist getlines procext custdata custview qwindow hexview openform

ALLDIRS:=idapython bdescr nextfix callee dwarf makeidt search unpack samout    \
	 makefop $(SAMPLES) $(EXAMPLES) ntvdd char2oem comhelper lsbn choose2  \
	 mc12dg128 pdb tds uunp stealth uiswitch script_plg                    \
	 grep snaptest tracing_api $(ADDITIONAL_PLUGINS)

# remove any missing plugins from the list
ALLDIRS:=$(wildcard $(ALLDIRS))

# remove plugins that depend on the kernel source code
ifeq ($(wildcard ../ida),)
  ALLDIRS:=$(filter-out pdb,$(ALLDIRS))
endif

# remove plugins that depend on pc source code
ifeq ($(wildcard ../module/pc),)
  ALLDIRS:=$(filter-out bdescr uiswitch,$(ALLDIRS))
endif

# remove plugins that depend on arm source code
ifeq ($(wildcard ../module/arm),)
  ALLDIRS:=$(filter-out callee,$(ALLDIRS))
endif

# remove plugins that depend on i51 source code
ifeq ($(wildcard ../module/i51),)
  ALLDIRS:=$(filter-out makefop,$(ALLDIRS))
endif

# remove plugins that depend on dbg loader source code
ifeq ($(wildcard ../ldr/dbg),)
  ALLDIRS:=$(filter-out tds,$(ALLDIRS))
endif

# idapython can be built only in 32-bit mode
ifdef __X64__
  ALLDIRS:=$(filter-out idapython,$(ALLDIRS))
endif

# remove plugins that can not compile in the current os
ifndef __NT__
  ALLDIRS:=$(filter-out stealth uunp,$(ALLDIRS))
endif

ifdef __X64__
  ALLDIRS:=debugger
endif

.PHONY: $(ALLDIRS)

all:    $(ALLDIRS)

$(ALLDIRS):
	@cd $@; $(MAKE)
