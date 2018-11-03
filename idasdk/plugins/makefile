include ../allmake.mak

ALLDIRS := callee      \
           callgraph   \
           choose      \
           custdata    \
           custview    \
           debugger    \
           ex_debidc   \
           ex_events1  \
           extlang     \
           findcrypt2  \
           formchooser \
           formsample  \
           funclist    \
           getlines    \
           hello       \
           hexview     \
           highlighter \
           ht_output   \
           ht_view     \
           mtsample    \
           navcolor    \
           openform    \
           pdb         \
           procext     \
           script_plg  \
           snapshots   \
           tracer      \
           tracing_api \
           ugraph      \
           ugraph3     \
           ui_requests \
           uiswitch    \
           vcsample    \

ifdef 0
# TODO these do not build
# add plugin that depend on Qt (if Qt is available)
ifneq ($(wildcard $(QTDIR)),)
  ALLDIRS += qwindow qproject
endif

endif

# add windows-specific plugin
ifdef __NT__
  ALLDIRS += uunp
endif

ifndef __X64__
ALLDIRS = debugger
endif

.PHONY: $(ALLDIRS)
all:    $(ALLDIRS)

$(ALLDIRS):
	@$(MAKE) -C $@

clean:: $(addprefix clean-,$(ALLDIRS))

clean-%::
	$(MAKE) -s -C $* clean
