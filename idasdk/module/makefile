include ../allmake.mak

ALLDIRS := 6502      \
           65816     \
           78k0      \
           78k0s     \
           80196     \
           arc       \
           avr       \
           c39       \
           cr16      \
           dsp56k    \
           f2mc      \
           fr        \
           h8        \
           h8500     \
           hppa      \
           i51       \
           i860      \
           i960      \
           java      \
           kr1878    \
           m32r      \
           m740      \
           m7700     \
           m7900     \
           mn102     \
           nec850    \
           oakdsp    \
           pdp11     \
           pic       \
           sam8      \
           script    \
           st20      \
           st7       \
           st9       \
           tlcs900   \
           tms320c1  \
           tms320c3  \
           tms320c5  \
           tms320c54 \
           tms320c55 \
           tms320c6  \
           xa        \
           z8        \
           z80       \

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
