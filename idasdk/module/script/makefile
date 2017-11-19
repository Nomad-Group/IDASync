include ../../allmake.mak

all:    ebc msp430

ebc: $(R)procs/ebc.py
$(R)procs/ebc.py: ebc.py
	$(CP) $? $@

msp430: $(R)procs/msp430.py
$(R)procs/msp430.py: msp430.py
	$(CP) $? $@
