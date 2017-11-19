
include ../../allmake.mak

LDRDIR=$(R)loaders
LOADERS = bios_image.py hppacore.idc wince.py pdfldr.py uimage.py

all: $(addprefix $(LDRDIR)/, $(LOADERS))

$(LDRDIR)/%.idc: ./%.idc
	$(CP) $? $@

$(LDRDIR)/%.py: ./%.py
	$(CP) $? $@
