include ../../allmake.mak

ifeq ($(or $(__MAC__),$(__LINUX__)),)
all:
ifdef __X64__
	$(MAKE) -f makefile.win
endif
ifeq ($(__EA64__),$(__X64__))
	$(MAKE) USE_STATIC_RUNTIME=1 -C ../../ env
	export PATH="$$PATH:$(shell cygpath -u $(VSPATH8))Common7/Ide"; $(MAKE) DONT_BUILD_PLUGIN=1 USE_STATIC_RUNTIME=1 -f makefile.win
endif
clean:
	$(MAKE) -f makefile.win clean
else
  include makefile.unx
endif
