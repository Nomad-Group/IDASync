include ../../allmake.mak

ifndef DONT_BUILD_PLUGIN
ifneq ("$(wildcard $(QTDIR)/bin/qmake)","")
    # under ms windows this plugin can be built only with visual studio
    ifdef __VC__
      BUILD_QWINDOW=1
    endif

    ifndef __NT__
      BUILD_QWINDOW=1
    endif
  endif
endif

ifdef BUILD_QWINDOW
  ifdef __MAC__
    TMPOUT = libqwindow.dylib
    # We must change the library path in the plugin so they become relative
    # to the idaq executable. Otherwise the plugin loads the second copy of
    # these libraries and crashes IDA
    ifdef NDEBUG
    CHANGE_LIBPATH=install_name_tool -change \
               @rpath/$1.framework/Versions/5/$1 \
               @executable_path/../Frameworks/$1.framework/Versions/5/$1 $@
    else
    CHANGE_LIBPATH=install_name_tool -change \
               @rpath/$1.framework/Versions/5/$1 \
               @executable_path/../Frameworks/$1.framework/Versions/5/$1_debug $@
    endif
  endif
  ifdef __NT__
    TMPOUT = qwindow_nt.dll
    ifdef NDEBUG
      NMAKE_TARGET = release
      NMAKEFILE = qmakefile.raw.Release
    else
      NMAKE_TARGET = debug
      NMAKEFILE = qmakefile.raw.Debug
    endif
    MSINC=$(MSSDK)include/um;$(MSSDK)include/shared
    VCINC=$(1)VC/Include;$(2);$(MSINC)
    ifdef __X64__
      MSLIB=$(MSSDK)lib/x64
      VCBIN=$(1)VC/bin/amd64;$(1)Common7/Ide;$(MSSDK)bin;$(1)VC/bin$(if $(QTDIR),;$(QTDIR)bin,)
      VCLIB=$(1)VC/Lib/amd64;$(if $(2),;$(2)x64,);$(MSLIB)
    else
      MSLIB=$(MSSDK)lib/x86
      VCBIN=$(1)VC/bin;$(1)Common7/Ide$(if $(MSSDK),;$(MSSDK)bin,)$(if $(QTDIR),;$(QTDIR)bin,)
      VCLIB=$(1)VC/Lib;$(if $(2),;$(2)x86,);$(MSLIB)
    endif
  endif
  ifdef __LINUX__
    TMPOUT = libqwindow.so
  endif

# Default target; don't call it "all" as it would conflict with plugin.mak
# We can't depend directly on $(BINARY) as it is defined in plugin.mak.
all_qwindow: all_qwindow2
PROC = qwindow
include ../plugin.mak
# Wait until plugin.mak defines $(BINARY)
all_qwindow2: output/$(TMPOUT)

OBJS=$(F)qwindow$(O) $(F)moc_myactions$(O)

# Don't set target to $(BINARY): it would inherit dependencies on Windows
output/$(TMPOUT): objdir qmakefile qwindow.cpp myactions.h ../../plugins/plugin.script
	[ -e output ] || mkdir output
ifdef __NT__
	@echo "#!/bin/bash" > nmake.sh
	@echo "export LIB='$(call VCLIB,$(VSPATH),$(UCRT_LIB))'" >> nmake.sh
	@echo "export LIBDIR=../../lib/$(SYSDIR)" >> nmake.sh
	@echo "export INCLUDE='$(call VCINC,$(VSPATH),$(UCRT_INCLUDE))'" >> nmake.sh
	@echo "export O='$(O)'" >> nmake.sh
	@echo "export I='$(I)'" >> nmake.sh
	@echo "export F='$(F)'" >> nmake.sh
	@echo "unset MAKEFLAGS" >> nmake.sh
	@echo -n "export PATH=\"" >> nmake.sh
	@echo -n `cygpath -u -p "$(call VCBIN,$(VSPATH)):$$"` >> nmake.sh
	@echo "PATH\"" >> nmake.sh
	@echo "$(MSVCDIR)bin/nmake -nologo -f qmakefile $(NMAKE_TARGET)" >> nmake.sh
	chmod +x nmake.sh
	./nmake.sh
else
	$(MAKE) -f qmakefile
endif
ifdef __MAC__
	$(call CHANGE_LIBPATH,QtWidgets)
	$(call CHANGE_LIBPATH,QtGui)
	$(call CHANGE_LIBPATH,QtCore)
endif
	$(CP) output/$(TMPOUT) $(BINARY)

# This is passed to the shell; make sure to double backslashes
# Don't assume it's GNU sed (on OSX)
define SED_QMAKEFILE
1i\\
include ../../allmake.mak
/^CC /d
/^CXX /d
s/LINKER\s.*/LINKER = $$(CXX)/
s/^\(C\(XX\)\{0,1\}FLAGS\).*/\\1 = $(subst /,\/,$(CFLAGS)) $$(DEFINES)/
/^LINK\s/a\\
LINK += $(subst /,\/,$(PLUGIN_SCRIPT) $(PDBSW))
s/^first:\(.*\)/first: objdir \\1/
/^first:/a\\
include ../../objdir.mak
endef
export SED_QMAKEFILE
# This goes through an intermediate makefile as desired results can't be
# achieved directly with qmake.  Merge standard build system into the generated
# makefile.
qmakefile: qmakefile.raw makefile
ifdef __NT__
	$(CP) $< $@
else
	echo "$$SED_QMAKEFILE" > qmakefile.sed
	sed -f qmakefile.sed < $< > $@
endif


# Always rebuild it as it depends on environment (NDEBUG, ...)
.PHONY: qmakefile.raw
qmakefile.raw: qwindow.pro
ifdef __NT__
	cat $< | sed \
		'/^DEFINES /a\DEFINES += __NT__=1' \
		> qwindow_nt.pro
	$(QTDIR)/bin/qmake -Wnone qwindow_nt.pro
else
	$(QTDIR)/bin/qmake -Wnone qwindow.pro
endif

else
# not BUILD_QWINDOW
define CANT_BUILD
Skipping plugins/qwindow: no QT found in $(subst \,\\,$(QTDIR)).
Make sure QT is installed and try rebuilding.  If QT is installed in another
folder, set the QTDIR environment variable to its name with a trailing slash.
endef
export CANT_BUILD
all_qwindow:
	@echo "$$CANT_BUILD"
endif
