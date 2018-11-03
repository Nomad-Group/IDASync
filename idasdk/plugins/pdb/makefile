PROC=pdb

include ../../allmake.mak
ifdef __NT__
  O1=old
endif
ADDITIONAL_GOALS=cfg
ifdef __VC__
  ADDITIONAL_LIBS=oleaut32.lib ole32.lib
endif

include ../plugin.mak

#__CFLAGS=/wd4191

cfg: $(C)pdb.cfg
$(C)pdb.cfg: pdb.cfg
	$(CP) $? $@


# MAKEDEP dependency list ------------------
$(F)old$(O)     : $(I)auto.hpp $(I)bitrange.hpp $(I)bytes.hpp               \
	          $(I)config.hpp $(I)err.h $(I)fpro.h $(I)funcs.hpp         \
	          $(I)ida.hpp $(I)idp.hpp $(I)kernwin.hpp $(I)lines.hpp     \
	          $(I)llong.hpp $(I)nalt.hpp $(I)netnode.hpp $(I)pro.h      \
	          $(I)range.hpp $(I)segment.hpp $(I)ua.hpp $(I)xref.hpp     \
	          cvconst.h dbghelp.h old.cpp oldpdb.h
$(F)pdb$(O)     : $(I)allins.hpp $(I)auto.hpp $(I)bitrange.hpp              \
	          $(I)bytes.hpp $(I)config.hpp $(I)dbg.hpp                  \
	          $(I)demangle.hpp $(I)diskio.hpp $(I)err.h $(I)fpro.h      \
	          $(I)frame.hpp $(I)funcs.hpp $(I)ida.hpp $(I)idd.hpp       \
	          $(I)idp.hpp $(I)intel.hpp $(I)kernwin.hpp $(I)lines.hpp   \
	          $(I)llong.hpp $(I)loader.hpp $(I)md5.h $(I)nalt.hpp       \
	          $(I)name.hpp $(I)netnode.hpp $(I)pro.h $(I)range.hpp      \
	          $(I)segment.hpp $(I)struct.hpp $(I)typeinf.hpp            \
	          $(I)ua.hpp $(I)workarounds.hpp $(I)xref.hpp               \
	          ../../ldr/pe/cor.h ../../ldr/pe/corhdr.h                  \
	          ../../ldr/pe/mycor.h ../../ldr/pe/pe.h                    \
	          ../../plugins/debugger/consts.h                           \
	          ../../plugins/debugger/rpc_hlp.h                          \
	          ../../plugins/debugger/win32_rpc.h common.cpp common.h    \
	          cvconst.h dia2.h misc.cpp oldpdb.h pdb.cpp pdb.hpp        \
	          pdbaccess.cpp pdbaccess.hpp pdblocal.cpp pdblocal.hpp     \
	          pdbreg.cpp pdbreg.hpp pdbremote.cpp pdbremote.hpp         \
	          sip.cpp tilbuild.cpp tilbuild.hpp varser.hpp
