PROC=tracing_api
include ../plugin.mak

# MAKEDEP dependency list ------------------
$(F)tracer$(O)  :
$(F)tracing_api$(O): $(I)area.hpp $(I)bitrange.hpp $(I)bytes.hpp $(I)dbg.hpp    \
	          $(I)fpro.h $(I)funcs.hpp $(I)ida.hpp $(I)idd.hpp          \
	          $(I)idp.hpp $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp   \
	          $(I)loader.hpp $(I)nalt.hpp $(I)netnode.hpp $(I)pro.h     \
	          $(I)segment.hpp $(I)ua.hpp $(I)xref.hpp tracing_api.cpp
