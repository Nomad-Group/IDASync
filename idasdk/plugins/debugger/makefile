
# This makefile may call itself recursively with ASYNC=1

ifneq ($(wildcard ../../parse),)
  ENABLE_LOWCNDS=1
endif
ifneq ($(wildcard ../../ida),)
  ifndef __CEARM__
    ENABLE_REMOTEPDB=1
  endif
endif

# first build win32 local debugger plugin (if not ASYNC)
ifdef ASYNC
  CEFLAGS=-DUSE_ASYNC
  DONT_BUILD_PLUGIN=1
else
  PROC=win32_user
endif

ifneq ($(or $(__ANDROID__),$(__CEARM__),$(__ARMLINUX__),$(USE_STATIC_RUNTIME)),)
  ALLDIRS=
  DONT_BUILD_PLUGIN=1
  ifdef __CEARM__
    MODULES=win32_server kdstub wincetst
    ifndef ASYNC
      MAKE_ASYNC=async
    endif
  else ifdef __ANDROID__
    MODULES=android_server
  else ifdef USE_STATIC_RUNTIME
    O1=win32_debmod
    O2=winbase_debmod
    O3=pc_debmod
    ifdef __X64__
      SERVER=win32_server
    endif
    ifndef __EA64__
      SERVER=win32_server
    endif
  else
    MODULES=arm$(SYSNAME)_server
  endif
else
  ifdef ASYNC
    MODULES=wince_stub
  else
    MAKE_ASYNC=async
    O1=win32_debmod
    O2=winbase_debmod
    O3=pc_debmod
    ifdef __X64__
      SERVER=win32_server
      DONT_BUILD_PLUGIN=1
    endif
    ifndef __EA64__
      SERVER=win32_server
    endif
    MODULES=cfg           \
  	  win32_stub      \
  	  linux_stub      \
  	  armlinux_stub   \
  	  mac_stub        \
  	  wince_stub      \
  	  epoc_user       \
  	  $(WINDBG_USER)  \
  	  iphone_stub     \
  	  $(BOCHS_USER)   \
  	  gdb_user        \
          replay_user     \
#	  tracer chktrk
  endif
endif
O4=debmod
ifdef ENABLE_LOWCNDS
  O5=idcfuncs
endif
O6=win32_server_stub
O7=w32sehch
ADDITIONAL_GOALS=$(ALLDIRS) $(SERVER) $(MODULES) $(MAKE_ASYNC)

ifdef __X64__
  DONT_BUILD_PLUGIN=1
  MODULES=
endif

include ../plugin.mak

# all debug servers should go under the dbgsrv directory
SERVERBIN=$(R)dbgsrv/

ifdef ASYNC
  F=$(OBJDIR)_async/
$(OBJDIR)_async/%$(O): %.cpp
	$(CXX) $(CFLAGS) -c $(OBJSW)$@ $<
endif

async:
	@[ -d $(OBJDIR)_async ] || mkdir -p $(OBJDIR)_async
	@$(MAKE) ASYNC=1

ifdef ENABLE_LOWCNDS
  LOWCND_FLAGS=-DENABLE_LOWCNDS
  LOWCND_LIBS=$(L)idc$(A)
  LOWCND_OBJS=$(F)idcfuncs$(O) $(L)dbgsrv_funcs$(O)
endif

ifdef ENABLE_REMOTEPDB
  REMOTEPDB_FLAGS=-DENABLE_REMOTEPDB
  ifdef __NT__
    OLE32=ole32.lib
    REMOTEPDB_LIBS=$(L)til$(A)
    REMOTEPDB_SYSLIBS=oleaut32.lib $(OLE32)
    REMOTEPDB_OBJS=$(F)tilfuncs$(O)
  endif
endif
__CFLAGS=$(LOWCND_FLAGS) $(REMOTEPDB_FLAGS) -Ibochs_ctrl/$(F) $(CEFLAGS) -D_ITERATOR_DEBUG_LEVEL=0 -wd4574

.PHONY: $(ADDITIONAL_GOALS) kdstub async

ifdef __X64__
  DEFFILE=../plugin64.def
else
  DEFFILE=../plugin.def
endif

RPC_COMMON=$(F)rpc_hlp$(O) $(F)rpc_engine$(O) $(F)util$(O)
STUB_COMMON=$(RPC_COMMON) $(F)rpc_client$(O) $(F)rpc_debmod$(O) $(F)debmod$(O)
SERVER_COMMON=$(F)server$(O) $(RPC_COMMON) $(F)rpc_server$(O) $(DUMB) \
	      $(F)debmod$(O) $(LOWCND_OBJS)
#----------------------------------------------------------------------------
ifdef __X64__
  WIN32SERVER=$(SERVERBIN)win64_remote$(B)
  SERVER_TRANS=$(F)tcpip$(O)
  SERVER_OBJS=$(OBJ2) $(OBJ3) $(F)win32_server_impl$(O)
else ifdef __CEARM__
  ifdef ASYNC
    WIN32SERVER=$(SERVERBIN)wince_remote_arm.dll
    SERVER_TRANS=$(F)async$(O)
    CREATE_DLL=/LD
  else
    WIN32SERVER=$(SERVERBIN)wince_remote_tcp$(B)
    SERVER_TRANS=$(F)tcpip$(O)
  endif
  ARM_RTTI_LIB=ccrtrtti.lib
  ACCESSCOPROC=xscale/$(OBJDIR)/accesscoproc$(O)
  SERVER_OBJS=$(ACCESSCOPROC) $(F)wince_debmod$(O) $(F)winbase_debmod$(O) \
              $(F)arm_debmod$(O)
  CCL_LNK_OPT=/implib:$(F)wince_remote_arm.lib
else
  WIN32SERVER=$(SERVERBIN)win32_remote$(B)
  SERVER_TRANS=$(F)tcpip$(O)
  SERVER_OBJS=$(OBJ2) $(OBJ3) $(F)win32_server_impl$(O)
endif

ALLLIBS=$(L)pro$(A)

WIN32_REMOTE_OBJ=$(SERVER_TRANS) $(SERVER_OBJS) $(SERVER_COMMON) \
	         $(REMOTEPDB_OBJS) $(F)win32_debmod$(O)
win32_server: $(WIN32SERVER)

$(WIN32SERVER): $(WIN32_REMOTE_OBJ) $(ALLLIBS)
	$(CCL) $(CREATE_DLL) $(OUTSW)$@ $(WIN32_REMOTE_OBJ) $(ALLLIBS) $(C_LIB) $(ARM_RTTI_LIB) $(REMOTEPDB_SYSLIBS)
ifndef CCL_LNK_OPT
	-@$(RM) $(@R).exp
	-@$(RM) $(@R).lib
endif

#----------------------------------------------------------------------------
kdstub:
	@cd xscale; $(MAKE)
$(ACCESSCOPROC): | kdstub
wincetst: wincetst.exe
wincetst.exe: $(F)wincetst$(O) $(F)winceasm$(O)
	$(CCL) $(OUTSW)$@ $(F)wincetst$(O) $(F)winceasm$(O) $(L)pro$(A) $(C_LIB) $(ARM_RTTI_LIB)
$(F)winceasm$(O): winceasm.s | objdir
	$(_ARMASM) -o $@ $?

tracer: tracer$(B)
TRACER_OBJS=$(F)tracer$(O) $(F)win32_debmod$(O) $(F)debmod$(O) $(F)pc_debmod$(O) $(DUMB) \
	    $(LOWCND_OBJS) $(F)win32_server_stub$(O) $(F)winbase_debmod$(O)
tracer$(B): $(TRACER_OBJS) $(ALLLIBS)
	$(call link_dumb,$@ $(TRACER_OBJS) $(ALLLIBS))

#----------------------------------------------------------------------------
WIN32_STUB_OBJ=$(F)win32_rstub$(O) $(F)tcpip$(O) $(F)win32_server_stub$(O) $(STUB_COMMON) $(F)w32sehch$(O)
WIN32CLIENT=$(BIN_PATH)win32_stub$(PLUGIN)
win32_stub: $(WIN32CLIENT)

$(WIN32CLIENT): $(WIN32_STUB_OBJ) $(IDALIB) $(DEFFILE)
	$(LINKER) $(LINKOPTS) /OUT:$@ $(WIN32_STUB_OBJ) $(IDALIB) user32.lib
	-@$(RM) $(@R).exp
	-@$(RM) $(@R).lib

#----------------------------------------------------------------------------
ifdef ASYNC
WINCECLIENT=$(BIN_PATH)wince_stub$(PLUGIN)
CLIENTTRANSPORT=$(F)async$(O)
else
WINCECLIENT=$(BIN_PATH)wincetcp_stub$(PLUGIN)
CLIENTTRANSPORT=$(F)tcpip$(O)
endif
WINCE_STUB_OBJ=$(F)wince_rstub$(O) $(CLIENTTRANSPORT) $(STUB_COMMON)
wince_stub: $(WINCECLIENT)

$(WINCECLIENT): $(WINCE_STUB_OBJ) $(IDALIB) $(DEFFILE)
	$(LINKER) $(LINKOPTS) /OUT:$@ $(WINCE_STUB_OBJ) $(IDALIB) user32.lib
	-@$(RM) $(@R).exp
	-@$(RM) $(@R).lib

#----------------------------------------------------------------------------
EPOC_STUB_OBJ=$(F)epoc_user$(O) $(F)epoc_debmod$(O) $(F)arm_debmod$(O) $(F)debmod$(O)
EPOCCLIENT=$(BIN_PATH)epoc_user$(PLUGIN)
epoc_user: $(EPOCCLIENT)

$(EPOCCLIENT): $(EPOC_STUB_OBJ) $(IDALIB) $(DEFFILE)
	$(LINKER) $(LINKOPTS) /OUT:$@ $(EPOC_STUB_OBJ) $(IDALIB) user32.lib advapi32.lib
	-@$(RM) $(@R).exp
	-@$(RM) $(@R).lib

CHKTRK_OBJS=$(F)chktrk$(O) $(L)dumb$(O) $(L)pro$(A)
chktrk: chktrk$(B)
chktrk$(B): $(F)chktrk$(O)
	$(CCL) $(OUTSW)$@ $(CHKTRK_OBJS) advapi32.lib

#----------------------------------------------------------------------------
$(F)symmacho$(O): $(I)area.hpp $(I)diskio.hpp $(I)ida.hpp $(I)kernwin.hpp   \
	          $(I)llong.hpp $(I)loader.hpp $(I)netnode.hpp $(I)pro.h    \
	          ../../ldr/ar/aixar.hpp ../../ldr/ar/ar.hpp                \
	          ../../ldr/ar/arcmn.cpp ../../ldr/mach-o/../ar/ar.hpp      \
	          ../../ldr/mach-o/common.cpp ../../ldr/mach-o/common.h     \
	          symelf.hpp symmacho.cpp symmacho.hpp | objdir
ifdef __VC__
	$(CC) $(CFLAGS) -c -I../../ldr/mach-o/h -I../../ldr/mach-o/vc_h -D__arm__ $(OBJSW)$@ symmacho.cpp
else
	$(CC) $(CFLAGS) -c -I../../ldr/mach-o/h -D__arm__ $(OBJSW)$@ symmacho.cpp
endif

LINUX_STUB_OBJ=$(F)linux_rstub$(O) $(F)tcpip$(O) $(STUB_COMMON)
LINUXCLIENT=$(BIN_PATH)linux_stub$(PLUGIN)
linux_stub: $(LINUXCLIENT)

$(LINUXCLIENT): $(LINUX_STUB_OBJ) $(IDALIB) $(DEFFILE)
	$(LINKER) $(LINKOPTS) /OUT:$@ $(LINUX_STUB_OBJ) $(IDALIB) user32.lib
	-@$(RM) $(@R).exp
	-@$(RM) $(@R).lib

#----------------------------------------------------------------------------
ARM_LINUX_STUB_OBJ=$(F)armlinux_rstub$(O) $(F)tcpip$(O) $(STUB_COMMON)
ARM_LINUXCLIENT=$(BIN_PATH)armlinux_stub$(PLUGIN)
armlinux_stub: $(ARM_LINUXCLIENT)

$(ARM_LINUXCLIENT): $(ARM_LINUX_STUB_OBJ) $(IDALIB) $(DEFFILE)
	$(LINKER) $(LINKOPTS) /OUT:$@ $(ARM_LINUX_STUB_OBJ) $(IDALIB) user32.lib
	-@$(RM) $(@R).exp
	-@$(RM) $(@R).lib

#----------------------------------------------------------------------------
MAC_STUB_OBJ=$(F)mac_rstub$(O) $(F)tcpip$(O) $(F)symmacho$(O) $(STUB_COMMON)
MACCLIENT=$(BIN_PATH)mac_stub$(PLUGIN)
mac_stub: $(MACCLIENT)

$(MACCLIENT): $(MAC_STUB_OBJ) $(IDALIB) $(DEFFILE)
	$(LINKER) $(LINKOPTS) /OUT:$@ $(MAC_STUB_OBJ) $(IDALIB) user32.lib
	-@$(RM) $(@R).exp
	-@$(RM) $(@R).lib

$(F)mac_rstub$(O): $(I)area.hpp $(I)bytes.hpp $(I)dbg.hpp $(I)diskio.hpp     \
	          $(I)err.h $(I)expr.hpp $(I)fpro.h $(I)funcs.hpp           \
	          $(I)ida.hpp $(I)idd.hpp $(I)idp.hpp $(I)kernwin.hpp       \
	          $(I)lines.hpp $(I)llong.hpp $(I)loader.hpp $(I)nalt.hpp   \
	          $(I)name.hpp $(I)netnode.hpp $(I)pro.h $(I)segment.hpp    \
	          $(I)srarea.hpp $(I)ua.hpp $(I)xref.hpp async.h            \
	          common_local_impl.cpp common_stub_impl.cpp consts.h       \
	          deb_pc.hpp debmod.h mac_local_impl.cpp mac_rstub.cpp      \
	          pc_local_impl.cpp rapi/rapi.h rpc_client.h rpc_debmod.h   \
	          rpc_engine.h rpc_hlp.h tcpip.h | objdir
	$(CC) $(CFLAGS) $(OBJSW)$@ -c -I../../ldr/mach-o/h -D__i386__ mac_rstub.cpp


#----------------------------------------------------------------------------
IPHONE_STUB_OBJ=$(F)iphone_rstub$(O) $(F)tcpip$(O) $(STUB_COMMON)
IPHONECLIENT=$(BIN_PATH)iphone_stub$(PLUGIN)
iphone_stub: $(IPHONECLIENT)

$(IPHONECLIENT): $(IPHONE_STUB_OBJ) $(IDALIB) $(DEFFILE)
	$(LINKER) $(LINKOPTS) /OUT:$@ $(IPHONE_STUB_OBJ) $(IDALIB) user32.lib
	-@$(RM) $(@R).exp
	-@$(RM) $(@R).lib

$(F)iphone_rstub$(O): $(I)area.hpp $(I)bytes.hpp $(I)dbg.hpp $(I)diskio.hpp     \
	          $(I)err.h $(I)expr.hpp $(I)fpro.h $(I)funcs.hpp           \
	          $(I)ida.hpp $(I)idd.hpp $(I)idp.hpp $(I)kernwin.hpp       \
	          $(I)lines.hpp $(I)llong.hpp $(I)loader.hpp $(I)nalt.hpp   \
	          $(I)name.hpp $(I)netnode.hpp $(I)pro.h $(I)segment.hpp    \
	          $(I)srarea.hpp $(I)ua.hpp $(I)xref.hpp                    \
	          arm_local_impl.cpp arm_regs.cpp async.h                   \
	          common_local_impl.cpp common_stub_impl.cpp consts.h       \
	          deb_arm.hpp debmod.h iphone_rstub.cpp mac_local_impl.cpp  \
	          rapi/rapi.h rpc_client.h rpc_debmod.h rpc_engine.h        \
	          rpc_hlp.h tcpip.h | objdir
	$(CC) $(CFLAGS) -c -I../../ldr/mach-o/h -D__i386__ /Fo$@ iphone_rstub.cpp

#----------------------------------------------------------------------------
cfg: $(C)exceptions.cfg

$(C)exceptions.cfg:  exceptions.cfg
	$(CP) $? $@

ifdef ALLDIRS
$(ALLDIRS):
	@cd $@; $(MAKE)
endif

# MAKEDEP dependency list ------------------
$(F)arm_debmod$(O): $(I)area.hpp $(I)auto.hpp $(I)bytes.hpp $(I)dbg.hpp       \
	          $(I)expr.hpp $(I)fpro.h $(I)funcs.hpp $(I)ida.hpp         \
	          $(I)idd.hpp $(I)idp.hpp $(I)kernwin.hpp $(I)lines.hpp     \
	          $(I)llong.hpp $(I)loader.hpp $(I)nalt.hpp $(I)name.hpp    \
	          $(I)netnode.hpp $(I)offset.hpp $(I)pro.h $(I)queue.hpp    \
	          $(I)regex.h $(I)segment.hpp $(I)srarea.hpp                \
	          $(I)typeinf.hpp $(I)ua.hpp $(I)xref.hpp                   \
	          ../../ldr/aof/aof.h ../../module/arm/../idaidp.hpp        \
	          arm_debmod.cpp arm_debmod.h consts.h deb_arm.hpp          \
	          debmod.h
$(F)armlinux_rstub$(O): $(I)area.hpp $(I)bytes.hpp $(I)dbg.hpp $(I)diskio.hpp     \
	          $(I)err.h $(I)expr.hpp $(I)fpro.h $(I)funcs.hpp           \
	          $(I)ida.hpp $(I)idd.hpp $(I)idp.hpp $(I)kernwin.hpp       \
	          $(I)lines.hpp $(I)llong.hpp $(I)loader.hpp $(I)nalt.hpp   \
	          $(I)name.hpp $(I)netnode.hpp $(I)pro.h $(I)segment.hpp    \
	          $(I)srarea.hpp $(I)ua.hpp $(I)xref.hpp                    \
	          arm_local_impl.cpp arm_regs.cpp armlinux_rstub.cpp        \
	          async.h common_local_impl.cpp common_stub_impl.cpp        \
	          consts.h deb_arm.hpp debmod.h linux_local_impl.cpp        \
	          rapi/rapi.h rpc_client.h rpc_debmod.h rpc_engine.h        \
	          rpc_hlp.h tcpip.h
$(F)async$(O)   : $(I)auto.hpp $(I)diskio.hpp $(I)err.h $(I)expr.hpp        \
	          $(I)fpro.h $(I)ida.hpp $(I)kernwin.hpp $(I)llong.hpp      \
	          $(I)pro.h async.cpp async.h consts.h rapi/rapi.h
$(F)chktrk$(O)  : $(I)diskio.hpp $(I)err.h $(I)fpro.h $(I)kernwin.hpp       \
	          $(I)llong.hpp $(I)pro.h chktrk.cpp metrotrk.cpp           \
	          metrotrk.h
$(F)debmod$(O)  : $(I)area.hpp $(I)bytes.hpp $(I)diskio.hpp $(I)err.h       \
	          $(I)expr.hpp $(I)fpro.h $(I)funcs.hpp $(I)ida.hpp         \
	          $(I)idd.hpp $(I)idp.hpp $(I)kernwin.hpp $(I)lines.hpp     \
	          $(I)llong.hpp $(I)nalt.hpp $(I)name.hpp $(I)netnode.hpp   \
	          $(I)pro.h $(I)segment.hpp $(I)typeinf.hpp $(I)ua.hpp      \
	          $(I)xref.hpp consts.h debmod.cpp debmod.h
$(F)epoc_debmod$(O): $(I)area.hpp $(I)bytes.hpp $(I)diskio.hpp $(I)err.h       \
	          $(I)expr.hpp $(I)fpro.h $(I)funcs.hpp $(I)ida.hpp         \
	          $(I)idd.hpp $(I)idp.hpp $(I)kernwin.hpp $(I)lines.hpp     \
	          $(I)llong.hpp $(I)nalt.hpp $(I)netnode.hpp $(I)pro.h      \
	          $(I)segment.hpp $(I)srarea.hpp $(I)ua.hpp $(I)xref.hpp    \
	          arm_debmod.h consts.h deb_arm.hpp debmod.h                \
	          epoc_debmod.cpp epoc_debmod.h metrotrk.cpp metrotrk.h
$(F)epoc_user$(O): $(I)area.hpp $(I)bytes.hpp $(I)dbg.hpp $(I)err.h          \
	          $(I)expr.hpp $(I)fpro.h $(I)funcs.hpp $(I)ida.hpp         \
	          $(I)idd.hpp $(I)idp.hpp $(I)kernwin.hpp $(I)lines.hpp     \
	          $(I)llong.hpp $(I)loader.hpp $(I)nalt.hpp $(I)name.hpp    \
	          $(I)netnode.hpp $(I)pro.h $(I)segment.hpp $(I)srarea.hpp  \
	          $(I)ua.hpp $(I)xref.hpp arm_debmod.h arm_local_impl.cpp   \
	          arm_regs.cpp common_local_impl.cpp common_stub_impl.cpp   \
	          consts.h deb_arm.hpp debmod.h epoc_debmod.h               \
	          epoc_local_impl.cpp epoc_user.cpp metrotrk.h
$(F)linux_check$(O): linux_check.c
$(F)linux_debmod$(O): $(I)area.hpp $(I)bytes.hpp $(I)diskio.hpp $(I)err.h       \
	          $(I)expr.hpp $(I)fpro.h $(I)funcs.hpp $(I)ida.hpp         \
	          $(I)idd.hpp $(I)idp.hpp $(I)kernwin.hpp $(I)lines.hpp     \
	          $(I)llong.hpp $(I)loader.hpp $(I)nalt.hpp $(I)name.hpp    \
	          $(I)netnode.hpp $(I)pro.h $(I)prodir.h $(I)segment.hpp    \
	          $(I)ua.hpp $(I)xref.hpp ../../ldr/elf/elf.h               \
	          ../../ldr/elf/elfbase.h \
	          arm_debmod.h async.h consts.h deb_arm.hpp deb_pc.hpp      \
	          debmod.h linux_debmod.cpp linux_debmod.h                  \
	          linux_threads.cpp pc_debmod.h rapi/rapi.h rpc_engine.h    \
	          rpc_hlp.h rpc_server.h symelf.hpp tcpip.h
$(F)linux_rstub$(O): $(I)area.hpp $(I)bytes.hpp $(I)dbg.hpp $(I)diskio.hpp     \
	          $(I)err.h $(I)expr.hpp $(I)fpro.h $(I)funcs.hpp           \
	          $(I)ida.hpp $(I)idd.hpp $(I)idp.hpp $(I)kernwin.hpp       \
	          $(I)lines.hpp $(I)llong.hpp $(I)loader.hpp $(I)nalt.hpp   \
	          $(I)name.hpp $(I)netnode.hpp $(I)pro.h $(I)segment.hpp    \
	          $(I)srarea.hpp $(I)ua.hpp $(I)xref.hpp async.h            \
	          common_local_impl.cpp common_stub_impl.cpp consts.h       \
	          deb_pc.hpp debmod.h linux_local_impl.cpp linux_rstub.cpp  \
	          pc_local_impl.cpp rapi/rapi.h rpc_client.h rpc_debmod.h   \
	          rpc_engine.h rpc_hlp.h tcpip.h
$(F)linux_user$(O): $(I)area.hpp $(I)bytes.hpp $(I)dbg.hpp $(I)err.h          \
	          $(I)expr.hpp $(I)fpro.h $(I)funcs.hpp $(I)ida.hpp         \
	          $(I)idd.hpp $(I)idp.hpp $(I)kernwin.hpp $(I)lines.hpp     \
	          $(I)llong.hpp $(I)loader.hpp $(I)nalt.hpp $(I)name.hpp    \
	          $(I)netnode.hpp $(I)pro.h $(I)segment.hpp $(I)srarea.hpp  \
	          $(I)ua.hpp $(I)xref.hpp arm_debmod.h                      \
	          common_local_impl.cpp common_stub_impl.cpp consts.h       \
	          deb_arm.hpp deb_pc.hpp debmod.h linux_debmod.h            \
	          linux_local_impl.cpp linux_user.cpp pc_debmod.h           \
	          pc_local_impl.cpp
$(F)linux_wait$(O): $(I)area.hpp $(I)expr.hpp $(I)ida.hpp $(I)idd.hpp         \
	          $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp $(I)pro.h     \
	          $(I)ua.hpp $(I)xref.hpp arm_debmod.h consts.h             \
	          deb_arm.hpp deb_pc.hpp debmod.h linux_debmod.h            \
	          linux_wait.cpp pc_debmod.h
$(F)mac_debmod$(O): $(I)area.hpp $(I)bytes.hpp $(I)diskio.hpp $(I)err.h       \
	          $(I)expr.hpp $(I)fpro.h $(I)funcs.hpp $(I)ida.hpp         \
	          $(I)idd.hpp $(I)idp.hpp $(I)kernwin.hpp $(I)lines.hpp     \
	          $(I)llong.hpp $(I)loader.hpp $(I)nalt.hpp $(I)name.hpp    \
	          $(I)netnode.hpp $(I)pro.h $(I)segment.hpp $(I)ua.hpp      \
	          $(I)xref.hpp ../../ldr/mach-o/common.h consts.h           \
	          deb_arm.hpp deb_pc.hpp debmod.h mac_debmod.cpp            \
	          mac_debmod.h pc_debmod.h symelf.hpp symmacho.hpp
$(F)mac_user$(O): $(I)area.hpp $(I)bytes.hpp $(I)dbg.hpp $(I)diskio.hpp     \
	          $(I)err.h $(I)expr.hpp $(I)fpro.h $(I)funcs.hpp           \
	          $(I)ida.hpp $(I)idd.hpp $(I)idp.hpp $(I)kernwin.hpp       \
	          $(I)lines.hpp $(I)llong.hpp $(I)loader.hpp $(I)nalt.hpp   \
	          $(I)name.hpp $(I)netnode.hpp $(I)pro.h $(I)segment.hpp    \
	          $(I)srarea.hpp $(I)ua.hpp $(I)xref.hpp                    \
	          common_local_impl.cpp common_stub_impl.cpp consts.h       \
	          deb_arm.hpp deb_pc.hpp debmod.h mac_debmod.h              \
	          mac_local_impl.cpp mac_user.cpp pc_debmod.h               \
	          pc_local_impl.cpp symelf.hpp symmacho.hpp
$(F)pc_debmod$(O): $(I)area.hpp $(I)expr.hpp $(I)ida.hpp $(I)idd.hpp         \
	          $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp $(I)pro.h     \
	          $(I)ua.hpp $(I)xref.hpp consts.h deb_pc.hpp debmod.h      \
	          pc_debmod.cpp pc_debmod.h
$(F)rpc_client$(O): $(I)area.hpp $(I)diskio.hpp $(I)err.h $(I)expr.hpp        \
	          $(I)fpro.h $(I)ida.hpp $(I)idd.hpp $(I)kernwin.hpp        \
	          $(I)lines.hpp $(I)llong.hpp $(I)name.hpp $(I)pro.h        \
	          $(I)ua.hpp $(I)xref.hpp async.h consts.h debmod.h         \
	          rapi/rapi.h rpc_client.cpp rpc_client.h rpc_engine.h      \
	          rpc_hlp.h tcpip.h
$(F)rpc_debmod$(O): $(I)area.hpp $(I)diskio.hpp $(I)err.h $(I)expr.hpp        \
	          $(I)fpro.h $(I)ida.hpp $(I)idd.hpp $(I)kernwin.hpp        \
	          $(I)lines.hpp $(I)llong.hpp $(I)pro.h $(I)segment.hpp     \
	          $(I)ua.hpp $(I)xref.hpp async.h consts.h debmod.h         \
	          rapi/rapi.h rpc_client.h rpc_debmod.cpp rpc_debmod.h      \
	          rpc_engine.h rpc_hlp.h tcpip.h
$(F)rpc_engine$(O): $(I)area.hpp $(I)diskio.hpp $(I)err.h $(I)expr.hpp        \
	          $(I)fpro.h $(I)ida.hpp $(I)idd.hpp $(I)kernwin.hpp        \
	          $(I)lines.hpp $(I)llong.hpp $(I)pro.h $(I)ua.hpp          \
	          $(I)xref.hpp async.h consts.h debmod.h rapi/rapi.h        \
	          rpc_engine.cpp rpc_engine.h rpc_hlp.h tcpip.h
$(F)rpc_hlp$(O) : $(I)area.hpp $(I)bytes.hpp $(I)expr.hpp $(I)fpro.h        \
	          $(I)funcs.hpp $(I)ida.hpp $(I)idd.hpp $(I)idp.hpp         \
	          $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp $(I)nalt.hpp  \
	          $(I)name.hpp $(I)netnode.hpp $(I)pro.h $(I)segment.hpp    \
	          $(I)typeinf.hpp $(I)ua.hpp $(I)xref.hpp consts.h          \
	          rpc_hlp.cpp rpc_hlp.h
$(F)rpc_server$(O): $(I)area.hpp $(I)bytes.hpp $(I)diskio.hpp $(I)err.h       \
	          $(I)expr.hpp $(I)fpro.h $(I)funcs.hpp $(I)ida.hpp         \
	          $(I)idd.hpp $(I)idp.hpp $(I)kernwin.hpp $(I)lines.hpp     \
	          $(I)llong.hpp $(I)nalt.hpp $(I)name.hpp $(I)netnode.hpp   \
	          $(I)pro.h $(I)segment.hpp $(I)typeinf.hpp $(I)ua.hpp      \
	          $(I)xref.hpp async.h consts.h debmod.h rapi/rapi.h        \
	          rpc_engine.h rpc_hlp.h rpc_server.cpp rpc_server.h        \
	          server.h tcpip.h
$(F)server$(O)  : $(I)area.hpp $(I)diskio.hpp $(I)err.h $(I)expr.hpp        \
	          $(I)fpro.h $(I)ida.hpp $(I)idd.hpp $(I)kernwin.hpp        \
	          $(I)lines.hpp $(I)llong.hpp $(I)pro.h $(I)ua.hpp          \
	          $(I)xref.hpp async.h consts.h debmod.h rapi/rapi.h        \
	          rpc_engine.h rpc_hlp.h rpc_server.h server.cpp server.h   \
	          tcpip.h
$(F)symelf$(O)  : $(I)area.hpp $(I)diskio.hpp $(I)expr.hpp $(I)fpro.h       \
	          $(I)ida.hpp $(I)idd.hpp $(I)kernwin.hpp $(I)lines.hpp     \
	          $(I)llong.hpp $(I)pro.h $(I)ua.hpp $(I)xref.hpp           \
	          ../../ldr/elf/common.cpp ../../ldr/elf/elf.h              \
	          ../../ldr/elf/elfbase.h ../../ldr/elf/elfr_arm.h          \
	          ../../ldr/elf/elfr_ia6.h ../../ldr/elf/elfr_mip.h         \
	          ../../ldr/elf/elfr_ppc.h ../../ldr/elf/reader.cpp         \
	          consts.h debmod.h symelf.cpp symelf.hpp
$(F)tcpip$(O)   : $(I)err.h $(I)expr.hpp $(I)kernwin.hpp $(I)llong.hpp      \
	          $(I)pro.h consts.h tcpip.cpp tcpip.h
$(F)util$(O)    : $(I)area.hpp $(I)expr.hpp $(I)fpro.h $(I)ida.hpp          \
	          $(I)idd.hpp $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp   \
	          $(I)pro.h $(I)ua.hpp $(I)xref.hpp consts.h debmod.h       \
	          util.cpp
$(F)w32sehch$(O): $(I)area.hpp $(I)bytes.hpp $(I)dbg.hpp $(I)fpro.h         \
	          $(I)funcs.hpp $(I)ida.hpp $(I)idd.hpp $(I)idp.hpp         \
	          $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp               \
	          $(I)loader.hpp $(I)nalt.hpp $(I)name.hpp $(I)netnode.hpp  \
	          $(I)pro.h $(I)segment.hpp $(I)ua.hpp $(I)xref.hpp         \
	          w32sehch.cpp w32sehch.h
$(F)win32_debmod$(O): $(I)area.hpp $(I)auto.hpp $(I)bytes.hpp $(I)dbg.hpp       \
	          $(I)diskio.hpp $(I)err.h $(I)exehdr.h $(I)expr.hpp        \
	          $(I)fpro.h $(I)funcs.hpp $(I)ida.hpp $(I)idd.hpp          \
	          $(I)idp.hpp $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp   \
	          $(I)nalt.hpp $(I)netnode.hpp $(I)pro.h $(I)prodir.h       \
	          $(I)segment.hpp $(I)ua.hpp $(I)xref.hpp                   \
	          ../../ldr/pe/common.cpp ../../ldr/pe/common.h             \
	          ../../ldr/pe/pe.h arm_debmod.h async.h consts.h           \
	          deb_arm.hpp deb_pc.hpp debmod.h pc_debmod.h rapi/rapi.h   \
	          rpc_engine.h rpc_hlp.h rpc_server.h tcpip.h               \
	          win32_debmod.cpp win32_debmod.h win32_debmod_impl.cpp     \
	          win32_rpc.h win32_undoc.h win32_util_impl.cpp             \
	          winbase_debmod.h wince.hpp wince_debmod.h                 \
	          wince_debmod_impl.cpp xscale/Breakpoint.h
$(F)win32_rstub$(O): $(I)area.hpp $(I)bytes.hpp $(I)dbg.hpp $(I)diskio.hpp     \
	          $(I)err.h $(I)expr.hpp $(I)fpro.h $(I)funcs.hpp           \
	          $(I)ida.hpp $(I)idd.hpp $(I)idp.hpp $(I)kernwin.hpp       \
	          $(I)lines.hpp $(I)llong.hpp $(I)loader.hpp $(I)nalt.hpp   \
	          $(I)name.hpp $(I)netnode.hpp $(I)pro.h $(I)segment.hpp    \
	          $(I)srarea.hpp $(I)typeinf.hpp $(I)ua.hpp $(I)xref.hpp    \
	          ../../ldr/pe/pe.h ../../plugins/pdb/common.h              \
	          ../../plugins/pdb/cvconst.h ../../plugins/pdb/dia2.h      \
	          ../../plugins/pdb/pdbaccess.hpp                           \
	          ../../plugins/pdb/pdblocal.hpp async.h                    \
	          common_local_impl.cpp common_stub_impl.cpp consts.h       \
	          deb_pc.hpp debmod.h pc_local_impl.cpp rapi/rapi.h         \
	          rpc_client.h rpc_debmod.h rpc_engine.h rpc_hlp.h tcpip.h  \
	          w32sehch.h win32_local_impl.cpp win32_rpc.h               \
	          win32_rstub.cpp
$(F)win32_server_impl$(O): $(I)area.hpp $(I)expr.hpp $(I)ida.hpp $(I)idd.hpp         \
	          $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp $(I)pro.h     \
	          $(I)ua.hpp $(I)xref.hpp ../../ldr/pe/pe.h arm_debmod.h    \
	          consts.h deb_arm.hpp deb_pc.hpp debmod.h pc_debmod.h      \
	          rpc_hlp.h win32_debmod.h win32_rpc.h                      \
	          win32_server_impl.cpp winbase_debmod.h wince.hpp          \
	          wince_debmod.h
$(F)win32_server_stub$(O): $(I)area.hpp $(I)expr.hpp $(I)ida.hpp $(I)idd.hpp         \
	          $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp $(I)pro.h     \
	          $(I)ua.hpp $(I)xref.hpp ../../ldr/pe/pe.h arm_debmod.h    \
	          consts.h deb_arm.hpp deb_pc.hpp debmod.h pc_debmod.h      \
	          win32_debmod.h win32_server_stub.cpp winbase_debmod.h     \
	          wince.hpp wince_debmod.h
$(F)win32_user$(O): $(I)area.hpp $(I)bytes.hpp $(I)dbg.hpp $(I)err.h          \
	          $(I)expr.hpp $(I)fpro.h $(I)funcs.hpp $(I)ida.hpp         \
	          $(I)idd.hpp $(I)idp.hpp $(I)kernwin.hpp $(I)lines.hpp     \
	          $(I)llong.hpp $(I)loader.hpp $(I)nalt.hpp $(I)name.hpp    \
	          $(I)netnode.hpp $(I)pro.h $(I)segment.hpp $(I)srarea.hpp  \
	          $(I)typeinf.hpp $(I)ua.hpp $(I)xref.hpp                   \
	           ../../ldr/pe/pe.h                    \
	          ../../plugins/pdb/common.h ../../plugins/pdb/cvconst.h    \
	          ../../plugins/pdb/dia2.h ../../plugins/pdb/pdbaccess.hpp  \
	          ../../plugins/pdb/pdblocal.hpp  arm_debmod.h              \
	          common_local_impl.cpp common_stub_impl.cpp consts.h       \
	          deb_arm.hpp deb_pc.hpp debmod.h pc_debmod.h               \
	          pc_local_impl.cpp rpc_hlp.h w32sehch.h win32_debmod.h     \
	          win32_local_impl.cpp win32_rpc.h win32_user.cpp           \
	          winbase_debmod.h wince.hpp wince_debmod.h
$(F)winbase_debmod$(O): $(I)area.hpp $(I)expr.hpp $(I)ida.hpp $(I)idd.hpp         \
	          $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp $(I)pro.h     \
	          $(I)ua.hpp $(I)xref.hpp ../../ldr/pe/pe.h arm_debmod.h    \
	          consts.h deb_arm.hpp deb_pc.hpp debmod.h pc_debmod.h      \
	          winbase_debmod.cpp winbase_debmod.h wince.hpp             \
	          wince_debmod.h
$(F)wince_debmod$(O): $(I)area.hpp $(I)diskio.hpp $(I)err.h $(I)expr.hpp        \
	          $(I)fpro.h $(I)ida.hpp $(I)idd.hpp $(I)kernwin.hpp        \
	          $(I)lines.hpp $(I)llong.hpp $(I)pro.h $(I)ua.hpp          \
	          $(I)xref.hpp ../../ldr/pe/pe.h arm_debmod.h async.h       \
	          consts.h deb_arm.hpp debmod.h rapi/rapi.h rpc_engine.h    \
	          rpc_hlp.h rpc_server.h tcpip.h wince.hpp                  \
	          wince_debmod.cpp wince_debmod.h xscale/Breakpoint.h
$(F)wince_rstub$(O): $(I)area.hpp $(I)bytes.hpp $(I)dbg.hpp $(I)diskio.hpp     \
	          $(I)err.h $(I)expr.hpp $(I)fpro.h $(I)funcs.hpp           \
	          $(I)ida.hpp $(I)idd.hpp $(I)idp.hpp $(I)kernwin.hpp       \
	          $(I)lines.hpp $(I)llong.hpp $(I)loader.hpp $(I)nalt.hpp   \
	          $(I)name.hpp $(I)netnode.hpp $(I)pro.h $(I)segment.hpp    \
	          $(I)srarea.hpp $(I)typeinf.hpp $(I)ua.hpp $(I)xref.hpp    \
	          ../../ldr/pe/pe.h                                         \
	          ../../plugins/pdb/common.h ../../plugins/pdb/cvconst.h    \
	          ../../plugins/pdb/dia2.h ../../plugins/pdb/pdbaccess.hpp  \
	          ../../plugins/pdb/pdblocal.hpp arm_local_impl.cpp        \
	          arm_regs.cpp async.h common_local_impl.cpp                \
	          common_stub_impl.cpp consts.h deb_arm.hpp debmod.h        \
	          rapi/rapi.h rpc_client.h rpc_debmod.h rpc_engine.h        \
	          rpc_hlp.h tcpip.h win32_local_impl.cpp win32_rpc.h        \
	          wince.hpp wince_rstub.cpp
