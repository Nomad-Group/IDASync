#
#       Common part of make files for IDA under MS Windows.
#

# find directory of allmake.mak:
IDA:=$(dir $(lastword $(MAKEFILE_LIST)))

# define the version number we are building
IDAVER_MAJOR:=7
IDAVER_MINOR:=0
# 700
IDAVERDECIMAL:=$(IDAVER_MAJOR)$(IDAVER_MINOR)0
# 7.0
IDAVERDOTTED:=$(IDAVER_MAJOR).$(IDAVER_MINOR)

# unix: redirect to allmake.unx
ifneq ($(or $(__MAC__),$(__LINUX__)),)
# 'unixpath' helper on unix systems is the identity op.
unixpath=$1
include $(IDA)allmake.unx
else
# the rest of the file is for windows

NASM=$(RS)nasmw.exe

# define: convert unix path to dos path by replacing slashes by backslashes
dospath=$(subst /,\\,$(1))
# define: convert dos path to unix path by replacing backslashes by slashes
unixpath=$(subst \,/,$(1))
# define: return absolute path given a relative path
qabspath=$(abspath $(1))/
# define: logical negation
not = $(if $(1),,1)
# define: comma to use in function calls as a literal
comma=,

# if none of these are defined, default to __NT__
ifeq ($(or $(__ANDROID__),$(__ANDROID_X86__),$(__ARMLINUX__),$(__LINUX__),$(__MAC__)),)
  __NT__=1
endif

include $(IDA)defaults.mk

# ifndef NDEBUG
#  DEBUG := 1
# endif

ifndef VC_USE_CPUS
  VC_USE_CPUS := 8
endif

# force visual studio for WinCE and x64
ifneq ($(or $(__CEARM__),$(__X64__)),)
  ifeq ($(or $(__ANDROID__),$(__ANDROID_X86__)),)
    __VC__=1
  endif
endif

# since we can not debug android/cearm servers, there is no point in building
# them with debug info. always build the optimized version.
ifneq ($(or $(__ANDROID__),$(__CEARM__),$(__ARMLINUX__)),)
  NDEBUG=1
  __ARM__=1       # both of them run on arm processor
endif
ifdef __ANDROID_X86__
  NDEBUG=1
endif

ifdef __ARM__
  PROCFLAG=-D__ARM__
  TARGET_PROCESSOR_MODULE=arm
else
  TARGET_PROCESSOR_MODULE=pc
endif

ULINK_64F=+$(ULNK_CFG_DIR)ulink.vx
ULINK_VCF=+$(ULNK_CFG_DIR)ulink.v9

ifdef __X64__
  ULNK_CFG=$(ULINK_64F)
else
  ifdef __VC__
    ULNK_CFG=$(ULINK_VCF)
  else
    ULNK_CFG=$(ULINK_BCF)
  endif
endif

ULNK_COMPAT=-O- -o- -Gh -Gh-
ifndef __X64__
  ULNK_COMPAT=$(ULNK_COMPAT) -P-
endif

ULINK=$(ULNK_BASE) $(ULNK_CFG) $(ULINK_COMPAT_OPT)

_ULCCOPT=$(_LDFLAGS) $(LNDEBUG) $(_LNK_EXE_MAP) $(_LSHOW)

ifdef __X64__
  ifneq ($(PROCESSOR_ARCHITEW6432),AMD64)
    NO_EXECUTE_TESTS = 1
  endif
endif

ifdef NDEBUG
  OPTSUF=_opt
endif

#-----------
AROPT?=ru
ifndef NOSHOW
  AROPT:=$(AROPT)v
else
  .SILENT:
  _LDSW=_q

  ifdef __VC__
    _CSHOW=/nologo
  else
    _CSHOW=-q
  endif

  _LSHOW=/nologo

  _LBSHOW=_f/nologo
endif   # NOSHOW

ifdef SUPPRESS_WARNINGS
  ifdef __ANDROID__
    NOWARNS=-w
  else
    ifdef __VC__
      NOWARNS=-w -wd4702 -wd4738
    else # BCC
      NOWARNS=-w-
    endif
  endif
endif

LDEXE=$(RS)ld$(BS) $(_LDSW)

######################### set TV variables
ifndef TVSRC
  TVSRC=$(IDA)ui/txt/tv/
endif

ifdef _CFLAGS_TV       # set tv path(s) for ui/txt after include defaults.mk
  _CFLAGS=-I$(TVSRC)include $(_CFLAGS_TV)
endif

############################################################################
.PHONY: all All goal Goal total Total objdir test runtest $(ADDITIONAL_GOALS)

######################### set linker debug switch
ifdef __VC__
  ifdef NDEBUG
    LNDEBUG=/DEBUG /PDB:$(PDBDIR)/ /INCREMENTAL:NO /OPT:ICF /OPT:REF /PDBALTPATH:%_PDB%
  else
    LNDEBUG=/DEBUG /PDB:$(PDBDIR)/
  endif
endif

MSVCDIR?=$(VSPATH)VC/
MSVCARMDIR?=$(VSPATH8)VC/ce/

#########################
# visual studio: set c runtime to use
# default is dynamic runtime
# if USE_STATIC_RUNTIME is set, use static runtime
# in that case, use VS8 for better compatibility
ifneq ($(and $(__VC__),$(NDEBUG),$(call not,$(RUNTIME_LIBSW))),)
  ifdef USE_STATIC_RUNTIME
    RUNTIME_LIBSW=/MT
    STATSUF=_s
    __VC8__=1
    MSVCDIR=$(VSPATH8)VC/
    R32=$(RS)/x86_win_vc/
    B32=$(BS)
  else
    RUNTIME_LIBSW=/MD
    LNKERREP=/ERRORREPORT:QUEUE
  endif
else
  ifdef USE_STATIC_RUNTIME
    RUNTIME_LIBSW=/MTd
    STATSUF=_s
    __VC8__=1
    MSVCDIR=$(VSPATH8)VC/
    R32=$(RS)/x86_win_vc/
    B32=$(BS)
  else
    RUNTIME_LIBSW=/MDd
    LNKERREP=/ERRORREPORT:QUEUE
  endif
endif

ifdef __X64__
  SWITCHX64=-D__X64__
endif

ifdef __EA64__
  SUFF64=64
  ADRSIZE=64
  SWITCH64=-D__EA64__
else
  ADRSIZE=32
endif

# include,help and other directories are common for all platforms and compilers:
I =$(IDA)include/
# help file is stored in the bin directory
HO=$(R)
# _ida.hlp placed in main tool directory
HI=$(RS)
C =$(R)cfg/
RI=$(R)idc/
# help source
HS=.hls
# help headers
HH=.hhp
SYSNAME=win

CXX=$(CC)

#############################################################################
# To compile debugger server for Android, Android NDK should be installed
# Environment variable ANDROID_NDK must point to it (default c:/android-ndk-r4b/)
# To cross-compile for ARM Linux/uCLinux, define SOURCERY root directory
# (default C:/CodeSourcery/Sourcery G++ Lite)
ifneq ($(or $(__ANDROID__),$(__ANDROID_X86__),$(__ARMLINUX__)),)
  ifneq ($(or $(__NT__),$(__VC__)),)
    $(error "Please undefine __NT__, __VC__ to compile for Android/ARM Linux")
  endif
  ifneq ($(and $(__ANDROID__),$(__ANDROID_X86__)),)
    $(error "Define __ANDROID__ or __ANDROID_X86__, but not both")
  endif
  ifdef NDEBUG
    CCOPT=-O3 -ffunction-sections -fdata-sections
    OUTDLLOPTS=-Wl,-S,-x$(DEAD_STRIP)
  else
    CCOPT=-g
    OUTDLLOPTS=-Wl,--strip-debug,--discard-all
  endif
  BUILD_ONLY_SERVER=1
  COMPILER_NAME=gcc
  TARGET_PROCESSOR_NAME=arm
  ifneq ($(or $(__ANDROID__),$(__ANDROID_X86__)),)
    ifdef __EA64__
      ifndef __X64__
        $(error "Please undefine __EA64__ (or define __X64__) to compile for Android")
      endif
    endif
    SYSNAME=android
    ANDROID_NDK_BASE=$(IDA)../third_party/android-ndk
    LIBTHREAD_DB_SRC=$(ANDROID_NDK_BASE)/gdb-7.6/libthread_db.c
    CCOPT=-O3
    SYS=$(PROCFLAG) -shared
    # Configuration: armeabi
    ifdef __ANDROID__
      ifdef __X64__
	ANDROID_NDK=$(ANDROID_NDK_BASE)/arm64-v8a-21
      else
	ANDROID_NDK=$(ANDROID_NDK_BASE)/armeabi-8
      endif
    else  # __ANDROID_X86__
      ifdef __X64__
	TARGET_PROCESSOR_NAME=x64
	ANDROID_NDK=$(ANDROID_NDK_BASE)/x64-21
      else
	TARGET_PROCESSOR_NAME=x86
	ANDROID_NDK=$(ANDROID_NDK_BASE)/x86-19
      endif
    endif
    CCDIR=$(ANDROID_NDK)/bin
    SYSROOT=$(ANDROID_NDK)/sysroot
    CRTBEGIN=$(SYSROOT)/usr/lib/crtbegin_dynamic.o
    CRTEND=$(SYSROOT)/usr/lib/crtend_android.o
    # ABI
    ifdef __ANDROID__
      ifdef __X64__
	CCPART=aarch64-linux-android
	SYS+=-fstack-protector-strong
      else
	CCPART=arm-linux-androideabi
	SYS+=-fstack-protector -march=armv5te -mtune=xscale -msoft-float -mthumb
      endif
      __EXTRADEF:=-D__ANDROID__ -D__ARM__
    else  # __ANDROID_X86__
      ifdef __X64__
	CCPART=x86_64-linux-android
        SYS+=-fPIE -fstack-protector-strong
	CRTBEGIN=$(SYSROOT)/usr/lib64/crtbegin_dynamic.o
	CRTEND=$(SYSROOT)/usr/lib64/crtend_android.o
      else
	CCPART=i686-linux-android
	SYS+=-fstack-protector
      endif
      # gcc defines __ANDROID__ for all *-*-linux-*android* targets
      __EXTRADEF:=-D__ANDROID_X86__
    endif
    # Android common
    STLDIR=
    STLDEFS=
    __EXTRACPP:=-fno-rtti
  else
    ifneq ($(or $(__EA64__),$(__X64__)),)
      $(error "Please undefine __EA64__, __X64__ to compile for ARM Linux")
    endif
    ifdef __UCLINUX__
      SYSNAME:=uclinux
      CCPART=arm-uclinuxeabi
      __EXTRADEF:=-D__ARM__ -D__UCLINUX__
      __EXTRACPP:=-fno-rtti
    else
      __EXTRADEF:=-D__ARM__
      __EXTRACPP:=-fexceptions
      SYSNAME:=linux
      CCPART=arm-none-linux-gnueabi
    endif
    CCDIR=$(SOURCERY)/bin
    SYSROOT=$(SOURCERY)/$(CCPART)/libc
    STLDEFS=$(strip                         \
	    -D_M_ARM                        \
	    -D__linux__                     \
	    -D_STLP_HAS_NO_NEW_C_HEADERS    \
	    -D_STLP_NO_BAD_ALLOC            \
	    -D_STLP_NO_EXCEPTION_HEADER     \
	    -D_STLP_USE_NO_IOSTREAMS        \
	    -D_STLP_USE_MALLOC              \
	    -D_STLP_UINT32_T="unsigned long")
  endif
  CC=$(CCDIR)/$(CCPART)-gcc.exe
  CXX=$(CCDIR)/$(CCPART)-g++.exe
  SYSINC=$(SYSROOT)/usr/include
  SYSLIB=$(SYSROOT)/usr/lib
  __EXTRADEF+=-Wno-psabi

  CFLAGS=$(strip \
        $(SYS) $(SWITCH64) $(SWITCHX64) $(CCOPT)                  \
	-I$(I) $(if $(STLDIR),-I$(STLDIR)) -I$(SYSINC)            \
  	-D__LINUX__                                               \
  	$(__EXTRADEF)                                             \
  	-D_FORTIFY_SOURCE=0                                       \
  	-DNO_OBSOLETE_FUNCS                                       \
  	-DUSE_DANGEROUS_FUNCTIONS                                 \
  	$(STLDEFS)                                                \
  	-pipe -fno-strict-aliasing -fwrapv $(_CFLAGS))
  CPPFLAGS=-fvisibility=hidden -fvisibility-inlines-hidden $(__EXTRACPP) $(CFLAGS)
  OUTSW=-o #with space
  OBJSW=-o #with space
  STDLIBS=-lrt -lpthread
  ifneq ($(or $(__ANDROID__),$(__ANDROID_X86__)),)
    LDFLAGS=-nostdlib -Bdynamic -Wl,-z,nocopyreloc -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now
    SYSLIBS=-L$(SYSLIB)
    ifdef __ANDROID__
      ifdef __X64__
	LDFLAGS+=-Wl,-dynamic-linker,/system/bin/linker64
	SYSLIBS+=$(ANDROID_NDK)/aarch64-linux-android/lib/libstdc++.a
      else
	LDFLAGS+=-Wl,-dynamic-linker,/system/bin/linker -mthumb
	SYSLIBS+=$(ANDROID_NDK)/arm-linux-androideabi/lib/thumb/libstdc++.a
      endif
    else  # __ANDROID_X86__
      ifdef __X64__
        LDFLAGS+=-fPIE -pie --sysroot=$(SYSROOT)
	SYSLIB=$(SYSROOT)/usr/lib64
        SYSLIBS=-L$(SYSLIB) -L$(SYSROOT)/usr/lib $(ANDROID_NDK)/$(CCPART)/lib64/libstdc++.a
      else
        SYSLIBS+=$(ANDROID_NDK)/$(CCPART)/lib/libstdc++.a
      endif
    endif
    LDFLAGS+=$(_LDFLAGS)
    CCL=$(CXX) $(LDFLAGS)
    SYSLIBS+=-lc -lgcc -ldl -Wl,--export-dynamic
  else
    LDFLAGS =-Wl,-z $(_LDFLAGS)
    CCL=$(CXX) $(LDFLAGS) $(STDLIBS)
  endif
  OUTDLL  =$(SYS) -Wl,--gc-sections -Wl,--no-undefined $(OUTDLLOPTS)
  B       =
  BS      =.exe
  DLLEXT  =.so
  O       =.o
  A       =.a
  AR      =$(RS)ar$(BS) _e.at _g _l$(CCDIR)/$(CCPART)-ar.exe $(AROPT)
#############################################################################
else ifdef __LINT__                                       # PC-Lint
  __CODE_CHECKER__=1
  COMPILER_NAME=lint
  ifdef __X64__
    TARGET_PROCESSOR_NAME=x64
  else
    TARGET_PROCESSOR_NAME=x86
  endif
  ifdef LINT_WARNING_MODE
    LINT_ALWAYS_SUCCEED=--lint-always-succeed
  endif
  # 647 suspicuous truncation -- we should eventually enable this
  ifdef __X64__
    SUPPRESS64=-e647
  else
    ifdef __EA64__
      SUPPRESS64=-e647
    endif
  endif
  CC      =$(PYTHON) $(RS)pclint.py $(LINT_ALWAYS_SUCCEED)
  CFLAGS  =$(SUPPRESS64) $(SWITCH64) $(SWITCHX64) $(_CFLAGS) $(LINTFLAGS)
  OUTSW   =--outdir
  OBJSW   =--outdir
  _LINKER =$(CC) --link
  LINKER  =$(_LINKER) $(_LDFLAGS) $(_LSHOW)
  CCL     =$(CC)
  AR      =$(CC) --lib
  O       =.lint
  B       =.lintexe
  A       =.lib
  R32     =$(RS)/x86_win_vc/
  B32     =$(SUFF64).exe
#############################################################################
else ifdef __X64__                         # Visual Studio for AMD64
  COMPILER_NAME=vc
  ifdef __VC8__
    SDK_LIB1=/LIBPATH:$(MSSDK)lib/x64
  else
    SDK_LIB1=/LIBPATH:$(WSDK_LIB)um/x64
    SDK_LIB2=/LIBPATH:$(WSDK_LIB)ucrt/x64
  endif
  TARGET_PROCESSOR_NAME=x64
  CC      =$(MSVCDIR)bin/amd64/cl.exe
  CFLAGS  =@$(IDA)$(SYSDIR)$(OPTSUF)$(STATSUF).cfg $(RUNTIME_LIBSW) $(SWITCH64) $(SWITCHX64) $(NOWARNS) $(_CFLAGS) $(_CSHOW)
  ifndef __USE_RTTI__
    NORTTI = /GR-
  endif
  OUTSW   =/Fe
  OBJSW   =/Fo
  BASESW  =/BASE
  OUTDLL  =/LD
  LNOUTDLL=/DLL
  ifdef BASE
    LDFLAGS =$(BASESW):$(BASE) $(_LDFLAGS)
  else
    LDFLAGS =$(_LDFLAGS)
  endif
  _LIBRTL=$(MSVCDIR)lib/amd64
  LINKOPTS_EXE=/LIBPATH:$(_LIBRTL) $(SDK_LIB1) $(SDK_LIB2) $(_LNK_EXE_MAP) $(LNDEBUG) $(LNKERREP)
  LINKOPTS=$(LNOUTDLL) $(LINKOPTS_EXE) $(_LSHOW)
  _LINKER =$(LDEXE) _v _l$(MSVCDIR)bin/amd64/link.exe
  CCL     =$(LDEXE) _v _l$(CC) _a"/link $(LINKOPTS_EXE) $(CCL_LNK_OPT) $(_LDFLAGS)" $(CFLAGS)
  LINKER=$(_LINKER) $(LDFLAGS) $(LNDEBUG) $(_LSHOW)
  C_STARTUP=
  C_LIB   =kernel32.lib
  B       =$(SUFF64).exe
  BS      =$(SUFF64).exe
  DLLEXT  =$(SUFF64).dll
  IDP     =$(DLLEXT)
  LDR     =$(DLLEXT)
  PLUGIN  =$(DLLEXT)
  O       =.obj
  A       =.lib
  ifndef NORTL
    IDPSTUB =
    LDRSTUB =
    IDPSLIB =$(C_LIB)
  else
    IDPSTUB =$(LIBDIR)/modstart
    LDRSTUB =$(LIBDIR)/modstart
    IDPSLIB =$(C_LIB)
  endif
  AR      =$(RS)ar$(BS) _e.at _v _l$(MSVCDIR)bin/amd64/lib.exe $(_LBSHOW) $(AROPT)
  # force C mode for .c files
  ifdef DONT_FORCE_CPP
    FORCEC=/TC
  endif
#############################################################################
else ifdef __CEARM__                                      # Visual C++ v4.0 for ARM 4.20
  BUILD_ONLY_SERVER=1
  COMPILER_NAME=vc
  TARGET_PROCESSOR_NAME=arm
  CC      ="$(MSVCARMDIR)bin/x86_arm/cl.exe"
  CFLAGS  =@$(IDA)$(SYSDIR)$(OPTSUF)$(STATSUF).cfg $(SWITCH64) $(SWITCHX64) $(PROCFLAG) $(NOWARNS) $(_CFLAGS) $(_CSHOW) # default compiler flags
  ifndef __USE_RTTI__
    NORTTI = /GR-
  endif
  ##CFLAG_SUFFIX = /link /subsystem:windowsce
  OUTSW   =/Fe
  OBJSW   =/Fo
  ifdef BASE
    LDFLAGS =/BASE:$(BASE) $(_LDFLAGS)
  else
    LDFLAGS =$(_LDFLAGS)
  endif
  OUTDLL  =-LD
  LINKOPTS_EXE=/LIBPATH:"$(MSVCARMDIR)lib/armv4" /LIBPATH:"$(ARMSDK)lib/armv4" $(LNDEBUG)
  LINKOPTS=$(LINKOPTS_EXE) $(_LSHOW)
  _LINKER =$(LDEXE) _l$(MSVCARMDIR)bin/x86_arm/link.exe
  LINKER =$(_LINKER) $(LDFLAGS)
  CCL     =$(LDEXE) _c _l$(CC) _a"/link /subsystem:windowsce,4.20 /machine:arm /armpadcode $(CCL_LNK_OPT) $(LINKOPTS)" $(CFLAGS) $(_LDFLAGS)
  C_LIB   =corelibc.lib coredll.lib libcmtd.lib
  B       =_arm.exe
  BS      =.exe
  IDP     =.cearm32
  DLLEXT  =.dll
  IDP     =.cearm32
  LDR     =.cearm32
  PLUGIN  =.cearm32
  O       =.obj
  A       =.lib
  IDPSLIB =$(C_LIB)
  _LIBR   =$(MSVCARMDIR)bin/x86_arm/lib.exe
  AR      =$(RS)ar$(BS) _e.at _v "_l$(_LIBR)" $(_LBSHOW) $(AROPT)
  # force C mode for .c files
  ifdef DONT_FORCE_CPP
    FORCEC=/TC
  endif
  _ARMASM ="$(MSVCARMDIR)bin/x86_arm/armasm.exe"
  R32     =$(RS)/x86_win_vc/
  B32     =$(BS)
#############################################################################
else                                                      # Visual Studio 2015 for x86
  __VC__=1
# /analyze not available for preview
#  VC_ANALYZE=/analyze
  COMPILER_NAME=vc
  ifdef __VC8__
    SDK_LIB1=/LIBPATH:$(MSSDK)lib
  else
    SDK_LIB1=/LIBPATH:$(WSDK_LIB)um/x86
    SDK_LIB2=/LIBPATH:$(WSDK_LIB)ucrt/x86
  endif
  TARGET_PROCESSOR_NAME=x86
  CC      =$(MSVCDIR)bin/cl.exe
  CFLAGS  =@$(IDA)$(SYSDIR)$(OPTSUF)$(STATSUF).cfg $(RUNTIME_LIBSW) $(SWITCH64) $(SWITCHX64) $(NOWARNS) $(_CFLAGS) $(_CSHOW) $(VC_ANALYZE)
  ifndef __USE_RTTI__
    NORTTI = /GR-
  endif
  OUTSW   =/Fe
  OBJSW   =/Fo
  BASESW  =/BASE
  OUTDLL  =/LD
  LNOUTDLL=/DLL
  ifdef BASE
    LDFLAGS =$(BASESW):$(BASE)
  endif
  _LIBRTL=$(MSVCDIR)lib
  LDFLAGS+=$(_LDFLAGS)
  LINKOPTS_EXE=/LIBPATH:$(_LIBRTL) $(SDK_LIB1) $(SDK_LIB2) $(_LNK_EXE_MAP) $(LNDEBUG) /LARGEADDRESSAWARE /DYNAMICBASE
  LINKOPTS=$(LNOUTDLL) $(LINKOPTS_EXE) $(_LSHOW) $(LNDEBUG)
  _LINKER =$(LDEXE) _l$(MSVCDIR)bin/link.exe
  CCL     =$(LDEXE) _v _l$(CC) _a"/link $(LINKOPTS_EXE) $(LDFLAGS)" $(CFLAGS)
  LINKER=$(_LINKER) $(LDFLAGS) $(LNDEBUG) $(_LSHOW)
  C_STARTUP=
  C_LIB   =kernel32.lib
  B       =$(SUFF64).exe
  BS      =.exe
  DLLEXT  =$(SUFF64).wll
  IDP     =$(SUFF64).w$(ADRSIZE)
  ifdef __EA64__
    LDR     =64.l$(ADRSIZE)
    PLUGIN  =.p$(ADRSIZE)
  else
    LDR     =.ldw
    PLUGIN  =.plw
  endif
  O       =.obj
  A       =.lib
  ifndef NORTL
    IDPSTUB =
    LDRSTUB =
    IDPSLIB =$(C_LIB)
  else
    IDPSTUB =$(LIBDIR)/modstart
    LDRSTUB =$(LIBDIR)/modstart
    IDPSLIB =$(C_LIB)
  endif
  AR      =$(RS)ar$(BS) _e.at _v _l$(MSVCDIR)bin/lib.exe $(_LBSHOW) $(AROPT)
  # force C mode for .c files
  ifdef DONT_FORCE_CPP
    FORCEC=/TC
  endif
endif
#############################################################################
ifdef __PVS__
  __CODE_CHECKER__=1
  #_CFLAGS:=$(_CFLAGS)
  ifdef PVS_WARNING_MODE
    PVSFLAGS:=--pvs-warning-mode
  endif
  ifdef PVS_VERBOSE
    PVSFLAGS+=--pvs-verbose
  endif
  COMPILER_NAME=pvs
  CC    =$(PYTHON) $(RS)pvsstudio.py $(PVSFLAGS)
  LDEXE =$(CC) --link
  AR    =$(CC) --lib
  R32     =$(RS)/x86_win_vc/
  B32     =$(SUFF64).exe
endif
#############################################################################

SYSDIR=$(TARGET_PROCESSOR_NAME)_$(SYSNAME)_$(COMPILER_NAME)_$(ADRSIZE)
# libraries directory
LIBDIR=$(IDA)lib/$(SYSDIR)
# object files directory
OBJDIR=obj/$(SYSDIR)$(OPTSUF)$(STATSUF)
# PDB files directory
PDBDIR=$(IDA)pdb/$(SYSDIR)

ifeq (1,0)           # this is for makedep
  F=
else
  F=$(OBJDIR)/
  L=$(LIBDIR)/
  R=$(IDA)bin/
endif

RS=$(IDA)bin/
BS=.exe

ifndef R32
  # can be defined before for build x64 in win32
  R32=$(R)
  B32=$(B)
else ifndef B32
  B32=$(BS)
endif

# Help Compiler
HC=$(R32)ihc$(B32)
STM=$(R32)stm$(B32)

IDALIB:=$(L)ida$(A)
DUMB:=$(L)dumb$(O)
HELP:=$(L)help$(O)
HLIB:=$(HI)_ida.hlp

CLPLIB:=$(L)clp$(A)

RM=rm -f
CP=cp -f --preserve=all
MV=mv
MKDIR=-@mkdir

# to be used like this: $(call link_dumb,$@ objfiles)
link_dumb=$(CCL) $(OUTSW)$1 $(DUMB) $(L)pro$(A)

########################################################################
CONLY?=-c

$(F)%$(O): %.cpp | objdir
ifneq ($(or $(__ANDROID__),$(__ANDROID_X86__),$(__ARMLINUX__)),)
	$(CXX) $(CPPFLAGS) $(CONLY) $(OBJSW)$@ $<
$(F)%$(O): %.c | objdir
	$(CC) $(CFLAGS) $(CONLY) $(OBJSW)$@ $<
else
	$(CC) $(CFLAGS) $(NORTTI) $(OBJSW)$@ $(CONLY) $<
$(F)%$(O): %.c | objdir
	$(CC) $(CFLAGS) $(CONLY) $(OBJSW)$@ $(FORCEC) $<
$(F)%$(O): %.asm | objdir
	$(ASM) $(AFLAGS) $(call dospath,$<),$(call dospath,$@)
endif

%.hhp: %.hls
	$(HC) -t $(HLIB) -i$@ $?

DLLSUFF=.dll

########################################################################
endif # if unix or windows

ifdef TESTABLE_BUILD
  CFLAGS+=-DTESTABLE_BUILD
  QT_TESTABLE_BUILD=TESTABLE_BUILD=1
endif

ifndef __NT__
  EXTERNAL_DLL_PFX=lib
endif

# http://www.cmcrossroads.com/article/printing-value-makefile-variable
print-%  :
	@echo $* = $($*)
	@echo $*\'s origin is $(origin $*)
