ifndef USE_STATIC_RUNTIME
_CFLAGS=$(__CFLAGS) -D__IDP__ 
  ifndef DONT_BUILD_PLUGIN
    _CFLAGS += -D__PLUGIN__
  endif
__IDP__=1
else
_CFLAGS=$(__CFLAGS)
endif
LINTFLAGS=$(_LINTFLAGS)

ifndef O
  include ../../allmake.mak
endif

ifdef BETA
  F:=beta$(F)
endif

# to avoid 'undefined symbol' warnings from gnu make with --warn-undefined-variables
OBJ1:=
OBJ2:=
OBJ3:=
OBJ4:=
OBJ5:=
OBJ6:=
OBJ7:=
OBJ8:=
OBJ9:=
OBJ10:=
OBJ11:=
OBJ12:=
OBJ13:=
OBJ14:=
OBJ15:=

ifdef O1
  OBJ1:=$(F)$(O1)$(O)
endif
ifdef O2
  OBJ2:=$(F)$(O2)$(O)
endif
ifdef O3
  OBJ3:=$(F)$(O3)$(O)
endif
ifdef O4
  OBJ4:=$(F)$(O4)$(O)
endif
ifdef O5
  OBJ5:=$(F)$(O5)$(O)
endif
ifdef O6
  OBJ6:=$(F)$(O6)$(O)
endif
ifdef O7
  OBJ7:=$(F)$(O7)$(O)
endif
ifdef O8
  OBJ8:=$(F)$(O8)$(O)
endif
ifdef O9
  OBJ9:=$(F)$(O9)$(O)
endif
ifdef O10
  OBJ10:=$(F)$(O10)$(O)
endif
ifdef O11
  OBJ11:=$(F)$(O11)$(O)
endif
ifdef O12
  OBJ12:=$(F)$(O12)$(O)
endif
ifdef O13
  OBJ13:=$(F)$(O13)$(O)
endif
ifdef O14
  OBJ14:=$(F)$(O14)$(O)
endif
ifdef O15
  OBJ15:=$(F)$(O15)$(O)
endif

OBJS:=$(F)$(PROC)$(O) $(OBJ1) $(OBJ2) $(OBJ3) $(OBJ4) $(OBJ5) $(OBJ6) $(OBJ7) \
     $(OBJ8) $(OBJ9) $(OBJ10) $(OBJ11) $(OBJ12) $(OBJ13) $(OBJ14) $(OBJ15)   \
     $(ADDITIONAL_OBJS)

BIN_PATH:=$(R)plugins/

ifndef DONT_BUILD_PLUGIN
  BINARY=$(BIN_PATH)$(PROC)$(PLUGIN)
endif

all:	objdir $(BINARY) $(ADDITIONAL_GOALS)
include ../../objdir.mak

ifdef __UNIX__
  ifndef PLUGIN_SCRIPT
    ifdef __LINUX__
      PLUGIN_SCRIPT=-Wl,--version-script=../../plugins/plugin.script
    endif
    ifdef __MAC__
      PLUGIN_SCRIPT=-Wl,-install_name,$(@F)
    endif
  endif
  DEFFILE=

  ifndef DONT_BUILD_PLUGIN
$(BINARY): ../../plugins/plugin.script $(OBJS) makefile
	$(CXX) $(ARCH_CFLAGS) $(CFLAGS) $(OUTDLL) $(OUTSW)$@ $(OBJS) -L$(R) $(LINKIDA) $(PLUGIN_SCRIPT) $(ADDITIONAL_LIBS) $(STDLIBS)
  endif
else # windows

  ifdef __X64__
    DEFFILE:=../../plugins/plugin64.def
  else
    DEFFILE:=../../plugins/plugin.def
  endif

  ifneq ($(and $(__VC__),$(DEBUG)),)
    PDBSW=/PDB:$(BIN_PATH)$(PROC)$(SUFF64).pdb
  endif

  ifndef DONT_BUILD_PLUGIN
$(BINARY): $(DEFFILE) $(OBJS) $(IDALIB) $(RESFILES)
	$(LINKER) $(LINKOPTS) /STUB:../../plugins/stub /OUT:$@ $(PDBSW) $(OBJS) $(IDALIB) user32.lib $(ADDITIONAL_LIBS)
	@$(RM) $(@:$(PLUGIN)=.exp) $(@:$(PLUGIN)=.lib)
  endif
endif
ifdef POSTACTION
	$(POSTACTION)
endif
