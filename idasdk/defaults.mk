RS=$(IDA)bin/

PEUTIL=$(RS)peutil.exe

ULNK_BASE=$(RS)ulink.exe

TLIB=$(RS)tlib.exe

ULNK_CFG_DIR=$(RS)

# Build 64-bit modules by default. Unset this to build 32-bit debug servers.
__X64__=1

ifdef __EA64__
  ifndef __X64__
    $(error "This SDK does not build for 32-bit ida64")
  endif
endif

# Force make to delete the target if the rule to build it fails
.DELETE_ON_ERROR:

THIRD_PARTY?=$(IDA)../third_party/
PYTHON_VERSION_MAJOR?=2
PYTHON_VERSION_MINOR?=7
PYTHON_VERNAME=python$(PYTHON_VERSION_MAJOR).$(PYTHON_VERSION_MINOR)

ifdef __NT__
  # This function converts a windows path to a 8.3 path with forward slashes as
  # file separator.  If the path doesn't exist, it is returned as is.
  shortdospath=$(subst \,/,$(shell if [ -e $(1) ]; then cygpath -d $(1); else echo $(1); fi))

  #-------------------------------------------------------

  ifndef VSPATH
    VSPATH := $(call shortdospath,"C:/Program Files (x86)/Microsoft Visual Studio 14.0/")
    export VSPATH
    ifeq (,$(wildcard $(VSPATH)))
      $(error Visual Studio not found in VSPATH (see defaults.mk))
    endif
  endif
  ifndef WSDKPATH
    WSDKPATH := $(call shortdospath,"C:/Program Files (x86)/Windows Kits/10/")
    export WSDKPATH
    ifeq (,$(wildcard $(WSDKPATH)))
      $(error Windows SDK not found in WSDKPATH (see defaults.mk))
    endif
  endif
  WSDKVER := "10.0.10240.0"

  ifndef WSDK_INCLUDE
    WSDK_INCLUDE := $(call shortdospath,"$(WSDKPATH)Include/$(WSDKVER)/")
    export WSDK_INCLUDE
    ifeq (,$(wildcard $(WSDK_INCLUDE)))
      $(error Windows SDK version $(WSDKVER) not found (see defaults.mk))
    endif
  endif
  ifndef WSDK_LIB
    WSDK_LIB := $(call shortdospath,"$(WSDKPATH)Lib/$(WSDKVER)/")
    export WSDK_LIB
    ifeq (,$(wildcard $(WSDK_LIB)))
      $(error Windows SDK version $(WSDKVER) not found (see defaults.mk))
    endif
  endif
  ifndef UCRT_INCLUDE
    UCRT_INCLUDE := $(call shortdospath,"$(WSDK_INCLUDE)ucrt/")
    export UCRT_INCLUDE
  endif
  ifndef UCRT_LIB
    UCRT_LIB := $(call shortdospath,"(WSDK_LIB)ucrt/")
    export UCRT_LIB
  endif
  ifndef VSPATH8
    VSPATH8 := $(call shortdospath,"C:/Program Files (x86)/Microsoft Visual Studio 9.0/")
    export VSPATH8
  endif
  ifndef MSSDK
    MSSDK := $(call shortdospath,"C:/Program Files (x86)/Microsoft SDKs/Windows/v7.1A/")
    export MSSDK
  endif
  ARMSDK?=$(VSPATH8)SmartDevices/SDK/PocketPC2003/
  GCCBINDIR?=c:/cygwin/bin
  PYTHON_ROOT?=c:
  PYTHON27_X86?=$(PYTHON_ROOT)/python$(PYTHON_VERSION_MAJOR)$(PYTHON_VERSION_MINOR)/python.exe
  PYTHON27_X64?=$(PYTHON_ROOT)/python$(PYTHON_VERSION_MAJOR)$(PYTHON_VERSION_MINOR)-x64/python.exe
else
  ifdef __LINUX__
    PYTHON27_X86?=$(PYTHON_VERNAME)
    PYTHON27_X64?=/usr/bin/$(PYTHON_VERNAME)
  else
    PYTHON27_X86=$(PYTHON_VERNAME)
    PYTHON27_X64=$(PYTHON_VERNAME)
  endif
endif

ifdef __X64__
  PYTHON?=$(PYTHON27_X64)
else
  PYTHON?=$(PYTHON27_X86)
endif

ifdef __LINUX__
  # I (arnaud) have to introduce this so I can have debuggable 32-bit
  # IDA binaries on Stretch.
  LINKTIME_HARDENING?=-z now
endif

# Qt version
QTVER_?=5.6.0
ifdef __X64__
  QTSUFF=-x64
endif
QTVER=$(QTVER_)$(QTSUFF)

# Qt directory
ifdef __NT__
  QTDIR?=c:/Qt/$(QTVER)/
else
  ifdef __MAC__
    QTDIR?=/Users/Shared/Qt/$(QTVER)/
  else
    QTDIR?=/usr/local/Qt/$(QTVER)/
  endif
  QT_QMAKE?=$(QTDIR)/bin/qmake
endif


# PyQt version
PYQTVER?=5.6.0$(QTSUFF)
SIPVER?=4.18$(QTSUFF)


ANDROID_NDK?=c:/android-ndk-r4b/
SOURCERY?=C:/CODESO~1/SOURCE~1
HHC?=$(IDA)ui/qt/help/chm/hhc.exe
STLDIR?=$(THIRD_PARTY)stlport

# Doxygen
ifdef __NT__
  DOXYGEN_BIN=$(THIRD_PARTY)doxygen/bin/windows/Release/doxygen.exe
else
  ifdef __MAC__
    DOXYGEN_BIN=$(THIRD_PARTY)doxygen/bin/mac/doxygen
  else
    DOXYGEN_BIN=$(THIRD_PARTY)doxygen/bin/linux/doxygen
  endif
endif

# SWiG
SWIG_VERSION?=2.0.12
ifdef __NT__
  SWIGDIR=$(THIRD_PARTY)swig/swigwin-$(SWIG_VERSION)/
  SWIG?=$(SWIGDIR)/swig.exe
else
  ifdef __MAC__
    SWIGDIR=$(THIRD_PARTY)swig/swigmac-$(SWIG_VERSION)/swig-$(SWIG_VERSION)-install/
    SWIG?=$(SWIGDIR)bin/swig
  else
    SWIGDIR=$(THIRD_PARTY)swig/swiglinux-$(SWIG_VERSION)/swig-$(SWIG_VERSION)-install/
    SWIG?=$(SWIGDIR)bin/swig
  endif
endif


# keep all paths in unix format, with forward slashes
MSSDK        :=$(call unixpath,$(MSSDK))
VSPATH8      :=$(call unixpath,$(VSPATH8))
VSPATH       :=$(call unixpath,$(VSPATH))
WSDK_INCLUDE :=$(call unixpath,$(WSDK_INCLUDE))
WSDK_LIB     :=$(call unixpath,$(WSDK_LIB))
UCRT_INCLUDE :=$(call unixpath,$(UCRT_INCLUDE))
UCRT_LIB     :=$(call unixpath,$(UCRT_LIB))
ARMSDK       :=$(call unixpath,$(ARMSDK))
GCCBINDIR    :=$(call unixpath,$(GCCBINDIR))
PYTHON_ROOT  :=$(call unixpath,$(PYTHON_ROOT))
# unixpath-ify PYTHON _only_ if it was defined. Otherwise, this will
# define it and conditional assignments (i.e., '?=') will never apply
ifneq ($(origin PYTHON), undefined)
  PYTHON     :=$(call unixpath,$(PYTHON))
endif
SWIG         :=$(call unixpath,$(SWIG))
QTDIR        :=$(call unixpath,$(QTDIR))
ANDROID_NDK  :=$(call unixpath,$(ANDROID_NDK))
SOURCERY     :=$(call unixpath,$(SOURCERY))
STLDIR       :=$(call unixpath,$(STLDIR))
HHC          :=$(call unixpath,$(HHC))
ifdef __NT__
  THIRD_PARTY  :=$(call unixpath,$(THIRD_PARTY))
endif

QT_QMAKE?=$(QTDIR)/bin/qmake

# http://stackoverflow.com/questions/16467718/how-to-print-out-a-variable-in-makefile
.print-%  : ; @echo $($*)

################################EOF###############################
