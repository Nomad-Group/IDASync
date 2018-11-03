
# definitions for idapython (& other plugins dynamically linked to Python)
ifdef __NT__
  ifneq ($(UCRT_INCLUDE),)
    I_UCRT_INCLUDE=/I$(UCRT_INCLUDE)
  endif
  PYTHON_ROOT?=c:
  ifdef __X64__
    PYTHON_DIR_SUFFIX=-x64
  endif
  PYTHON_DIR=$(PYTHON_ROOT)/python$(PYTHON_VERSION_MAJOR)$(PYTHON_VERSION_MINOR)$(PYTHON_DIR_SUFFIX)
  PYTHON_CFLAGS=-I$(PYTHON_DIR)/include /EHsc
  PYTHON_LDFLAGS=$(PYTHON_DIR)/libs/python$(PYTHON_VERSION_MAJOR)$(PYTHON_VERSION_MINOR).lib
else
  ifdef __LINUX__
    LIBPYTHON_NAME=libpython$(PYTHON_VERSION_MAJOR).$(PYTHON_VERSION_MINOR).so.1.0
    PRECOMPILED_DIR:=$(shell pwd)/../idapython/precompiled

    ifdef __X64__
      ifneq ($(LINUX_PYTHON_HOME_X64),)
        L_PYTHON_INCLUDES=-I$(LINUX_PYTHON_HOME_X64)/include/$(PYTHON_VERNAME)
        L_PYTHON_LDFLAGS=-L$(LINUX_PYTHON_HOME_X64)/lib -lpython$(PYTHON_VERSION_MAJOR).$(PYTHON_VERSION_MINOR) -ldl
      else
        L_PYTHON_INCLUDES:=$(shell $(PYTHON)-config --includes)
        L_PYTHON_LDFLAGS:=$(shell $(PYTHON)-config --ldflags)
      endif
    else
      ifneq ($(LINUX_PYTHON_HOME),)
        L_PYTHON_INCLUDES=-I$(LINUX_PYTHON_HOME)/include/$(PYTHON_VERNAME)
        L_PYTHON_LDFLAGS=-L$(LINUX_PYTHON_HOME)/lib -lpython$(PYTHON_VERSION_MAJOR).$(PYTHON_VERSION_MINOR) -ldl
      else
        L_PYTHON_INCLUDES=-I$(PRECOMPILED_DIR)/include/$(PYTHON_VERNAME)
        L_PYTHON_LDFLAGS:=$(PRECOMPILED_DIR)/$(LIBPYTHON_NAME) -ldl
      endif
    endif

    PYTHON_CFLAGS=$(L_PYTHON_INCLUDES)
    PYTHON_LDFLAGS=$(L_PYTHON_LDFLAGS)
  else # __MAC__
    PYTHON_CFLAGS:=$(shell $(PYTHON)-config --includes)
    PYTHON_LDFLAGS:=$(shell $(PYTHON)-config --ldflags)
  endif
endif
