#
# Makefile for the linux vdfs4-filesystem tools routines.
#
##########################################################################
# VDFS Tools Version Definition(MAJ.MIN-DATE)
##########################################################################
#-------------------------------------------------------------------------
MAJ_VER=1
MIN_VER=43
DATE=191204 #YYMMDD
#-------------------------------------------------------------------------
TOOLS_VERSION="$(strip $(MAJ_VER)).$(strip $(MIN_VER))-$(strip $(DATE))"
##########################################################################

MKFS = mkfs.vdfs
UNPACK = unpack.vdfs
FSCK = fsck.vdfs
TUNE = tune.vdfs
PAGE_TYPES = page-types.vdfs
TEST = test
BTREE_TEST = btrtst
INFO = info.vdfs

UNITTEST = unit_tests_cunit
CC = $(CROSS_COMPILE)gcc
HOST=`$(CROSS_COMPILE)gcc -dumpmachine`
LIBS = -lrt -lpthread
LIBZ = -lz


# Use system OpenSSL, zlib, lzo2 libraries and headers
OPENSSL_LIB = -lcrypto -ldl
ZLIB_FILE =
LZOLIB_FILE =
LZOLIB_LIB = -llzo2

CFLAGS += -Wall -Wextra -I./include -I./key
CFLAGS += -DTOOLS_VERSION=\"$(TOOLS_VERSION)\"
CFLAGS += -O1 -ggdb -MD
CFLAGS += -DUSER_SPACE
CFLAGS += -DCONFIG_VDFS4_DEBUG
CFLAGS += -Iinclude
CFLAGS += -D_FILE_OFFSET_BITS=64

# Add system include paths for OpenSSL, zlib, lzo2
CFLAGS += -I/usr/include
CFLAGS += -I/usr/include/openssl
CFLAGS += -I/usr/include/lzo

ifdef VDFS4_NO_WARN
	CFLAGS += -Werror
endif

ifeq ($(host),x86_32)
	CROSS_COMPILE=
	HOST=i686-linux-gnu
	CFLAGS += -m32
	SECURE_CFLAGS += -m32
endif
ifeq ($(host),x86_64)
	CROSS_COMPILE=
	HOST=x86_64-linux-gnu
endif

CFLAGS += -I$(HOME)/local/include

#Secure flags
ifeq ($(ENABLE_SECURE_FLAGS),1)
 SECURE_CFLAGS += -fstack-protector-strong
 SECURE_CFLAGS += -Wl,-z,relro
 SECURE_CFLAGS += -D_FORTIFY_SOURCE=2 -O1
 SECURE_CFLAGS += -fPIE -pie
 CFLAGS += $(SECURE_CFLAGS)
endif

SOURCE_MKFS = $(wildcard ./mkfs/*.c)
SOURCE_UNPACK = $(wildcard ./unpack/*.c)
SOURCE_FSCK = $(wildcard ./fsck/*.c)
SOURCE_TEST = $(wildcard ./full_btree_test/*.c)
SOURCE_BTREE_TEST = $(wildcard ./btree_test/*.c)
SOURCE_TUNE = $(wildcard ./tune/*.c)
SOURCE_LIB = $(wildcard ./lib/*.c)
SOURCE_PAGE_TYPES = $(wildcard ./vm/*.c)
SOURCE_INFO = $(wildcard ./info/*.c)
SOURCE_KEY = $(wildcard ./key/*.c)

DEPS = $(wildcard ./mkfs/*.d)
DEPS := $(DEPS) $(wildcard ./unpack/*.d)
DEPS := $(DEPS) $(wildcard ./fsck/*.d)
DEPS := $(DEPS) $(wildcard ./full_btree_test/*.d)
DEPS := $(DEPS) $(wildcard ./tune/*.d)
DEPS := $(DEPS) $(wildcard ./lib/*.d)
DEPS := $(DEPS) $(wildcard ./btree_test/*.d)
DEPS := $(DEPS) $(wildcard ./info/*.d)
DEPS := $(DEPS) $(wildcard ./tune/*.d)
DEPS := $(DEPS) $(wildcard ./lib/*.d)
DEPS := $(DEPS) $(wildcard ./vm/*.d)
DEPS := $(DEPS) $(wildcard ./unit_tests_cunit/*.d)
DEPS := $(DEPS) $(wildcard ./unit_tests_cunit/mkfs/*.d)

OBJ_MKFS = $(SOURCE_MKFS:.c=.o)
OBJ_TUNE = $(SOURCE_TUNE:.c=.o)
OBJ_LIB = $(SOURCE_LIB:.c=.o)
OBJ_FSCK = $(SOURCE_FSCK:.c=.o)
OBJ_TEST = $(SOURCE_TEST:.c=.o)
OBJ_BTREE_TEST = $(SOURCE_BTREE_TEST:.c=.o)
OBJ_UNPACK = $(SOURCE_UNPACK:.c=.o)
OBJ_MKFS_UNIT = $(SOURCE_MKFS_UNIT:.c=.o)
OBJ_LIB_UNIT = $(SOURCE_LIB_UNIT:.c=.o)
OBJ_UNPACK_UNIT = $(SOURCE_UNPACK_UNIT:.c=.o)
OBJ_TUNE_UNIT = $(SOURCE_TUNE_UNIT:.c=.o)
OBJ_INFO = $(SOURCE_INFO:.c=.o)
OBJ_KEY = $(SOURCE_KEY:.c=.o)

unpack: CFLAGS += -D__RD_FROM_VOL__
fsck: CFLAGS += -D__RD_FROM_VOL__
btrtst: CFLAGS += -DCONFIG_VDFS4_DEBUG_TOOLS_GET_BNODE

all: mkfs unpack tune fsck info

mkfs: $(OBJ_LIB) $(OBJ_MKFS) $(OBJ_KEY)
	@$(CC) -g -rdynamic -std=gnu99 -o $(MKFS) $(OBJ_LIB) $(OBJ_MKFS) $(OBJ_KEY) $(LIBS) $(LIBZ) $(LZOLIB_LIB) $(OPENSSL_LIB) $(SECURE_CFLAGS) $(CFLAGS)
	@echo "  CCLD      " $@;

unpack: $(OBJ_LIB) $(OBJ_UNPACK)
	@$(CC) -o $(UNPACK) $(OBJ_LIB) $(OBJ_UNPACK) $(LIBS) $(LIBZ) $(LZOLIB_LIB) $(OPENSSL_LIB) $(CFLAGS)
	@echo "  CCLD      " $@;

test: $(OBJ_LIB) $(OBJ_TEST)
	@$(CC) -o $(TEST) $(OBJ_LIB) $(OBJ_TEST) $(LIBZ) $(LZOLIB_LIB) $(OPENSSL_LIB) $(CFLAGS)
	@echo "  CCLD      " $@;

btrtst: $(OBJ_LIB) $(OBJ_BTREE_TEST)
	@$(CC) -o $(BTREE_TEST) $(OBJ_LIB) $(OBJ_BTREE_TEST) $(LIBZ) $(LZOLIB_LIB) $(OPENSSL_LIB) $(CFLAGS)
	@echo "  CCLD      " $@;

tune: $(OBJ_LIB) $(OBJ_TUNE)
	@$(CC) -std=gnu99 -o $(TUNE) $(OBJ_LIB) $(OBJ_TUNE) $(LIBS) $(LIBZ) $(LZOLIB_LIB) $(OPENSSL_LIB) $(CFLAGS)
	@echo "  CCLD      " $@;

fsck: $(OBJ_LIB) $(OBJ_FSCK)
	@$(CC) -std=gnu99 -o $(FSCK) $(OBJ_LIB) $(OBJ_FSCK) $(LIBS) $(LIBZ) $(LZOLIB_LIB) -lm $(OPENSSL_LIB) $(CFLAGS)
	@echo "  CCLD      " $@;

page-types: $(OBJ_PAGE_TYPES)
	@$(CC) -std=gnu99 -o $(PAGE_TYPES) $(OBJ_PAGE_TYPES) $(CFLAGS)
	@echo "  CCLD      " $@;

info: $(OBJ_INFO)
	@$(CC) -std=gnu99 -o $(INFO) $(OBJ_INFO) $(CFLAGS)
	@echo "  CCLD      " $@;

%.o : %.c
	@$(CC) $(CFLAGS) -c $< -o $@
	@echo "  CC        " $@;
-include $(DEPS)

clean:
	-rm -f $(OBJ_LIB)
	-rm -f $(MKFS) $(OBJ_MKFS)
	-rm -f $(UNPACK) $(OBJ_UNPACK)
	-rm -f $(FSCK) $(OBJ_FSCK)
	-rm -f $(TUNE) $(OBJ_TUNE)
	-rm -f $(TEST) $(OBJ_TEST)
	-rm -f $(PAGE_TYPES) $(OBJ_PAGE_TYPES)
	-rm -f $(INFO) $(OBJ_INFO)
	-rm -f $(OBJ_KEY)
	-rm -rf *.o
	-rm -rf ./src/*.o
	-rm -f $(UNITTEST)/*.o
	-rm -f $(DEPS)
	$(shell rm -f `find -name \*.o` > /dev/null 2> /dev/null)
	$(shell rm -f `find -name \*.d` > /dev/null 2> /dev/null)
	$(shell rm -f `find -name test` > /dev/null 2> /dev/null)
	$(shell rm -f `find -name \*.gcno` > /dev/null 2> /dev/null)
	$(shell rm -f `find -name \*.gcda` > /dev/null 2> /dev/null)
	$(shell rm -f `find -name \*.gcov` > /dev/null 2> /dev/null)
	$(shell rm -f `find -name test_report` > /dev/null 2> /dev/null)

distclean: clean

opensource: clean
	-rm -rf ./fsck ./info ./vdcrc ./tune ./unpack

unit_tests:
	$(eval export CFLAGS = -fprofile-arcs -ftest-coverage $(CFLAGS))
	$(eval export LFLAGS = -lgcov -coverage $(LFLAGS))
	make unit_tests_internal

unit_tests_internal: $(OBJ_LIB) $(OBJ_MKFS) $(OBJ_TUNE) $(OBJ_UNPACK)
	$(eval export CURRENT_DIRECTORY = $(shell pwd))
	$(eval export CFLAGS = -I$(CURRENT_DIRECTORY)/include $(CFLAGS))
	$(eval export CC HOME LIBS OPENSSL_LIB CPPFLAGS TARGET_ARCH)
	$(eval export OBJ_LIB = $(foreach lib,$(OBJ_LIB),$(CURRENT_DIRECTORY)/$(lib)))
	$(eval export OBJ_MKFS = $(foreach lib,$(OBJ_MKFS),$(CURRENT_DIRECTORY)/$(lib)))
	$(eval export OBJ_UNPACK = $(foreach lib,$(OBJ_UNPACK),$(CURRENT_DIRECTORY)/$(lib)))
	$(eval export OBJ_TUNE = $(foreach lib,$(OBJ_TUNE),$(CURRENT_DIRECTORY)/$(lib)))
	$(eval export ZLIB_FILE = $(foreach lib,$(ZLIB_FILE),$(CURRENT_DIRECTORY)/$(lib)))
	$(eval export LZOLIB_FILE = $(foreach lib,$(LZOLIB_FILE),$(CURRENT_DIRECTORY)/$(lib)))
	$(eval export OPENSSL_LIB = $(subst -L./,-L$(CURRENT_DIRECTORY)/,$(OPENSSL_LIB)))
	strip --strip-symbol main $(OBJ_MKFS);
	strip --strip-symbol main $(OBJ_TUNE);
	strip --strip-symbol main $(OBJ_UNPACK);
	make -C unit_tests_cunit
	$(UNITTEST)/count_results.sh
	gcov $(SOURCE_MKFS) $(SOURCE_UNPACK)  $(SOURCE_TEST) $(SOURCE_BTREE_TEST) $(SOURCE_TUNE)  $(SOURCE_LIB)

.PHONY: all clean distclean opensource mkfs unpack tune fsck info test btrtst unit_tests unit_tests_internal page-types
