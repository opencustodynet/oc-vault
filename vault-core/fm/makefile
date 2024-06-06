# default the FMSDK path
FMSDK?=/usr/safenet/lunafmsdk
LUNASDK=/usr/safenet/lunaclient

# to use gcc from /usr/bin run
PPWERPC=/opt/eldk-5.6/powerpc-4xx/sysroots/i686-eldk-linux/usr/bin/powerpc-linux
STRIP=$(PPWERPC)/powerpc-linux-strip
RELEASE=../../target/powerpc-unknown-linux-gnu/release
include $(FMSDK)/samples/fmconfig.mk

NAME = vault-core

FMTARGETDIR ?= .

ODIR = $(FMTARGETDIR)/obj-ppc
BDIR = $(RELEASE)

_OBJS = \
	hdr.o \
	vault.o

OBJS = $(patsubst %,$(ODIR)/%,$(_OBJS))

INCLUDE += \
    /usr/safenet/lunaclient/samples/include \
    $(FMSDK)/include \
	$(FMSDK)/include/fm/hsm \
    $(FMSDK)/include/fm/host \
	.

FMLIBS:= \
	fmsupt

DEFINES+=

L_FLAGS +=-Wl,-t

LIBS := -L$(FMLIBDIR) $(addprefix -l,$(FMLIBS)) -L$(RELEASE) -lvault_core

C_FLAGS += -O2

I_OPT    := $(addprefix -I, $(INCLUDE))

all: $(BDIR)/$(NAME).bin strip

$(BDIR):
	mkdir -p $(BDIR)

$(ODIR):
	mkdir -p $(ODIR)

$(ODIR)/%.o: %.c $(ODIR)
	$(CC) -c $(I_OPT) $(DEFINES) $(C_FLAGS) -o$@ $<

$(BDIR)/$(NAME).bin : $(BDIR) $(OBJS)
	$(CC) $(L_FLAGS) $(L_FLAGS2) -o$@ $(OBJS) $(LIBS) -lgcc

strip:
	$(STRIP) -s $(BDIR)/$(NAME).bin

clean:
	-rm -r $(BDIR) $(ODIR)

dirs: $(BDIR) $(ODIR)

