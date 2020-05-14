SRCS += main.c
SRCS += sph_keccak.c
SRCS += keccak.c


SRCDIR = .
OBJDIR = obj

prefix = /usr/local
includedir = ${prefix}/include
libdir = ${prefix}/lib

TEST_PROGRAMS = test

###########################################################################

OBJECTS = $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SRCS))

COMMIT_ID := $(shell git describe --abbrev --always --tags --dirty 2>/dev/null || echo "")

CFLAGS += -std=gnu99 -pedantic -g
CFLAGS += -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers -Wno-pointer-to-int-cast $(DEBUG) -fPIC
CFLAGS += -DPERIPHERY_VERSION_COMMIT=\"$(COMMIT_ID)\"
LDFLAGS += -pthread -lstdc++ 

###########################################################################

.PHONY: all
all: $(TEST_PROGRAMS)

.PHONY: clean
clean:
	rm -rf $(OBJDIR) $(TEST_PROGRAMS)

###########################################################################

$(TEST_PROGRAMS): $(OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJECTS) -o $@

###########################################################################

$(OBJECTS): | $(OBJDIR)

$(OBJDIR):
	mkdir $(OBJDIR)

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) $(LDFLAGS) -c $< -o $@

