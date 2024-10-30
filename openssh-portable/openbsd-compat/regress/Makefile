sysconfdir=/etc/ssh
piddir=/var/run
srcdir=.
top_srcdir=../..


CC=cc
LD=cc
CFLAGS=-g -O2 -pipe -Wno-error=format-truncation -Wall -Wextra -Wpointer-arith -Wuninitialized -Wsign-compare -Wformat-security -Wsizeof-pointer-memaccess -Wno-pointer-sign -Wno-unused-parameter -Wno-unused-result -Wimplicit-fallthrough -Wmisleading-indentation -fno-strict-aliasing -D_FORTIFY_SOURCE=2 -ftrapv -fzero-call-used-regs=used -ftrivial-auto-var-init=zero -fno-builtin-memset -fstack-protector-strong -fPIE  
CPPFLAGS=-I. -I.. -I../.. -I$(srcdir) -I$(srcdir)/.. -I$(srcdir)/../..  -D_XOPEN_SOURCE=600 -D_BSD_SOURCE -D_DEFAULT_SOURCE -D_GNU_SOURCE -DOPENSSL_API_COMPAT=0x10100000L -DHAVE_CONFIG_H
EXEEXT=
LIBCOMPAT=../libopenbsd-compat.a
LIBSSH=../../libssh.a
LIBS=-lmd  -lcrypto  -lz
LDFLAGS= -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -fstack-protector-strong -pie  $(LIBCOMPAT)

TESTPROGS=closefromtest$(EXEEXT) snprintftest$(EXEEXT) strduptest$(EXEEXT) \
	strtonumtest$(EXEEXT) opensslvertest$(EXEEXT) utimensattest$(EXEEXT)

all:	t-exec ${OTHERTESTS}

.c:	$(LIBCOMPAT) $(LIBSSH)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -o $@ $< $(LIBCOMPAT) $(LIBSSH) $(LIBS)

t-exec:	$(TESTPROGS)
	@echo running compat regress tests
	@for TEST in ""$?; do \
		echo "run test $${TEST}" ... 1>&2; \
		./$${TEST}$(EXEEXT) || exit $$? ; \
	done
	@echo finished compat regress tests

clean:
	rm -f *.o *.a core $(TESTPROGS) valid.out

distclean: clean
	rm -f Makefile *~
