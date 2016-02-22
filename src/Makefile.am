
bin_PROGRAMS = tuntest

tuntest_SOURCES = \
  tuntest.c

tuntest_CFLAGS := $(NL_CFLAGS) $(NLROUTE_CFLAGS) $(NLGENL_CFLAGS)
tuntest_LDADD := -lpthread $(NL_LIBS) $(NLROUTE_LIBS) $(NLGENL_LIBS)
