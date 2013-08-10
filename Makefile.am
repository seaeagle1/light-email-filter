EXTRA_DIST = acsite.m4 
SUBDIRS = src

dist-hook:
	@if test -d "$(srcdir)/.git"; \
	then \
		echo Creating ChangeLog &&\
		git log --date=short > ChangeLog;\
	else \
		echo A git clone is required to generate a ChangeLog >&2; \
	fi
