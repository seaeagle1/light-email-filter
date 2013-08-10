
sbin_PROGRAMS = light_email_filter

light_email_filter_SOURCES = lefilter.c \
			../proxsmtp/common/spio.c ../proxsmtp/common/smtppass.c \
			../proxsmtp/common/smtppass.h ../proxsmtp/common/sppriv.h \
			../proxsmtp/common/stringx.c ../proxsmtp/common/stringx.h \
			../proxsmtp/common/sock_any.c ../proxsmtp/common/sock_any.h \
			../proxsmtp/common/usuals.h ../proxsmtp/common/compat.c \
			../proxsmtp/common/compat.h

light_email_filter_CFLAGS = -I${top_srcdir}/proxsmtp/common/ -I${top_srcdir}/

