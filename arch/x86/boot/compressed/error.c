// SPDX-License-Identifier: GPL-2.0
/*
 * Callers outside of misc.c need access to the error reporting routines,
 * but the *_putstr() functions need to stay in misc.c because of how
 * memcpy() and memmove() are defined for the compressed boot environment.
 */
#include "misc.h"
#include "error.h"

void warn(const char *m)
{
	error_putstr("\n\n");
	error_putstr(m);
	error_putstr("\n\n");
}

void error(char *m)
{
	warn(m);
	error_putstr(" -- System halted");

	while (1)
		asm("hlt");
}

#if IS_ENABLED(CONFIG_HAKC)
/* EFI libstub  provides ls_vsnprintf() */
#else
/* EFI libstub  provides vsnprintf() */
#endif
#ifdef CONFIG_EFI_STUB
void panic(const char *fmt, ...)
{
	static char buf[1024];
	va_list args;
	int len;

	va_start(args, fmt);
#if IS_ENABLED(CONFIG_HAKC)
	len = ls_vsnprintf(buf, sizeof(buf), fmt, args);
#else
	len = vsnprintf(buf, sizeof(buf), fmt, args);
#endif
	va_end(args);

	if (len && buf[len - 1] == '\n')
		buf[len - 1] = '\0';

	error(buf);
}
#endif
