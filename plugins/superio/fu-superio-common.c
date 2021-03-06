/*
 * Copyright (C) 2018 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include <sys/errno.h>
#include <string.h>
#include <unistd.h>

#include "fu-superio-common.h"

gboolean
fu_superio_outb (gint fd, guint16 port, guint8 data, GError **error)
{
	if (pwrite (fd, &data, 1, (goffset) port) != 1) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_FAILED,
			     "failed to write to port %04x: %s",
			     (guint) port,
			     strerror (errno));
		return FALSE;
	}
	return TRUE;
}

gboolean
fu_superio_inb (gint fd, guint16 port, guint8 *data, GError **error)
{
	if (pread (fd, data, 1, (goffset) port) != 1) {
		g_set_error (error,
			     G_IO_ERROR,
			     G_IO_ERROR_FAILED,
			     "failed to read from port %04x: %s",
			     (guint) port,
			     strerror (errno));
		return FALSE;
	}
	return TRUE;
}

const gchar *
fu_superio_ldn_to_text (guint8 ldn)
{
	if (ldn == SIO_LDN_FDC)
		return "Floppy Disk Controller";
	if (ldn == SIO_LDN_GPIO)
		return "General Purpose IO";
	if (ldn == SIO_LDN_PARALLEL_PORT)
		return "Parallel Port";
	if (ldn == SIO_LDN_UART1)
		return "Serial Port 1";
	if (ldn == SIO_LDN_UART2)
		return "Serial Port 2";
	if (ldn == SIO_LDN_UART3)
		return "Serial Port 3";
	if (ldn == SIO_LDN_UART4)
		return "Serial Port 4";
	if (ldn == SIO_LDN_SWUC)
		return "System Wake-Up Control";
	if (ldn == SIO_LDN_KBC_MOUSE)
		return "KBC/Mouse";
	if (ldn == SIO_LDN_KBC_KEYBOARD)
		return "KBC/Keyboard";
	if (ldn == SIO_LDN_CIR)
		return "Consumer IR";
	if (ldn == SIO_LDN_SMFI)
		return "Shared Memory/Flash";
	if (ldn == SIO_LDN_RTCT)
		return "RTC-like Timer";
	if (ldn == SIO_LDN_SSSP1)
		return "Serial Peripheral";
	if (ldn == SIO_LDN_PECI)
		return "Platform Environmental Control";
	if (ldn == SIO_LDN_PM1)
		return "Power Management 1";
	if (ldn == SIO_LDN_PM2)
		return "Power Management 2";
	if (ldn == SIO_LDN_PM3)
		return "Power Management 3";
	if (ldn == SIO_LDN_PM4)
		return "Power Management 4";
	if (ldn == SIO_LDN_PM5)
		return "Power Management 5";
	return NULL;
}
