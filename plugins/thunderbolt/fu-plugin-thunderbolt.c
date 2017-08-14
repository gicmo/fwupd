/* -*- mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*-
 *
 * Copyright (C) 2017 Christian J. Kellner <christian@kellner.me>
 *
 * Licensed under the GNU General Public License Version 2
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <libudev.h>

#include "fu-plugin.h"
#include "fu-plugin-vfuncs.h"

typedef struct udev_monitor udev_monitor;
G_DEFINE_AUTOPTR_CLEANUP_FUNC(udev_monitor, udev_monitor_unref);

typedef struct udev_device udev_device;
G_DEFINE_AUTOPTR_CLEANUP_FUNC(udev_device, udev_device_unref);


struct FuPluginData {
	struct udev  *udev;
	udev_monitor *monitor;
	int           monitor_fd;
	GSource      *monitor_source;
	guint         monitor_tag;
};

static gchar *
fu_plugin_thunderbolt_gen_id (struct udev_device *device)
{
	gchar *id;

	id = g_strdup_printf ("tbt-%s", udev_device_get_syspath (device));
	g_strdelimit (id, "/:.-", '_');

	return id;
}

static gboolean
fu_plugin_thunderbolt_udev_get_id (udev_device *device,
				   const char  *name,
				   guint       *out)
{
	const char *sysfs;
	guint64 id;

	sysfs = udev_device_get_sysattr_value (device, name);

	if (sysfs == NULL) {
		g_warning ("failed get id (%s) parse %s", name, sysfs);
		return FALSE;
	}

	id = g_ascii_strtoull (sysfs, NULL, 16);
	if (id == 0x0) {
		g_warning ("failed to parse %s", sysfs);
		return FALSE;
	} else if (id > G_MAXUINT) {
		g_warning ("vendor id overflows guint %s", sysfs);
		return FALSE;
	}

	*out = id;
	return TRUE;
}

static gboolean
fu_plugin_thunderbolt_is_host (udev_device *device)
{
	udev_device *parent; /* memory belongs to the child */
	const char *name;

	/* the (probably safe) assumption this code makes is
	 * that the thunderbolt device which is a direct child
	 * of the domain is the host controller device itself */
	parent = udev_device_get_parent (device);
	name = udev_device_get_sysname (parent);
	if (name == NULL)
		return FALSE;

	return g_str_has_prefix(name, "domain");
}

static void
fu_plugin_thunderbolt_add (FuPlugin *plugin, udev_device *device)
{
	FuDevice *dev_tmp;
	const gchar *name;
	const gchar *uuid;
	const gchar *vendor;
	const gchar *version;
	g_autofree gchar *id = NULL;
	g_autofree gchar *vendor_id = NULL;
	g_autofree gchar *device_id = NULL;
	g_autoptr(FuDevice) dev = NULL;
	gboolean is_host;
	gboolean ok;
	guint did, vid = 0x0;

	uuid = udev_device_get_sysattr_value (device, "unique_id");
	if (uuid == NULL) {
		/* most likely the domain itself, ignore */
		return;
	}

	g_debug ("adding udev device: %s @ %s",
		 uuid, udev_device_get_syspath (device));

	id = fu_plugin_thunderbolt_gen_id (device);
	dev_tmp = fu_plugin_cache_lookup (plugin, id);
	if (dev_tmp != NULL) {
		g_debug ("ignoring duplicate %s", id);
		return;
	}

	ok = fu_plugin_thunderbolt_udev_get_id (device, "vendor", &vid);
	if (!ok) {
		return;
	}

	ok = fu_plugin_thunderbolt_udev_get_id (device, "device", &did);
	if (!ok) {
		return;
	}

	name = udev_device_get_sysattr_value (device, "device_name");
	vendor = udev_device_get_sysattr_value (device, "vendor_name");
	version = udev_device_get_sysattr_value (device, "nvm_version");
	is_host = fu_plugin_thunderbolt_is_host (device);
	vendor_id = g_strdup_printf ("TBT:0x%04X", vid);
	device_id = g_strdup_printf ("TBT-%04x%04x", vid, did);

	dev = fu_device_new ();
	fu_device_set_id (dev, id);

	if (is_host) {
		g_autofree gchar *pretty_name = NULL;
		pretty_name = g_strdup_printf ("%s Thunderbolt Controller", name);
		fu_device_set_name (dev, pretty_name);
	} else {
		fu_device_set_name (dev, name);
	}

	fu_device_set_vendor (dev, vendor);
	fu_device_set_vendor_id (dev, vendor_id);
	fu_device_add_guid (dev, device_id);
	fu_device_set_version (dev, version);

	if (is_host)
		fu_device_add_flag (dev, FWUPD_DEVICE_FLAG_INTERNAL);

	fu_device_add_flag (dev, FWUPD_DEVICE_FLAG_ALLOW_ONLINE);
	fu_device_add_flag (dev, FWUPD_DEVICE_FLAG_ALLOW_OFFLINE);

	fu_plugin_cache_add (plugin, id, dev);
	fu_plugin_device_add_delay (plugin, dev);
}

static void
fu_plugin_thunderbolt_remove (FuPlugin *plugin, udev_device *device)
{
	FuDevice *dev;
	g_autofree gchar *id = NULL;

	id = fu_plugin_thunderbolt_gen_id (device);
	dev = fu_plugin_cache_lookup (plugin, id);
	if (dev == NULL)
		return;

	fu_plugin_cache_remove (plugin, id);
	fu_plugin_device_remove (plugin, dev);
}

static void
fu_plugin_thunderbolt_change (FuPlugin *plugin, udev_device *device)
{
	FuDevice *dev;
	const gchar *version;
	g_autofree gchar *id = NULL;

	id = fu_plugin_thunderbolt_gen_id (device);
	dev = fu_plugin_cache_lookup (plugin, id);
	if (dev == NULL) {
		g_warning ("got change event for unknown device, adding instead");
		fu_plugin_thunderbolt_add (plugin, device);
		return;
	}

	fu_plugin_device_remove (plugin, dev);
	version = udev_device_get_sysattr_value (device, "nvm_version");
	fu_device_set_version (dev, version);
}

static gboolean
udev_uevent_cb (GIOChannel   *source,
		GIOCondition  condition,
		gpointer      user_data)
{
	FuPlugin *plugin = (FuPlugin *) user_data;
	FuPluginData *data = fu_plugin_get_data (plugin);

	g_autoptr(udev_device) device = NULL;
	const char *action;

	device = udev_monitor_receive_device (data->monitor);

	if (device == NULL)
		return TRUE;

	action = udev_device_get_action (device);
	if (action == NULL)
		return TRUE;

	g_debug ("uevent for %s: %s", udev_device_get_syspath (device), action);

	if (g_str_equal (action, "add")) {
		fu_plugin_thunderbolt_add (plugin, device);
	} else if (g_str_equal (action, "remove")) {
		fu_plugin_thunderbolt_remove (plugin, device);
	} else if (g_str_equal (action, "change")) {
		fu_plugin_thunderbolt_change (plugin, device);
	}

	return TRUE;
}


/* virtual functions */

void
fu_plugin_init (FuPlugin *plugin)
{
	FuPluginData *data = fu_plugin_alloc_data (plugin, sizeof (FuPluginData));
	data->udev = udev_new ();
}

void
fu_plugin_destroy (FuPlugin *plugin)
{
	FuPluginData *data = fu_plugin_get_data (plugin);
	if (data->monitor) {
		udev_monitor_unref (data->monitor);
		g_source_destroy (data->monitor_source);
		g_source_unref (data->monitor_source);
	}

	udev_unref (data->udev);
}

gboolean
fu_plugin_coldplug (FuPlugin *plugin, GError **error)
{
	FuPluginData *data = fu_plugin_get_data (plugin);
	g_autoptr(udev_monitor) monitor = NULL;
	g_autoptr(GIOChannel) channel = NULL;
	struct udev_enumerate *enumerate;
	struct udev_list_entry *l, *devices;
	GSource *watch;
	guint tag;
	int fd;
	int r;

	monitor = udev_monitor_new_from_netlink (data->udev, "udev");
	if (monitor == NULL) {
		g_set_error_literal (error,
				     FWUPD_ERROR,
				     FWUPD_ERROR_INTERNAL,
				     "udev: could not create monitor");
		return FALSE;
	}

	udev_monitor_set_receive_buffer_size (monitor, 128*1024*1024);

	r = udev_monitor_filter_add_match_subsystem_devtype (monitor, "thunderbolt", NULL);
	if (r < 0) {
		g_set_error_literal (error,
				     FWUPD_ERROR,
				     FWUPD_ERROR_INTERNAL,
				     "udev: could not add match for 'thunderbolt' to monitor");
		return FALSE;
	}

	r = udev_monitor_enable_receiving (monitor);
	if (r < 0) {
		g_set_error_literal (error,
				     FWUPD_ERROR,
				     FWUPD_ERROR_INTERNAL,
				     "udev: could not enable monitoring");
		return FALSE;
	}

	fd = udev_monitor_get_fd (monitor);

	if (fd < 0) {
		g_set_error_literal (error,
				     FWUPD_ERROR,
				     FWUPD_ERROR_INTERNAL,
				     "udev: could not obtain fd for monitoring");
		return FALSE;
	}

	channel = g_io_channel_unix_new (fd);
	watch = g_io_create_watch (channel, G_IO_IN);

	g_source_set_callback (watch, (GSourceFunc) udev_uevent_cb, plugin, NULL);
	tag = g_source_attach (watch, g_main_context_get_thread_default ());

	data->monitor = udev_monitor_ref (monitor);
	data->monitor_fd = fd;
	data->monitor_tag = tag;
	data->monitor_source = watch;
	/* channel will be auto-unref'ed on func exit */

	enumerate = udev_enumerate_new (data->udev);
	udev_enumerate_add_match_subsystem (enumerate, "thunderbolt");
	udev_enumerate_scan_devices (enumerate);
	devices = udev_enumerate_get_list_entry (enumerate);

	for (l = devices; l; l = udev_list_entry_get_next (l)) {
		g_autoptr(udev_device) udevice = NULL;

		udevice = udev_device_new_from_syspath (udev_enumerate_get_udev (enumerate),
							udev_list_entry_get_name (l));

		if (udevice == NULL) {
			continue;
		}

		fu_plugin_thunderbolt_add (plugin, udevice);
	}

	return TRUE;
}
