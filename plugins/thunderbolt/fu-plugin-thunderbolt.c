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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <gio/gio.h>
#include <glib.h>
#include <gudev/gudev.h>

#include "fu-plugin.h"
#include "fu-plugin-vfuncs.h"

G_DEFINE_AUTOPTR_CLEANUP_FUNC(GUdevDevice, g_object_unref)

typedef void (*UEventNotify) (FuPlugin	  *plugin,
			      GUdevDevice *udevice,
			      const gchar *action,
			      gpointer     user_data);

struct FuPluginData {
	GUdevClient     *udev;

	/* in the case we are updating */
	UEventNotify     update_notify;
	gpointer         update_data;
};


static gchar *
fu_plugin_thunderbolt_gen_id_from_syspath (const gchar *syspath)
{
	gchar *id;
	id = g_strdup_printf ("tbt-%s", syspath);
	g_strdelimit (id, "/:.-", '_');
	return id;
}


static gchar *
fu_plugin_thunderbolt_gen_id (GUdevDevice *device)
{
	const gchar *syspath = g_udev_device_get_sysfs_path (device);
	return fu_plugin_thunderbolt_gen_id_from_syspath (syspath);
}

static guint64
udev_device_get_sysattr_guint64 (GUdevDevice *device,
				 const gchar *name,
				 GError **error)
{
	const gchar *sysfs;
	guint64 val;

	sysfs = g_udev_device_get_sysfs_attr (device, name);
	if (sysfs == NULL) {
		g_set_error (error,
			     FWUPD_ERROR,
			     FWUPD_ERROR_INTERNAL,
			     "failed get id %s for %s", name, sysfs);
		return 0x0;
	}

	val = g_ascii_strtoull (sysfs, NULL, 16);
	if (val == 0x0) {
		g_set_error (error,
			     FWUPD_ERROR,
			     FWUPD_ERROR_INTERNAL,
			     "failed to parse %s", sysfs);
		return 0x0;
	}

	return val;
}

static guint16
fu_plugin_thunderbolt_udev_get_id (GUdevDevice *device,
				   const gchar *name,
				   GError **error)
{

	guint64 id;

	id = udev_device_get_sysattr_guint64 (device, name, error);
	if (id == 0x0)
		return id;

	if (id > G_MAXUINT16) {
		g_set_error (error,
			     FWUPD_ERROR,
			     FWUPD_ERROR_INTERNAL,
			     "vendor id overflows");
		return 0x0;
	}

	return (guint16) id;
}

static gboolean
fu_plugin_thunderbolt_is_host (GUdevDevice *device)
{
	g_autoptr(GUdevDevice) parent = NULL;
	const gchar *name;

	/* the (probably safe) assumption this code makes is
	 * that the thunderbolt device which is a direct child
	 * of the domain is the host controller device itself */
	parent = g_udev_device_get_parent (device);
	name = g_udev_device_get_name (parent);
	if (name == NULL)
		return FALSE;

	return g_str_has_prefix (name, "domain");
}

static void
fu_plugin_thunderbolt_add (FuPlugin *plugin, GUdevDevice *device)
{
	FuDevice *dev_tmp;
	const gchar *name;
	const gchar *uuid;
	const gchar *vendor;
	const gchar *version;
	const gchar *devpath;
	gboolean is_host;
	guint16 did;
	guint16 vid;
	g_autofree gchar *id = NULL;
	g_autofree gchar *vendor_id = NULL;
	g_autofree gchar *device_id = NULL;
	g_autoptr(FuDevice) dev = NULL;
	g_autoptr(GError) error = NULL;

	uuid = g_udev_device_get_sysfs_attr (device, "unique_id");
	if (uuid == NULL) {
		/* most likely the domain itself, ignore */
		/* TODO: handle devices in safe-mode */
		return;
	}

	devpath = g_udev_device_get_sysfs_path (device);

	g_debug ("adding udev device: %s at %s", uuid, devpath);

	id = fu_plugin_thunderbolt_gen_id (device);
	dev_tmp = fu_plugin_cache_lookup (plugin, id);
	if (dev_tmp != NULL) {
		g_debug ("ignoring duplicate %s", id);
		return;
	}

	vid = fu_plugin_thunderbolt_udev_get_id (device, "vendor", &error);
	if (vid == 0x0) {
		g_warning ("failed to get Vendor ID: %s", error->message);
		return;
	}
	did = fu_plugin_thunderbolt_udev_get_id (device, "device", &error);
	if (did == 0x0) {
		g_warning ("failed to get Device ID: %s", error->message);
		return;
	}

	is_host = fu_plugin_thunderbolt_is_host (device);
	vendor_id = g_strdup_printf ("TBT:0x%04X", (guint) vid);
	device_id = g_strdup_printf ("TBT-%04x%04x", (guint) vid, (guint) did);

	dev = fu_device_new ();
	fu_device_set_id (dev, uuid);

	fu_device_set_metadata(dev, "sysfs-path", devpath);
	name = g_udev_device_get_sysfs_attr (device, "device_name");
	if (name != NULL) {
		if (is_host) {
			g_autofree gchar *pretty_name = NULL;
			pretty_name = g_strdup_printf ("%s Thunderbolt Controller", name);
			fu_device_set_name (dev, pretty_name);
		} else {
			fu_device_set_name (dev, name);
		}
	}

	vendor = g_udev_device_get_sysfs_attr (device, "vendor_name");
	if (vendor != NULL)
		fu_device_set_vendor (dev, vendor);
	fu_device_set_vendor_id (dev, vendor_id);
	fu_device_add_guid (dev, device_id);
	version = g_udev_device_get_sysfs_attr (device, "nvm_version");
	if (version != NULL)
		fu_device_set_version (dev, version);
	fu_device_add_flag (dev, FWUPD_DEVICE_FLAG_ALLOW_ONLINE);
	fu_device_add_flag (dev, FWUPD_DEVICE_FLAG_ALLOW_OFFLINE);
	if (is_host)
		fu_device_add_flag (dev, FWUPD_DEVICE_FLAG_INTERNAL);

	fu_plugin_cache_add (plugin, id, dev);
	fu_plugin_device_add_delay (plugin, dev);
}

static void
fu_plugin_thunderbolt_remove (FuPlugin *plugin, GUdevDevice *device)
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
fu_plugin_thunderbolt_change (FuPlugin *plugin, GUdevDevice *device)
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
	version = g_udev_device_get_sysfs_attr (device, "nvm_version");
	fu_device_set_version (dev, version);
}

static gboolean
udev_uevent_cb (GUdevClient *udev,
		const gchar *action,
		GUdevDevice *device,
		gpointer     user_data)
{
	FuPlugin *plugin = (FuPlugin *) user_data;
	FuPluginData *data = fu_plugin_get_data (plugin);

	if (action == NULL)
		return TRUE;

	g_debug ("uevent for %s: %s", g_udev_device_get_sysfs_path (device), action);

	if (data->update_notify != NULL) {
		g_debug ("using update notify handler for uevent");

		data->update_notify (plugin, device, action, data->update_data);
		return TRUE;
	}

	if (g_str_equal (action, "add")) {
		fu_plugin_thunderbolt_add (plugin, device);
	} else if (g_str_equal (action, "remove")) {
		fu_plugin_thunderbolt_remove (plugin, device);
	} else if (g_str_equal (action, "change")) {
		fu_plugin_thunderbolt_change (plugin, device);
	}

	return TRUE;
}

static gboolean
fu_plugin_thunderbolt_validate_firmware (GBytes *blob_fw, GError **error)
{
	/* FIXME: need to implement */
	return TRUE;
}

static GFile *
fu_plugin_thunderbolt_find_nvmem (GUdevDevice  *udevice,
				  GError      **error)
{
	const gchar *devpath;
	const gchar *name;
	g_autoptr(GDir) d;

	devpath = g_udev_device_get_sysfs_path (udevice);

	d = g_dir_open (devpath, 0, error);
	if (d == NULL)
		return NULL;

	while ((name = g_dir_read_name (d)) != NULL) {
		if (g_str_has_prefix (name, "nvm_non_active")) {
			g_autoptr(GFile) parent = g_file_new_for_path (devpath);
			g_autoptr(GFile) nvm_dir =g_file_get_child (parent, name);
			return g_file_get_child (nvm_dir, "nvmem");
		}
	}

	return NULL;
}

static gboolean
fu_plugin_thunderbolt_trigger_update (GUdevDevice  *udevice,
				      GError      **error)
{

	const gchar *devpath;
	int fd;
	ssize_t n;
	g_autofree gchar *auth_path = NULL;

	devpath = g_udev_device_get_sysfs_path (udevice);
	auth_path = g_build_filename (devpath, "nvm_authenticate", NULL);

	fd = open (auth_path, O_WRONLY | O_CLOEXEC);
	if (fd < 0) {
		g_set_error (error, G_IO_ERROR,
			     g_io_error_from_errno (errno),
			     "could not open 'nvm_authenticate': %s",
			     g_strerror (errno));
		return FALSE;
	}

	do {
		n = write (fd, "1", 1);
		if (n < 1 && errno != EINTR) {
			g_set_error (error, G_IO_ERROR,
				     g_io_error_from_errno (errno),
				     "could write to 'nvm_authenticate': %s",
				     g_strerror (errno));
			(void) close (fd);
			return FALSE;
		}
	} while (n < 1);

	(void) close (fd);
	return TRUE;
}

static gboolean
fu_plugin_thunderbolt_write_firmware (GUdevDevice  *udevice,
				      GBytes       *blob_fw,
				      GError      **error)
{
	gsize fw_size;
	gsize nwritten;
	gssize n;
	g_autoptr(GFile) nvmem = NULL;
	g_autoptr(GOutputStream) os = NULL;

	/* TODO: error propagation */
	nvmem = fu_plugin_thunderbolt_find_nvmem (udevice, error);
	if (nvmem == NULL)
		return FALSE;

	os = (GOutputStream *) g_file_append_to (nvmem,
						 G_FILE_CREATE_NONE,
						 NULL,
						 error);

	if (os == NULL)
		return FALSE;

	nwritten = 0;
	fw_size = g_bytes_get_size (blob_fw);

	do {
		g_autoptr(GBytes) fw_data = NULL;

		fw_data = g_bytes_new_from_bytes (blob_fw,
						  nwritten,
						  fw_size - nwritten);

		n = g_output_stream_write_bytes (os,
						 fw_data,
						 NULL,
						 error);
		if (n < 0) {
			return FALSE;
		}

		nwritten += n;

	} while (nwritten < fw_size);

	if (nwritten != fw_size) {
		g_set_error_literal (error,
				     FWUPD_ERROR,
				     FWUPD_ERROR_WRITE,
				     "Could not write all data to nvmem");
		return FALSE;
	}

	return g_output_stream_close (os, NULL, error);
}

typedef struct UpdateData {

	gboolean   have_device;
	GMainLoop *mainloop;
	const gchar *target_uuid;
	guint      timeout_id;

	GHashTable *changes;
} UpdateData;

static gboolean
on_wait_for_device_timeout (gpointer user_data)
{
	GMainLoop *mainloop = (GMainLoop *) user_data;
	g_main_loop_quit (mainloop);
	return FALSE;
}

static void
on_wait_for_device_added (FuPlugin    *plugin,
			  GUdevDevice *device,
			  UpdateData  *up_data)
{
	FuDevice  *dev;
	const gchar *uuid;
	const gchar *path;
	const gchar *version;
	g_autofree gchar *id = NULL;

	uuid = g_udev_device_get_sysfs_attr (device, "unique_id");
	if (uuid == NULL)
		return;

	dev = g_hash_table_lookup (up_data->changes, uuid);
	if (dev == NULL) {
		/* a previously unknown device, add it via
		 * the normal way */
		fu_plugin_thunderbolt_add (plugin, device);
		return;
	}

	/* maybe the device path has changed, lets make sure
	 * it is correct */
	path = g_udev_device_get_sysfs_path (device);
	fu_device_set_metadata (dev, "sysfs-path", path);

	/* make sure the version is correct, might have changed
	 * after update. */
	version = g_udev_device_get_sysfs_attr (device, "nvm_version");
	fu_device_set_version (dev, version);

	id = fu_plugin_thunderbolt_gen_id (device);
	fu_plugin_cache_add (plugin, id, dev);

	g_hash_table_remove (up_data->changes, uuid);

	/* check if this device is the target*/
	if (g_str_equal (uuid, up_data->target_uuid)) {
		up_data->have_device = TRUE;
		g_debug ("target (%s) re-appeared", uuid);
		g_main_loop_quit (up_data->mainloop);
	}
}

static void
on_wait_for_device_removed (FuPlugin    *plugin,
			    GUdevDevice *device,
			    UpdateData *up_data)
{
	g_autofree gchar *id = NULL;
	FuDevice  *dev;
	const gchar *uuid;

	id = fu_plugin_thunderbolt_gen_id (device);
	dev = fu_plugin_cache_lookup (plugin, id);

	if (dev == NULL)
		return;

	fu_plugin_cache_remove (plugin, id);
	uuid = fu_device_get_id (dev);
	g_hash_table_insert (up_data->changes,
			     (gpointer) uuid,
			     g_object_ref (dev));

	/* check if this device is the target*/
	if (g_str_equal (uuid, up_data->target_uuid)) {
		up_data->have_device = FALSE;
		g_debug ("target (%s) disappeared",
			 uuid);
	}
}

static void
on_wait_for_device_notify (FuPlugin    *plugin,
			   GUdevDevice *device,
			   const char  *action,
			   gpointer    user_data)
{
	UpdateData *up_data = (UpdateData *) user_data;

	if (g_str_equal (action, "add")) {
		on_wait_for_device_added (plugin, device, up_data);
	} else if (g_str_equal (action, "remove")) {
		on_wait_for_device_removed (plugin, device, up_data);
	} else if (g_str_equal (action, "change")) {
		fu_plugin_thunderbolt_change (plugin, device);
	}
}

static void
remove_leftover_devices (gpointer key,
			 gpointer value,
			 gpointer user_data)
{
	FuPlugin  *plugin = (FuPlugin *) user_data;
	FuDevice *dev = (FuDevice *) value;
	const gchar *syspath = fu_device_get_metadata (dev, "sysfs-path");
	g_autofree gchar *id = NULL;

	id = fu_plugin_thunderbolt_gen_id_from_syspath (syspath);

	fu_plugin_cache_remove (plugin, id);
	fu_plugin_device_remove (plugin, dev);
}

static gboolean
fu_plugin_thunderbolt_wait_for_device (FuPlugin  *plugin,
				       FuDevice  *dev,
				       guint      timeout_ms,
				       GError   **error)
{
	FuPluginData *data = fu_plugin_get_data (plugin);
	UpdateData    up_data = { TRUE, };
	g_autoptr(GMainLoop) mainloop = NULL;
	g_autoptr(GHashTable) changes = NULL;

	up_data.mainloop = mainloop = g_main_loop_new (NULL, FALSE);
	up_data.target_uuid = fu_device_get_id (dev);

	/* this will limit the maximum amount of time we wait for
	 * the device (i.e. 'dev') to re-appear. */
	up_data.timeout_id = g_timeout_add (timeout_ms,
					    on_wait_for_device_timeout,
					    mainloop);

	/* this will capture the device added, removed, changed
	 * signals while we are updating.  */
	data->update_data = &up_data;
	data->update_notify = on_wait_for_device_notify;

	changes = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, g_object_unref);
	up_data.changes = changes;

	/* now we wait ... */
	g_main_loop_run (mainloop);

	/* restore original udev change handler */
	data->update_data = NULL;
	data->update_notify = NULL;

	if (!up_data.have_device) {
		g_set_error_literal (error,
				     FWUPD_ERROR,
				     FWUPD_ERROR_INTERNAL,
				     "timed out while waiting for device");
	}

	g_hash_table_foreach (changes, remove_leftover_devices, plugin);

	return up_data.have_device;
}

/* virtual functions */

void
fu_plugin_init (FuPlugin *plugin)
{
	FuPluginData *data = fu_plugin_alloc_data (plugin, sizeof (FuPluginData));
	const gchar *subsystems[] = { "thunderbolt", NULL };

	data->udev = g_udev_client_new (subsystems);
	g_signal_connect (data->udev, "uevent",
			  G_CALLBACK (udev_uevent_cb), plugin);
}

void
fu_plugin_destroy (FuPlugin *plugin)
{
	FuPluginData *data = fu_plugin_get_data (plugin);
	g_object_unref (data->udev);
}

gboolean
fu_plugin_coldplug (FuPlugin *plugin, GError **error)
{
	FuPluginData *data = fu_plugin_get_data (plugin);
	GList *devices, *l;

	devices = g_udev_client_query_by_subsystem (data->udev, "thunderbolt");
	for (l = devices; l != NULL; l = l->next) {
		GUdevDevice *device = l->data;
		fu_plugin_thunderbolt_add (plugin, device);
	}

	g_list_foreach (devices, (GFunc) g_object_unref, NULL);
	g_list_free (devices);

	return TRUE;
}

#define FU_PLUGIN_THUNDERBOLT_UPDATE_TIMEOUT_MS 60 * 1000

gboolean
fu_plugin_update_online (FuPlugin *plugin,
			 FuDevice *dev,
			 GBytes *blob_fw,
			 FwupdInstallFlags flags,
			 GError **error)
{
	FuPluginData *data = fu_plugin_get_data (plugin);
	const gchar *devpath;
	gboolean ret;
	guint64 status;
	g_autoptr(GUdevDevice) udevice = NULL;
	g_autoptr(GError) error_local = NULL;

	ret = fu_plugin_thunderbolt_validate_firmware (blob_fw, &error_local);
	if (!ret) {
		g_set_error (error,
			     FWUPD_ERROR,
			     FWUPD_ERROR_NOT_FOUND,
			     "could not validate firmware: %s",
			     error_local->message);
		return FALSE;
	}

	devpath = fu_device_get_metadata (dev, "sysfs-path");
	g_return_val_if_fail (devpath, FALSE);

	udevice = g_udev_client_query_by_sysfs_path (data->udev, devpath);
	if (udevice == NULL) {
		g_set_error (error,
			     FWUPD_ERROR,
			     FWUPD_ERROR_NOT_FOUND,
			     "could not find thunderbolt device at %s",
			     devpath);
		return FALSE;
	}

	fu_plugin_set_status (plugin, FWUPD_STATUS_DEVICE_WRITE);
	ret = fu_plugin_thunderbolt_write_firmware (udevice, blob_fw, &error_local);
	if (!ret) {
		g_set_error (error,
			     FWUPD_ERROR,
			     FWUPD_ERROR_WRITE,
			     "could not write firmware to thunderbolt device at %s: %s",
			     devpath, error_local->message);
		return FALSE;
	}

	ret = fu_plugin_thunderbolt_trigger_update (udevice, &error_local);
	if (!ret) {
		g_set_error (error,
			     FWUPD_ERROR,
			     FWUPD_ERROR_NOT_SUPPORTED,
			     "Could not start thunderbolt device upgrade: %s",
			     error_local->message);
		return FALSE;
	}

	fu_plugin_set_status (plugin, FWUPD_STATUS_DEVICE_RESTART);

	/* the device will disappear and we need to wait until it reappears,
	 * and then check if we find an error */
	ret = fu_plugin_thunderbolt_wait_for_device (plugin,
						    dev,
						    FU_PLUGIN_THUNDERBOLT_UPDATE_TIMEOUT_MS,
						    &error_local);
	if (!ret) {
		g_set_error (error,
			     FWUPD_ERROR,
			     FWUPD_ERROR_NOT_FOUND,
			     "could not detect device after update: %s",
			     error_local->message);
		return FALSE;
	}

	/* now check if the update actually worked */
	status = udev_device_get_sysattr_guint64 (udevice, "nvm_authenticate", &error_local);

	/* anything else then 0x0 means we got an error */
	ret = status == 0x0;
	if (ret == FALSE)
		g_set_error (error,
			     FWUPD_ERROR,
			     FWUPD_ERROR_INTERNAL,
			     "update failed (status %" G_GINT64_MODIFIER "x)", status);

	return ret;
}
