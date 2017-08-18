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

#define _GNU_SOURCE 1
#include <errno.h>
#include <fwupd.h>
#include <glib.h>
#include <glib/gprintf.h>
#include <glib/gstdio.h>

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <umockdev.h>

#include <locale.h>

#include "fu-plugin-private.h"

typedef struct ThunderboltTest {
	UMockdevTestbed *bed;
	FuPlugin *plugin;
} ThunderboltTest;

static void
test_set_up (ThunderboltTest *tt, gconstpointer user_data)
{
	gboolean ok;
	g_autoptr(GError) error = NULL;

	tt->bed = umockdev_testbed_new ();
	g_assert_nonnull (tt->bed);

	g_debug ("mock sysfs at %s", umockdev_testbed_get_sys_dir (tt->bed));

	tt->plugin = fu_plugin_new ();
	g_assert_nonnull (tt->plugin);

	ok = fu_plugin_open (tt->plugin, PLUGINBUILDDIR "/libfu_plugin_thunderbolt.so", &error);

	g_assert_no_error (error);
	g_assert_true (ok);

	ok = fu_plugin_runner_startup (tt->plugin, &error);
	g_assert_no_error (error);
	g_assert_true (ok);

}

static void
test_tear_down (ThunderboltTest *tt, gconstpointer user_data)
{
	g_object_unref (tt->plugin);
	g_object_unref (tt->bed);
}


static char *
udev_mock_add_domain (UMockdevTestbed *bed, int id)
{
	char name[256] = { 0, };
	char *path;

	g_snprintf (name, sizeof (name), "domain%d", id);

	path = umockdev_testbed_add_device (bed, "thunderbolt", name,
					    NULL,
					    "security", "secure",
					    NULL,
					    "DEVTYPE",
					    "thunderbolt_domain",
					    NULL);

	g_assert_nonnull (path);
	return path;
}

static char *
udev_mock_add_device (UMockdevTestbed *bed,
		      const char *parent,
		      const char *id,
		      const char *uuid,
		      const char *device_name,
		      const char *device_id,
		      int         nvm_auth,
		      const char *nvm_version)
{
	g_autofree char *generated = NULL;
	char authorized[16] = { 0, };
	char *path;

	if (uuid == NULL) {
		generated = g_uuid_string_random ();
		uuid = generated;
	}

	g_snprintf (authorized, sizeof (authorized), "%d", nvm_auth);

	path = umockdev_testbed_add_device (bed, "thunderbolt", id,
					    parent,
					    "device_name", device_name,
					    "device", device_id,
					    "vendor", "042",
					    "vendor_name", "GNOME.org",
					    "authorized", "0",
					    "nvm_authenticate", authorized,
					    "nvm_version", nvm_version,
					    "unique_id", uuid,
					    NULL,
					    "DEVTYPE",
					    "thunderbolt_device",
					    NULL);

	g_assert_nonnull (path);
	return path;
}

static char *
udev_mock_add_nvme_nonactive (UMockdevTestbed *bed,
			      const char      *parent,
			      int              id)
{
	char name[256] = { 0, };
	char *path;

	g_snprintf (name, sizeof (name), "nvm_non_active%d", id);

	path = umockdev_testbed_add_device (bed, "nvmem", name,
					    parent,
					    "nvmem", "",
					    NULL,
					    NULL);

	g_assert_nonnull (path);
	return path;
}

typedef struct MockDevice MockDevice;
typedef struct MockDeviceTree {

	MockDevice *root;

	UMockdevTestbed *bed;
	GMainLoop  *loop;
	gboolean    complete;

	int device_count;
	int nvm_count;

} MockDeviceTree;


struct MockDevice {

	/* we fill this in */
	const char *name; /* sysfs: device_name */
	const char *id;   /* sysfs: device */

	int         nvm_authenticate;
	const char *nvm_version;

	int delay_ms;
	struct MockDevice *children;

	/* optionally filled out */
	char *uuid;

	/* filled out when attached */
	const char *domain;

	char *nvm_device;
	char *path;

	int sysfs_id;
	int sysfs_nvm_id;

	FuDevice *fu_device;

	/* only valid during tree building */
	MockDeviceTree *tree;
};

static MockDevice *
udev_mock_tree_find_device (MockDevice *root, const char *uuid)
{
	MockDevice *iter;

	if (root->uuid && g_str_equal (root->uuid, uuid))
		return root;

	for (iter = root->children; iter && iter->name; iter++) {
		MockDevice *res = udev_mock_tree_find_device (iter, uuid);
		if (res != NULL)
			return res;
	}

	return NULL;

}

static gboolean
udev_mock_tree_has_fu_devices (MockDevice *root)
{
	MockDevice *iter;

	if (root->fu_device == NULL)
		return FALSE;

	for (iter = root->children; iter && iter->name; iter++) {
		gboolean complete = udev_mock_tree_has_fu_devices (iter);
		if (!complete)
			return FALSE;
	}

	return TRUE;
}

static void
udev_mock_tree_device_added_cb (FuPlugin *plugin, FuDevice *device, gpointer user_data)
{
	MockDeviceTree *tree = (MockDeviceTree *) user_data;
	MockDevice *root = tree->root;
	const char *uuid = fu_device_get_id (device);
	MockDevice *target;

	target = udev_mock_tree_find_device (root, uuid);

	if (target == NULL) {
		g_warning ("Got device that could not be matched: %s", uuid);
		return;
	}

	target->fu_device = g_object_ref (device);

	if ((tree->complete = udev_mock_tree_has_fu_devices (root))) {
		g_main_loop_quit (tree->loop);
	}
}

static const char *
udev_mock_tree_parent_rec (MockDevice *parent, MockDevice *dev)
{
	MockDevice *iter;

	for (iter = parent->children; iter && iter->name; iter++) {
		const char *path;
		if (iter == dev)
			return parent->path;
		else if ((path = udev_mock_tree_parent_rec (iter, dev)) != NULL)
			return path;
	}

	return NULL;
}

static const char *
udev_mock_tree_parent (MockDeviceTree *tree, MockDevice *dev)
{
	if (tree->root == dev)
		return tree->root->domain;

	return udev_mock_tree_parent_rec (tree->root, dev);
}

static gboolean
udev_mock_tree_device_add_cb (gpointer user_data)
{
	MockDevice *dev = (MockDevice *) user_data;
	MockDeviceTree *tree = dev->tree;
	const char *parent = udev_mock_tree_parent (tree, dev);
	MockDevice *iter;
	char authenticate[16] = { 0, };
	char idstr[16] = { 0, };

	if (dev->uuid == NULL) {
		dev->uuid = g_uuid_string_random ();
	}

	g_snprintf (authenticate, sizeof (authenticate), "%d", dev->nvm_authenticate);

	if (dev->sysfs_id == 0)
		dev->sysfs_id = (tree->device_count)++;

	g_snprintf (idstr, sizeof (idstr), "0-%d", dev->sysfs_id);

	dev->path = umockdev_testbed_add_device (tree->bed, "thunderbolt", idstr,
						 parent,
						 "device_name", dev->name,
						 "device", dev->id,
						 "vendor", "042",
						 "vendor_name", "GNOME.org",
						 "authorized", "0",
						 "nvm_authenticate", authenticate,
						 "nvm_version", dev->nvm_version,
						 "unique_id", dev->uuid,
						 NULL,
						 "DEVTYPE",
						 "thunderbolt_device",
						 NULL);
	if (dev->sysfs_nvm_id == 0)
		dev->sysfs_nvm_id = (tree->nvm_count)++;

	dev->nvm_device = udev_mock_add_nvme_nonactive (tree->bed, dev->path,dev->sysfs_nvm_id);

	g_assert_nonnull (dev->path);
	g_assert_nonnull (dev->nvm_device);

	for (iter = dev->children; iter && iter->name; iter++) {
		iter->tree = tree;
		iter->domain = dev->domain;
		g_timeout_add (iter->delay_ms, udev_mock_tree_device_add_cb, iter);
	}

	return FALSE;
}


static gboolean
udev_mock_add_tree (UMockdevTestbed *bed,
		    FuPlugin        *plugin,
		    MockDevice      *root,
		    const char      *domain)
{
	g_autoptr(GMainLoop) mainloop = g_main_loop_new (NULL, FALSE);
	MockDeviceTree tree = {
		.bed = bed,
		.root = root,
		.loop = mainloop,
	};

	root->domain = domain;
	root->tree = &tree;
	g_timeout_add (root->delay_ms, udev_mock_tree_device_add_cb, root);

	g_signal_connect (plugin, "device-added",
			  G_CALLBACK (udev_mock_tree_device_added_cb),
			  &tree);

	g_main_loop_run (mainloop);

	return tree.complete;

}

static void
udev_mock_remove_tree (UMockdevTestbed *bed, MockDevice *dev)
{
	MockDevice *iter;

	for (iter = dev->children; iter && iter->name; iter++) {
		udev_mock_remove_tree (bed, iter);
	}

	umockdev_testbed_uevent (bed, dev->nvm_device, "remove");
	umockdev_testbed_remove_device (bed, dev->nvm_device);

	umockdev_testbed_uevent (bed, dev->path, "remove");
	umockdev_testbed_remove_device (bed, dev->path);

	g_free (dev->path);
	g_free (dev->nvm_device);

	dev->path = NULL;
	dev->nvm_device = NULL;
}

static void
udev_mock_dump_tree (MockDevice *root, int level)
{
	MockDevice *iter;

	g_debug ("%*s * %s [%s] at %s", level, " ", root->name, root->uuid, root->path);
	g_debug ("%*s   nvmem at %s", level, " ", root->nvm_device);

	for (iter = root->children; iter && iter->uuid; iter++) {
		udev_mock_dump_tree (iter, level + 2);
	}
}

typedef struct UpdateContext {
	GFileMonitor *monitor;

	guint result;
	guint timeout;
	MockDevice *device;
	UMockdevTestbed *bed;
	FuPlugin *plugin;

	MockDeviceTree tree;
} UpdateContext;


static gboolean
reattach_tree (gpointer user_data)
{
	UpdateContext *ctx = (UpdateContext *) user_data;

	ctx->tree.bed = ctx->bed;
	ctx->tree.root = ctx->device;

	g_debug ("Mock update done, reattaching tree...");

	ctx->device->tree = &ctx->tree;
	g_timeout_add (ctx->device->delay_ms, udev_mock_tree_device_add_cb, ctx->device);

	return FALSE;
}

static void
udev_file_changed_cb (GFileMonitor     *monitor,
		      GFile            *file,
		      GFile            *other_file,
		      GFileMonitorEvent event_type,
		      gpointer          user_data)
{
	UpdateContext *ctx = (UpdateContext *) user_data;
	gboolean ok;
	gsize len;
	g_autofree char *data = NULL;
	g_autoptr(GError) error = NULL;

	g_debug ("Got update trigger");
	ok = g_file_monitor_cancel (monitor);
	g_assert_true (ok);
	g_object_unref (ctx->monitor);
	ctx->monitor = NULL;

	ok = g_file_load_contents (file, NULL, &data, &len, NULL, &error);
	g_assert_no_error (error);
	g_assert_true (ok);

	if (!g_str_has_prefix (data, "1"))
		return;

	g_debug ("Removing tree below and including: %s", ctx->device->path);
	udev_mock_remove_tree (ctx->bed, ctx->device);

	g_debug ("Simulating update and scheduling tree reattachment in %3.2f seconds", ctx->timeout / 1000.0);
	g_timeout_add (ctx->timeout, reattach_tree, ctx);
}

static void
udev_mock_prepare_for_update (FuPlugin *plugin, UMockdevTestbed *bed, MockDevice *device, guint timeout_ms, UpdateContext *ctx)
{
	g_autoptr(GFile) dir = NULL;
	g_autoptr(GFile) f = NULL;
	g_autoptr(GError) error = NULL;
	GFileMonitor *monitor;

	dir = g_file_new_for_path (device->path);
	f = g_file_get_child (dir, "nvm_authenticate");

	monitor = g_file_monitor_file (f, G_FILE_MONITOR_NONE, NULL, &error);
	g_assert_no_error (error);
	g_assert_nonnull (monitor);

	ctx->plugin = plugin;
	ctx->device = device;
	ctx->bed = bed;
	ctx->timeout = timeout_ms;
	ctx->monitor = monitor;

	g_signal_connect (monitor, "changed",
			  G_CALLBACK (udev_file_changed_cb), ctx);
}


static MockDevice root_one = {

	.name = "Laptop",
	.id = "0x23",

	.nvm_authenticate = 0,
	.nvm_version = "20.0",

	.children = (MockDevice[]) {
		{
			.name = "Thunderbolt Cable",
			.id = "0x24",

			.nvm_authenticate = 0,
			.nvm_version = "20.0",

			.children = (MockDevice[]) {
				{
					.name = "Thunderbolt Dock",
					.id = "0x25",

					.nvm_authenticate = 0,
					.nvm_version = "10.0",
				},
				{ NULL, }

			},
		}, {
			.name = "Thunderbolt Cable",
			.id = "0x24",

			.nvm_authenticate = 0,
			.nvm_version = "23.0",

			.children = (MockDevice[]) {
				{
					.name = "Thunderbolt SSD",
					.id = "0x26",

					.nvm_authenticate = 0,
					.nvm_version = "5.0",
				},
				{ NULL, }
			},
		},
		{ NULL, }
	},

};


static void
_plugin_device_added_cb (FuPlugin *plugin, FuDevice *device, gpointer user_data)
{
	FuDevice **dev = (FuDevice **) user_data;
	g_set_object (dev, device);
}

static gboolean
on_timeout (gpointer user_data)
{
	GMainLoop *mainloop = (GMainLoop *) user_data;
	g_main_loop_quit (mainloop);
	return FALSE;
}

static void
test_basic (ThunderboltTest *tt, gconstpointer user_data)
{
	FuPlugin *plugin = tt->plugin;
	gboolean ok;
	g_autoptr(GError) error = NULL;
	g_autoptr(FuDevice) device = NULL;
	g_autofree char *domain_path = NULL;
	g_autofree char *host_path = NULL;
	g_autofree char *host_nvm_path = NULL;
	g_autoptr(GMainLoop) mainloop = NULL;

	ok = fu_plugin_runner_coldplug (plugin, &error);
	g_assert_no_error (error);
	g_assert_true (ok);

	g_signal_connect (plugin, "device-added",
			  G_CALLBACK (_plugin_device_added_cb),
			  &device);

	domain_path = udev_mock_add_domain (tt->bed, 0);

	host_path = udev_mock_add_device (tt->bed, domain_path, "0-0",
					  NULL,
					  "Laptop", "0x23",
					  0, /* nvm_authenticate */
					  "18.5");

	host_nvm_path = udev_mock_add_nvme_nonactive (tt->bed, host_path, 0);

	g_debug (" domain:   %s", domain_path);
	g_debug ("  host:    %s", host_path);
	g_debug ("   nvmem:  %s", host_nvm_path);

	mainloop = g_main_loop_new (NULL, FALSE);
	g_timeout_add (1000, on_timeout, mainloop);
	g_main_loop_run (mainloop);
	g_assert_nonnull (device);
}

static char mock_fw[] = "My cool firmware 23 42";
static void
test_update_working (ThunderboltTest *tt, gconstpointer user_data)
{
	FuPlugin *plugin = tt->plugin;
	gboolean ok;
	g_autoptr(GError) error = NULL;
	g_autofree char *domain_path = NULL;
	g_autoptr(GBytes) fw_data = NULL;
	UpdateContext ctx = { NULL, };

	ok = fu_plugin_runner_coldplug (plugin, &error);
	g_assert_no_error (error);
	g_assert_true (ok);

	domain_path = udev_mock_add_domain (tt->bed, 0);

	ok = udev_mock_add_tree (tt->bed, plugin, &root_one, domain_path);
	g_assert_true (ok);
	udev_mock_dump_tree (&root_one, 0);

	fw_data = g_bytes_new_static (mock_fw, strlen (mock_fw));

	g_assert_no_error (error);

	udev_mock_prepare_for_update (plugin, tt->bed, &root_one, 2*1000, &ctx);
	ok = fu_plugin_runner_update (plugin, root_one.fu_device, NULL, fw_data, 0, &error);
	g_assert_no_error (error);
	g_assert_true (ok);
}


int
main(int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);
	g_log_set_fatal_mask (NULL, G_LOG_LEVEL_ERROR | G_LOG_LEVEL_CRITICAL);

	if (!umockdev_in_mock_environment ()) {
		g_warning ("Need to run within umockdev wrapper (umockdev-wrapper %s)!",
			   program_invocation_short_name);
		return EXIT_FAILURE;
	}

	g_test_add ("/thunderbolt/basic",
		    ThunderboltTest,
		    NULL,
		    test_set_up,
		    test_basic,
		    test_tear_down);

	g_test_add ("/thunderbolt/update{working}",
		    ThunderboltTest,
		    NULL,
		    test_set_up,
		    test_update_working,
		    test_tear_down);

	return g_test_run ();
}
