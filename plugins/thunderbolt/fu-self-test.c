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


static gchar *
udev_mock_add_domain (UMockdevTestbed *bed, int id)
{
	gchar *path;
	g_autofree gchar *name = NULL;

	name = g_strdup_printf ("domain%d", id);
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


static gchar *
udev_mock_add_nvme_nonactive (UMockdevTestbed *bed,
			      const char      *parent,
			      int              id)
{
	g_autofree gchar *name = NULL;
	gchar *path;

	name = g_strdup_printf ("nvm_non_active%d", id);
	path = umockdev_testbed_add_device (bed, "nvmem", name,
					    parent,
					    "nvmem", "",
					    NULL,
					    NULL);

	g_assert_nonnull (path);
	return path;
}

typedef struct MockDevice MockDevice;

struct MockDevice {

	const char *name; /* sysfs: device_name */
	const char *id;   /* sysfs: device */
	const char *nvm_version;

	int delay_ms;

	int domain_id;

	struct MockDevice *children;

	/* optionally filled out */
	const char *uuid;
};

typedef struct MockTree MockTree;

struct MockTree {
	const MockDevice *device;

	MockTree  *parent;
	GPtrArray *children;

	gchar *sysfs_parent;
	int    sysfs_id;
	int    sysfs_nvm_id;

	gchar *uuid;

	UMockdevTestbed *bed;
	gchar  *path;
	gchar  *nvm_device;
	guint   nvm_authenticate;
	gchar  *nvm_version;

	FuDevice *fu_device;
};

static MockTree *
mock_tree_new (MockTree *parent, MockDevice *device, int *id)
{
	MockTree *node = g_slice_new0 (MockTree);
	int current_id = (*id)++;

	node->device = device;
	node->sysfs_id = current_id;
	node->sysfs_nvm_id = current_id;
	node->parent = parent;

	if (device->uuid)
		node->uuid = g_strdup (device->uuid);
	else
		node->uuid = g_uuid_string_random ();

	node->nvm_version = g_strdup (device->nvm_version);
	return node;
}

static void
mock_tree_free (MockTree *tree)
{
	guint i;

	for (i = 0; i < tree->children->len; i++) {
		MockTree *child = g_ptr_array_index (tree->children, i);
		mock_tree_free (child);
	}

	g_ptr_array_free (tree->children, TRUE);

	if (tree->fu_device)
		g_object_unref (tree->fu_device);

	g_free (tree->uuid);
	if (tree->bed != NULL) {
		if (tree->nvm_device) {
			umockdev_testbed_uevent (tree->bed, tree->nvm_device, "remove");
			umockdev_testbed_remove_device (tree->bed, tree->nvm_device);
		}

		if (tree->path) {
			umockdev_testbed_uevent (tree->bed, tree->path, "remove");
			umockdev_testbed_remove_device (tree->bed, tree->path);
		}


		g_object_unref (tree->bed);
	}

	g_free (tree->nvm_version);
	g_free (tree->nvm_device);
	g_free (tree->path);
	g_free (tree->sysfs_parent);
	g_slice_free (MockTree, tree);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC (MockTree, mock_tree_free);


static GPtrArray *
mock_tree_init_children (MockTree *node, int *id)
{
	GPtrArray *children = g_ptr_array_new ();
	MockDevice *iter;

	for (iter = node->device->children; iter && iter->name; iter++) {
		MockTree *child = mock_tree_new (node, iter, id);
		g_ptr_array_add (children, child);
		child->children = mock_tree_init_children (child, id);
	}

	return children;
}

static MockTree *
mock_tree_init (MockDevice *device)
{
	MockTree *tree;
	int devices = 0;

	tree = mock_tree_new (NULL, device, &devices);
	tree->children = mock_tree_init_children (tree, &devices);

	return tree;
}

static void
mock_tree_dump (const MockTree *node, int level)
{
	guint i;
	if (node->path) {
		g_debug ("%*s * %s [%s] at %s", level, " ",
			 node->device->name, node->uuid, node->path);
		g_debug ("%*s   nvmem at %s", level, " ",
			 node->nvm_device);
	} else {
		g_debug ("%*s * %s [%s] %d", level, " ",
			 node->device->name, node->uuid, node->sysfs_id);
	}

	for (i = 0; i < node->children->len; i++) {
		const MockTree *child = g_ptr_array_index (node->children, i);
		mock_tree_dump (child, level + 2);
	}
}

typedef gboolean (* MockTreePredicate) (const MockTree *node, gpointer data);

static const MockTree *
mock_tree_contains (const MockTree    *node,
		    MockTreePredicate  predicate,
		    gpointer           data)
{
	guint i;

	if (predicate (node, data))
		return node;

	for (i = 0; i < node->children->len; i++) {
		const MockTree *child;
		const MockTree *match;

		child = g_ptr_array_index (node->children, i);
		match = mock_tree_contains (child, predicate, data);
		if (match != NULL)
			return match;
	}

	return NULL;
}

static gboolean
mock_tree_all (const MockTree    *node,
	       MockTreePredicate  predicate,
	       gpointer           data)
{
	guint i;

	if (!predicate (node, data))
		return FALSE;

	for (i = 0; i < node->children->len; i++) {
		const MockTree *child;

		child = g_ptr_array_index (node->children, i);
		if (!mock_tree_all (child, predicate, data))
			return FALSE;
	}

	return TRUE;
}

static gboolean
mock_tree_compare_uuid (const MockTree *node, gpointer data)
{
	const gchar *uuid = (const gchar *) data;
	return g_str_equal (node->uuid, uuid);
}

static const MockTree *
mock_tree_find_uuid (const MockTree *root, const char *uuid)
{
	return mock_tree_contains (root,
				   mock_tree_compare_uuid,
				   (gpointer) uuid);
}

static gboolean
mock_tree_node_have_fu_device (const MockTree *node, gpointer data)
{
	return node->fu_device != NULL;
}

static gboolean
mock_tree_attach_device (gpointer user_data)
{
	MockTree *tree = (MockTree *) user_data;
	const MockDevice *dev = tree->device;
	guint i;
	g_autofree gchar *idstr = NULL;
	g_autofree gchar *authenticate = NULL;

	g_assert_nonnull (tree);
	g_assert_nonnull (tree->sysfs_parent);
	g_assert_nonnull (dev);

	idstr = g_strdup_printf ("%d-%d", dev->domain_id, tree->sysfs_id);
	authenticate = g_strdup_printf ("0x%x", tree->nvm_authenticate);

	tree->path = umockdev_testbed_add_device (tree->bed, "thunderbolt", idstr,
						  tree->sysfs_parent,
						  "device_name", dev->name,
						  "device", dev->id,
						  "vendor", "042",
						  "vendor_name", "GNOME.org",
						  "authorized", "0",
						  "nvm_authenticate", authenticate,
						  "nvm_version", tree->nvm_version,
						  "unique_id", tree->uuid,
						  NULL,
						  "DEVTYPE",
						  "thunderbolt_device",
						  NULL);

	tree->nvm_device = udev_mock_add_nvme_nonactive (tree->bed,
							 tree->path,
							 tree->sysfs_id);

	g_assert_nonnull (tree->path);
	g_assert_nonnull (tree->nvm_device);

	for (i = 0; i < tree->children->len; i++) {
		MockTree *child;

		child = g_ptr_array_index (tree->children, i);

		child->bed = g_object_ref (tree->bed);
		child->sysfs_parent = g_strdup (tree->path);

		g_timeout_add (child->device->delay_ms,
			       mock_tree_attach_device,
			       child);
	}

	return FALSE;
}

typedef struct AttachContext {
	/* in */
	MockTree  *tree;
	GMainLoop *loop;
	/* out */
	gboolean   complete;

} AttachContext;

static void
mock_tree_plugin_device_added (FuPlugin *plugin, FuDevice *device, gpointer user_data)
{
	AttachContext *ctx = (AttachContext *) user_data;
	MockTree *tree = ctx->tree;
	const char *uuid = fu_device_get_id (device);
	MockTree *target;

	target = (MockTree *) mock_tree_find_uuid (tree, uuid);

	if (target == NULL) {
		g_warning ("Got device that could not be matched: %s", uuid);
		return;
	}

	target->fu_device = g_object_ref (device);

	if (mock_tree_all (tree, mock_tree_node_have_fu_device, NULL)) {
		ctx->complete = TRUE;
		g_main_loop_quit (ctx->loop);
	}
}


static gboolean
mock_tree_attach (MockTree *root, UMockdevTestbed *bed, FuPlugin *plugin)
{
	g_autoptr(GMainLoop) mainloop = g_main_loop_new (NULL, FALSE);
	AttachContext ctx = {
		.tree = root,
		.loop = mainloop,
	};

	root->bed = g_object_ref (bed);
	root->sysfs_parent = udev_mock_add_domain (bed, root->device->domain_id);
	g_assert_nonnull (root->sysfs_parent);

	g_timeout_add (root->device->delay_ms, mock_tree_attach_device, root);

	g_signal_connect (plugin, "device-added",
			  G_CALLBACK (mock_tree_plugin_device_added),
			  &ctx);

	g_main_loop_run (mainloop);

	return ctx.complete;
}

/* the unused parameter makes the function signature compatible
 * with 'MockTreePredicate' */
static gboolean
mock_tree_node_is_detached (const MockTree *node, gpointer unused)
{
	gboolean ret = node->path == NULL;

	/* consistency checks: if ret, make sure we are
	 * fully detached */
	if (ret) {
		g_assert_null (node->nvm_device);
		g_assert_null (node->bed);
	} else {
		g_assert_nonnull (node->nvm_device);
		g_assert_nonnull (node->bed);
	}

	return ret;
}

static void
mock_tree_detach (MockTree *node)
{
	UMockdevTestbed *bed;
	guint i;

	if (mock_tree_node_is_detached (node, NULL))
		return;

	for (i = 0; i < node->children->len; i++) {
		MockTree *child = g_ptr_array_index (node->children, i);
		mock_tree_detach (child);
		g_free (child->sysfs_parent);
		child->sysfs_parent = NULL;
	}

	bed  = node->bed;
	umockdev_testbed_uevent (bed, node->nvm_device, "remove");
	umockdev_testbed_remove_device (bed, node->nvm_device);

	umockdev_testbed_uevent (bed, node->path, "remove");
	umockdev_testbed_remove_device (bed, node->path);

	g_free (node->path);
	g_free (node->nvm_device);

	node->path = NULL;
	node->nvm_device = NULL;

	g_object_unref (bed);
	node->bed = NULL;
}

typedef struct UpdateContext {
	GFileMonitor *monitor;

	guint result;
	guint timeout;
	UMockdevTestbed *bed;
	FuPlugin *plugin;

	MockTree *node;
	gchar *version;
} UpdateContext;

static void
update_context_free (UpdateContext *ctx)
{
	if (ctx == NULL)
		return;

	g_object_unref (ctx->bed);
	g_object_unref (ctx->plugin);
	g_object_unref (ctx->monitor);
	g_free (ctx->version);
	g_free (ctx);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC (UpdateContext, update_context_free);

static gboolean
reattach_tree (gpointer user_data)
{
	UpdateContext *ctx = (UpdateContext *) user_data;
	MockTree *node = ctx->node;

	g_debug ("Mock update done, reattaching tree...");

	node->bed = g_object_ref (ctx->bed);
	g_timeout_add (node->device->delay_ms, mock_tree_attach_device, node);

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
	g_autofree gchar *data = NULL;
	g_autoptr(GError) error = NULL;

	g_debug ("Got update trigger");
	ok = g_file_monitor_cancel (monitor);
	g_assert_true (ok);

	ok = g_file_load_contents (file, NULL, &data, &len, NULL, &error);
	g_assert_no_error (error);
	g_assert_true (ok);

	if (!g_str_has_prefix (data, "1"))
		return;

	g_debug ("Removing tree below and including: %s", ctx->node->path);
	mock_tree_detach (ctx->node);

	g_free (ctx->node->nvm_version);
	ctx->node->nvm_version = g_strdup (ctx->version);

	g_debug ("Simulating update and scheduling tree reattachment in %3.2f seconds",
		 ctx->timeout / 1000.0);
	g_timeout_add (ctx->timeout, reattach_tree, ctx);
}

static UpdateContext *
mock_tree_prepare_for_update (MockTree        *node,
			      FuPlugin        *plugin,
			      const char      *version,
			      guint            timeout_ms)
{
	UpdateContext *ctx;
	g_autoptr(GFile) dir = NULL;
	g_autoptr(GFile) f = NULL;
	g_autoptr(GError) error = NULL;
	GFileMonitor *monitor;

	ctx = g_new0 (UpdateContext, 1);
	dir = g_file_new_for_path (node->path);
	f = g_file_get_child (dir, "nvm_authenticate");

	monitor = g_file_monitor_file (f, G_FILE_MONITOR_NONE, NULL, &error);
	g_assert_no_error (error);
	g_assert_nonnull (monitor);

	ctx->node = node;
	ctx->plugin = g_object_ref (plugin);
	ctx->bed = g_object_ref (node->bed);
	ctx->timeout = timeout_ms;
	ctx->monitor = monitor;
	ctx->version = g_strdup (version);

	g_signal_connect (monitor, "changed",
			  G_CALLBACK (udev_file_changed_cb), ctx);

	return ctx;
}


static MockDevice root_one = {

	.name = "Laptop",
	.id = "0x23",
	.nvm_version = "20.0",

	.children = (MockDevice[]) {
		{
			.name = "Thunderbolt Cable",
			.id = "0x24",
			.nvm_version = "20.0",

			.children = (MockDevice[]) {
				{
					.name = "Thunderbolt Dock",
					.id = "0x25",
					.nvm_version = "10.0",
				},
				{ NULL, }

			},
		}, {
			.name = "Thunderbolt Cable",
			.id = "0x24",
			.nvm_version = "23.0",

			.children = (MockDevice[]) {
				{
					.name = "Thunderbolt SSD",
					.id = "0x26",

					.nvm_version = "5.0",
				},
				{ NULL, }
			},
		},
		{ NULL, },
	},

};

static gboolean
test_tree_uuids (const MockTree *node, gpointer data)
{
	const MockTree *root = (MockTree *) data;
	const gchar *uuid = node->uuid;
	const MockTree *found;

	g_assert_nonnull (uuid);

	g_debug ("Looking for %s", uuid);

	found = mock_tree_find_uuid (root, uuid);
	g_assert_nonnull (found);
	g_assert_cmpstr (node->uuid, ==, found->uuid);

	/* return false so we traverse the whole tree */
	return FALSE;
}

static void
test_tree (ThunderboltTest *tt, gconstpointer user_data)
{
	const MockTree *found;
	gboolean ret;
	g_autoptr(MockTree) tree = NULL;
	g_autoptr(GError) error = NULL;

	tree = mock_tree_init (&root_one);
	g_assert_nonnull (tree);

	mock_tree_dump (tree, 0);

	(void) mock_tree_contains (tree, test_tree_uuids, tree);

	found = mock_tree_find_uuid (tree, "nonexistentuuid");
	g_assert_null (found);

	ret = fu_plugin_runner_coldplug (tt->plugin, &error);
	g_assert_no_error (error);
	g_assert_true (ret);

	ret = mock_tree_attach (tree, tt->bed, tt->plugin);
	g_assert_true (ret);

	mock_tree_detach (tree);
	mock_tree_all (tree, mock_tree_node_is_detached, NULL);
}


static char mock_fw[] = "My cool firmware 23 42";
static void
test_update_working (ThunderboltTest *tt, gconstpointer user_data)
{
	FuPlugin *plugin = tt->plugin;
	gboolean ret;
	const gchar *version_after;
	g_autoptr(MockTree) tree = NULL;
	g_autoptr(GError) error = NULL;
	g_autoptr(GBytes) fw_data = NULL;
	g_autoptr(UpdateContext) up_ctx = NULL;

	tree = mock_tree_init (&root_one);
	g_assert_nonnull (tree);

	ret = fu_plugin_runner_coldplug (tt->plugin, &error);
	g_assert_no_error (error);
	g_assert_true (ret);

	ret = mock_tree_attach (tree, tt->bed, tt->plugin);
	g_assert_true (ret);

	fw_data = g_bytes_new_static (mock_fw, strlen (mock_fw));
	g_assert_no_error (error);
	g_assert_nonnull (fw_data);

	up_ctx = mock_tree_prepare_for_update (tree, plugin, "42.23", 2*1000);
	ret = fu_plugin_runner_update (plugin, tree->fu_device, NULL, fw_data, 0, &error);
	g_assert_no_error (error);
	g_assert_true (ret);

	version_after = fu_device_get_version (tree->fu_device);
	g_debug ("version after update: %s", version_after);
	g_assert_cmpstr (version_after, ==, "42.23");
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
		    test_tree,
		    test_tear_down);

	g_test_add ("/thunderbolt/update{working}",
		    ThunderboltTest,
		    NULL,
		    test_set_up,
		    test_update_working,
		    test_tear_down);

	return g_test_run ();
}
