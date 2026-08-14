#!/usr/bin/env python3
"""Reconstruct Hancom Gooroom 3.3 gnome-flashback over exact public lineages.

The lost original han3u4 source archive is not claimed as recovered. The exact
shipped AMD64 binary packages are the immutable target authority. Seven source
changes are imported from their public Gooroom 3.0 equivalents; four bounded
Hancom deltas are reconstructed from the packaged changelog and exact shipped
ELF/resource evidence.
"""
from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import difflib
import gzip
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tarfile
from pathlib import Path
from typing import Any

SOURCE = "gnome-flashback"
BASE_VERSION = "3.38.0-2+grm3u2+han3u1"
TARGET_VERSION = "3.38.0-2+grm3u2+han3u4"
HANCOM_REPOSITORY = "hancomgooroom/gnome-flashback"
HANCOM_COMMIT = "df5e1ec84df0cbb1dc9c1ce4f8a7ed366cd50db7"
HANCOM_TREE = "a5961872b3538a33b1ece5c76d0cf67506c71e2b"
GOOROOM_REPOSITORY = "gooroom/gnome-flashback"
GOOROOM_COMMIT = "68a47d769b0f15b84c532746ced1f8ae538ab545"
GOOROOM_TREE = "830a852c6272843c4c23da7e80b3b3961d4aeb38"
TARGETS = {
    "gnome-flashback-common": {
        "filename": "gnome-flashback-common_3.38.0-2+grm3u2+han3u4_all.deb",
        "architecture": "all",
        "size": 99916,
        "sha256": "5770961e60c68b25ea7a84ab14871635b450b79f25f9596c79edad67a34e4543",
    },
    "gnome-flashback": {
        "filename": "gnome-flashback_3.38.0-2+grm3u2+han3u4_amd64.deb",
        "architecture": "amd64",
        "size": 436564,
        "sha256": "6c62fea3341f7c208448250d9eaa2b467df99abdbad53bc236f089fad9741408",
    },
    "gnome-session-flashback": {
        "filename": "gnome-session-flashback_3.38.0-2+grm3u2+han3u4_all.deb",
        "architecture": "all",
        "size": 14508,
        "sha256": "3968b152293606e4626fbe3317913d6f57add08001c3a5a66abd71a8576abcf6",
    },
}
PUBLIC_PATCHES = {
    "gooroom-16-update-desktop-new-folder-message.patch": "c998a383a67a8b25f51af2f30f749f2a07c566452eb7ca6e8e768210db3e15d4",
    "gooroom-17-update-desktop-new-folder-length-limit.patch": "cad8fe4d17468a7e3598323f7ef7a8c7be310e9720d4424d79251aa7d30abf33",
    "gooroom-18-remove-new-folder-dialog-taskbar-icon.patch": "d844d1ecd00284c4055c11d53d0b34948748c04c6301d0ac1c3b217e6d4ef078",
    "gooroom-19-remove-open-terminal-menu-when-termianl-desktop-app-not-exist.patch": "515c1a09ed19e6edd725c21c46fa9c2ffd73a099ddf0a867a5fb736326f706d3",
    "gooroom-20-create-an-application-shortcut-icon-on-the-desktop.patch": "aedd5ef15f084ad967e1e9e789c0901a2043a2caedf7eef14e607f5f3a563b3d",
    "gooroom-21-update-open-terminal-menu-when-user-do-not-have-exec-permission.patch": "1b98b4ebadde6ac446b155dca52b99aabf166f0f8830a0b3ac0d86f4f3d021df",
    "gooroom-22-change-create-file-logic-when-file-change-done.patch": "55aca8b1f5d88135a3931392009fd5fd5f4f54f5839eb1e4f52c2315d785fc22",
}
AUTHORITATIVE_CHANGE_IDS = [
    "99da2574", "a38d3e6b", "ef9a0790",
    "7f8a9b22", "aa9dfb89",
    "cc88eff1", "1bf11751", "7af5a94e", "6b37d402",
]
UNIQUE_PATCH_NAME = "hancom-17-reconstructed-final-3.3-deltas.patch"
TARGET_RESOURCE = "/org/gnome/gnome-flashback/theme/common.css"
ELF_MAGIC = b"\x7fELF"

RESOURCE_MAP = {
    "/org/gnome/gnome-flashback/flashback-polkit-dialog.ui": "gnome-flashback/libpolkit/flashback-polkit-dialog.ui",
    "/org/gnome/gnome-flashback/gf-inhibit-dialog.ui": "gnome-flashback/libend-session-dialog/gf-inhibit-dialog.ui",
    "/org/gnome/gnome-flashback/polkit-agent-self-auth-dialog.ui": "gnome-flashback/libpolkit/polkit-agent-self-auth-dialog.ui",
    "/org/gnome/gnome-flashback/screensaver/arrow.svg": "data/screensaver/images/gooroom-screensaver-entry-arrow.svg",
    "/org/gnome/gnome-flashback/screensaver/logo.svg": "data/screensaver/images/gooroom-screensaver-logo.svg",
    "/org/gnome/gnome-flashback/screensaver/logout.svg": "data/screensaver/images/gooroom-screensaver-logout.svg",
    "/org/gnome/gnome-flashback/theme/Adwaita/gnome-flashback-dark.css": "data/theme/Adwaita/gnome-flashback-dark.css",
    "/org/gnome/gnome-flashback/theme/Adwaita/gnome-flashback.css": "data/theme/Adwaita/gnome-flashback.css",
    "/org/gnome/gnome-flashback/theme/HighContrast/gnome-flashback-inverse.css": "data/theme/HighContrast/gnome-flashback-inverse.css",
    "/org/gnome/gnome-flashback/theme/HighContrast/gnome-flashback.css": "data/theme/HighContrast/gnome-flashback.css",
    "/org/gnome/gnome-flashback/theme/Yaru/gnome-flashback.css": "data/theme/Yaru/gnome-flashback.css",
    "/org/gnome/gnome-flashback/theme/common.css": "data/theme/common.css",
    "/org/gnome/gnome-flashback/theme/fallback.css": "data/theme/fallback.css",
    "/org/gnome/gnome-flashback/theme/gooroom.css": "data/theme/gooroom.css",
    "/org/gnome/gnome-flashback/ui/gf-confirm-display-change-dialog.ui": "data/ui/gf-confirm-display-change-dialog.ui",
    "/org/gnome/gnome-flashback/ui/gf-unlock-dialog.ui": "gnome-flashback/libscreensaver/gf-unlock-dialog.ui",
}


def run(arguments: list[str], *, cwd: Path | None = None, binary: bool = False) -> str | bytes:
    completed = subprocess.run(
        arguments,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=not binary,
        check=False,
    )
    if completed.returncode:
        stdout = completed.stdout.decode("utf-8", "replace") if isinstance(completed.stdout, bytes) else completed.stdout
        stderr = completed.stderr.decode("utf-8", "replace") if isinstance(completed.stderr, bytes) else completed.stderr
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(arguments)}\n"
            f"stdout:\n{stdout}\nstderr:\n{stderr}"
        )
    return completed.stdout


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def deb_field(path: Path, field: str) -> str:
    completed = subprocess.run(
        ["dpkg-deb", "-f", str(path), field], text=True,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False,
    )
    return completed.stdout.strip() if completed.returncode == 0 else ""


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one source anchor, found {count}")
    return text.replace(old, new)


def deterministic_tar_gz(source: Path, destination: Path) -> None:
    if destination.exists():
        destination.unlink()
    run([
        "tar", "--sort=name", "--mtime=@0", "--owner=0", "--group=0",
        "--numeric-owner", "--exclude=.git", "--exclude=.pc", "-czf",
        str(destination), "-C", str(source), ".",
    ])


class GError(ctypes.Structure):
    _fields_ = [("domain", ctypes.c_uint32), ("code", ctypes.c_int), ("message", ctypes.c_char_p)]


def resource_entries_from_elf(elf: Path, temporary: Path) -> dict[str, bytes]:
    temporary.mkdir(parents=True, exist_ok=True)
    section = temporary / "resource.bin"
    run(["objcopy", f"--dump-section=.gresource.gf={section}", str(elf)])
    if not section.is_file() or not section.stat().st_size:
        raise SystemExit("target ELF lacks a usable .gresource.gf section")

    gio_name = ctypes.util.find_library("gio-2.0")
    glib_name = ctypes.util.find_library("glib-2.0")
    if not gio_name or not glib_name:
        raise SystemExit("GLib/GIO runtime libraries are unavailable")
    gio = ctypes.CDLL(gio_name)
    glib = ctypes.CDLL(glib_name)
    gio.g_resource_load.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.POINTER(GError))]
    gio.g_resource_load.restype = ctypes.c_void_p
    gio.g_resource_enumerate_children.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int, ctypes.POINTER(ctypes.POINTER(GError))]
    gio.g_resource_enumerate_children.restype = ctypes.POINTER(ctypes.c_char_p)
    gio.g_resource_lookup_data.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int, ctypes.POINTER(ctypes.POINTER(GError))]
    gio.g_resource_lookup_data.restype = ctypes.c_void_p
    gio.g_resource_unref.argtypes = [ctypes.c_void_p]
    glib.g_strfreev.argtypes = [ctypes.POINTER(ctypes.c_char_p)]
    glib.g_error_free.argtypes = [ctypes.POINTER(GError)]
    glib.g_bytes_get_size.argtypes = [ctypes.c_void_p]
    glib.g_bytes_get_size.restype = ctypes.c_size_t
    glib.g_bytes_get_data.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t)]
    glib.g_bytes_get_data.restype = ctypes.c_void_p
    glib.g_bytes_unref.argtypes = [ctypes.c_void_p]

    def error_message(error: ctypes.POINTER(GError)) -> str:
        if not error:
            return "unknown GLib error"
        message = error.contents.message.decode("utf-8", "replace")
        glib.g_error_free(error)
        return message

    error = ctypes.POINTER(GError)()
    resource = gio.g_resource_load(str(section).encode(), ctypes.byref(error))
    if not resource:
        raise SystemExit(f"cannot load dumped GResource: {error_message(error)}")
    rows: dict[str, bytes] = {}

    def walk(path: str) -> None:
        local_error = ctypes.POINTER(GError)()
        names = gio.g_resource_enumerate_children(resource, path.encode(), 0, ctypes.byref(local_error))
        if not names:
            raise SystemExit(f"cannot enumerate GResource {path}: {error_message(local_error)}")
        values: list[str] = []
        index = 0
        while names[index]:
            values.append(names[index].decode("utf-8"))
            index += 1
        glib.g_strfreev(names)
        for value in values:
            child = path + value
            if value.endswith("/"):
                walk(child)
                continue
            lookup_error = ctypes.POINTER(GError)()
            data = gio.g_resource_lookup_data(resource, child.encode(), 0, ctypes.byref(lookup_error))
            if not data:
                raise SystemExit(f"cannot read GResource {child}: {error_message(lookup_error)}")
            size = glib.g_bytes_get_size(data)
            pointer = glib.g_bytes_get_data(data, None)
            rows[child] = ctypes.string_at(pointer, size)
            glib.g_bytes_unref(data)

    walk("/")
    gio.g_resource_unref(resource)
    return rows


def unified_patch(before: Path, after: Path, paths: list[str]) -> str:
    chunks: list[str] = []
    for relative in paths:
        left = (before / relative).read_text(encoding="utf-8").splitlines(keepends=True)
        right = (after / relative).read_text(encoding="utf-8").splitlines(keepends=True)
        diff = difflib.unified_diff(left, right, fromfile=f"a/{relative}", tofile=f"b/{relative}")
        chunks.extend(diff)
    patch = "".join(chunks)
    if not patch:
        raise SystemExit("unique reconstruction patch is empty")
    return patch


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--hancom-repository", type=Path, required=True)
    parser.add_argument("--gooroom-repository", type=Path, required=True)
    parser.add_argument("--target-deb-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    hancom = args.hancom_repository.resolve()
    gooroom = args.gooroom_repository.resolve()
    target_dir = args.target_deb_dir.resolve()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)

    for repository, commit, tree, version, label in (
        (hancom, HANCOM_COMMIT, HANCOM_TREE, BASE_VERSION, "Hancom base"),
        (gooroom, GOOROOM_COMMIT, GOOROOM_TREE, "3.38.0-2+grm3u7", "Gooroom lineage"),
    ):
        if not (repository / ".git").exists():
            raise SystemExit(f"{label} is not a Git checkout: {repository}")
        actual_commit = str(run(["git", "rev-parse", "HEAD"], cwd=repository)).strip()
        actual_tree = str(run(["git", "rev-parse", "HEAD^{tree}"], cwd=repository)).strip()
        if actual_commit != commit or actual_tree != tree:
            raise SystemExit(f"{label} identity mismatch: {actual_commit} / {actual_tree}")
        if str(run(["git", "status", "--porcelain=v1"], cwd=repository)).strip():
            raise SystemExit(f"{label} checkout is not clean")
        actual_version = str(run(["dpkg-parsechangelog", "-l", "debian/changelog", "-SVersion"], cwd=repository)).strip()
        if actual_version != version:
            raise SystemExit(f"{label} source version mismatch: {actual_version}")

    targets: dict[str, Path] = {}
    target_rows: list[dict[str, Any]] = []
    target_roots = output / "target-roots"
    shutil.rmtree(target_roots, ignore_errors=True)
    target_roots.mkdir(parents=True)
    changelogs: dict[str, bytes] = {}
    for package, authority in TARGETS.items():
        deb = target_dir / authority["filename"]
        if not deb.is_file():
            raise SystemExit(f"target DEB missing: {deb}")
        if deb.stat().st_size != authority["size"] or sha256_file(deb) != authority["sha256"]:
            raise SystemExit(f"target DEB authority mismatch: {deb.name}")
        if deb_field(deb, "Package") != package:
            raise SystemExit(f"target package mismatch: {deb.name}")
        if deb_field(deb, "Version") != TARGET_VERSION:
            raise SystemExit(f"target version mismatch: {deb.name}")
        if deb_field(deb, "Architecture") != authority["architecture"]:
            raise SystemExit(f"target architecture mismatch: {deb.name}")
        source_field = deb_field(deb, "Source").split(" ", 1)[0] or package
        if source_field != SOURCE:
            raise SystemExit(f"target source mismatch: {deb.name}: {source_field}")
        root = target_roots / package
        root.mkdir()
        run(["dpkg-deb", "-x", str(deb), str(root)])
        changelog = root / "usr/share/doc" / package / "changelog.Debian.gz"
        if not changelog.is_file():
            raise SystemExit(f"target changelog missing: {changelog}")
        changelogs[package] = gzip.decompress(changelog.read_bytes())
        targets[package] = deb
        target_rows.append({"package": package, **authority})
    canonical_changelog = changelogs[SOURCE]
    if any(value != canonical_changelog for value in changelogs.values()):
        raise SystemExit("target package changelogs disagree")
    changelog_text = canonical_changelog.decode("utf-8")
    if not changelog_text.startswith(f"{SOURCE} ({TARGET_VERSION})"):
        raise SystemExit("target changelog version authority mismatch")
    for change in AUTHORITATIVE_CHANGE_IDS:
        if f"[{change}]" not in changelog_text:
            raise SystemExit(f"target changelog lacks authoritative change {change}")

    main_elf = target_roots / SOURCE / "usr/bin/gnome-flashback"
    if not main_elf.is_file() or not main_elf.read_bytes().startswith(ELF_MAGIC):
        raise SystemExit("target main ELF missing")
    resources = resource_entries_from_elf(main_elf, output / "resource-work")
    if set(resources) != set(RESOURCE_MAP):
        raise SystemExit(
            f"target embedded resource set mismatch: missing={sorted(set(RESOURCE_MAP)-set(resources))} "
            f"extra={sorted(set(resources)-set(RESOURCE_MAP))}"
        )
    target_css = resources[TARGET_RESOURCE]
    resource_rows: list[dict[str, Any]] = []

    patch_dir = hancom / "debian/patches"
    series = patch_dir / "series"
    series_text = series.read_text(encoding="utf-8")
    if not series_text.endswith("\n"):
        series_text += "\n"
    for name, expected_hash in PUBLIC_PATCHES.items():
        source_patch = gooroom / "debian/patches" / name
        if not source_patch.is_file() or sha256_file(source_patch) != expected_hash:
            raise SystemExit(f"public equivalent patch authority mismatch: {name}")
        destination = patch_dir / name
        if destination.exists():
            raise SystemExit(f"public equivalent patch already exists: {name}")
        shutil.copy2(source_patch, destination)
        series_text += name + "\n"
    series.write_text(series_text, encoding="utf-8")
    (hancom / "debian/changelog").write_bytes(canonical_changelog)

    run(["dpkg-source", "--before-build", "."], cwd=hancom)
    # Compare the target embedded resource set to the fully patched public Hancom base.
    for resource_path, source_path in RESOURCE_MAP.items():
        source_file = hancom / source_path
        if not source_file.is_file():
            raise SystemExit(f"public patched resource source is missing: {source_path}")
        source_payload = source_file.read_bytes()
        target_payload = resources[resource_path]
        identical = source_payload == target_payload
        if resource_path != TARGET_RESOURCE and not identical:
            raise SystemExit(f"unexpected embedded-resource delta: {resource_path}")
        if resource_path == TARGET_RESOURCE and identical:
            raise SystemExit("target common.css unexpectedly matches public base")
        resource_rows.append({
            "resource_path": resource_path,
            "source_path": source_path,
            "target_size": len(target_payload),
            "target_sha256": sha256_bytes(target_payload),
            "public_base_identical": identical,
        })

    unique_paths = [
        "data/theme/common.css",
        "gnome-flashback/libdesktop/gf-icon-view.c",
        "gnome-flashback/libscreensaver/gf-panel-bottom.c",
        "gnome-flashback/libscreensaver/gf-unlock-dialog.c",
    ]
    before = output / "before-unique"
    after = output / "after-unique"
    shutil.rmtree(before, ignore_errors=True)
    shutil.rmtree(after, ignore_errors=True)
    for relative in unique_paths:
        origin = hancom / relative
        destination = before / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(origin, destination)

    # ef9a0790: preserve the Placement submenu machinery and line geometry, but hide its parent item.
    icon_path = hancom / "gnome-flashback/libdesktop/gf-icon-view.c"
    icon_text = icon_path.read_text(encoding="utf-8")
    placement_block = (
        '  item = gtk_menu_item_new_with_label (_("Placement"));\n'
        '  gtk_menu_shell_append (GTK_MENU_SHELL (popup_menu), item);\n'
        '  gtk_widget_show (item);\n\n'
        '  append_placement_submenu (self, item);\n\n'
    )
    hidden_placement_block = (
        '  item = gtk_menu_item_new_with_label (_("Placement"));\n'
        '  gtk_menu_shell_append (GTK_MENU_SHELL (popup_menu), item);\n'
        '\n\n'
        '  append_placement_submenu (self, item);\n\n'
    )
    icon_text = replace_once(
        icon_text,
        placement_block,
        hidden_placement_block,
        "hidden desktop Placement submenu",
    )
    icon_path.write_text(icon_text, encoding="utf-8")

    # 7f8a9b22: target machine code consumes exactly GDK_KEY_Hangul on the password entry.
    unlock_path = hancom / "gnome-flashback/libscreensaver/gf-unlock-dialog.c"
    unlock_text = unlock_path.read_text(encoding="utf-8")
    unlock_text = replace_once(
        unlock_text,
        "static gint\nkey_press_event_cb (GtkWidget   *widget,\n",
        "static gint\nhangul_key_press_event_cb (GtkWidget   *widget,\n"
        "                           GdkEventKey *event,\n"
        "                           gpointer    *data)\n"
        "{\n"
        "  return event->keyval == GDK_KEY_Hangul;\n"
        "}\n\n"
        "static gint\nkey_press_event_cb (GtkWidget   *widget,\n",
        "Hangul key callback",
    )
    unlock_text = replace_once(
        unlock_text,
        '  g_signal_connect (self->auth_prompt_entry, "popup-menu",\n'
        '                      G_CALLBACK (prompt_entry_popup_event_cb),NULL);\n'
        '  g_signal_connect (self->auth_unlock_button, "clicked",\n',
        '  g_signal_connect (self->auth_prompt_entry, "popup-menu",\n'
        '                      G_CALLBACK (prompt_entry_popup_event_cb),NULL);\n'
        '  g_signal_connect (self->auth_prompt_entry, "key_press_event",\n'
        '                      G_CALLBACK (hangul_key_press_event_cb),NULL);\n'
        '  g_signal_connect (self->auth_unlock_button, "clicked",\n',
        "Hangul key signal connection",
    )
    unlock_path.write_text(unlock_text, encoding="utf-8")

    # aa9dfb89: source geometry is locked by target G_LOG line strings 49/68/85.
    panel_path = hancom / "gnome-flashback/libscreensaver/gf-panel-bottom.c"
    panel_text = panel_path.read_text(encoding="utf-8")
    panel_text = replace_once(
        panel_text,
        '#define LOGOUT_COMMAND  "/usr/bin/gnome-session-quit --force"\n',
        '#define LOGOUT_COMMAND  "/usr/bin/gnome-session-quit --force"\n'
        '#define ONLINE_COMMAND  "/usr/bin/nm-online"\n',
        "online command constant",
    )
    panel_text = replace_once(
        panel_text,
        "static gboolean\nbutton_press (GtkButton     *button,\n",
        "static gboolean\nnetwork_online (GfPanelBottom *self)\n"
        "{\n"
        "    char   **argv  = NULL;\n"
        "    GError  *error = NULL;\n"
        "    gboolean res;\n\n"
        "    res = g_shell_parse_argv (ONLINE_COMMAND, NULL, &argv, &error);\n\n"
        "    if (!res) {\n"
        "        g_warning (\"Could not parse online command: %s\", error->message);\n"
        "        g_error_free (error);\n"
        "        return FALSE;\n"
        "    }\n\n"
        "    return TRUE;\n"
        "}\n\n"
        "static gboolean\nbutton_press (GtkButton     *button,\n",
        "network-online helper",
    )
    panel_text = replace_once(
        panel_text,
        '    g_signal_connect (self->clock, "notify::clock",\n'
        '                      G_CALLBACK (clock_changed_cb),\n'
        '                      self);\n\n'
        '    left_hbox = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 0);\n',
        '    g_signal_connect (self->clock, "notify::clock",\n'
        '                      G_CALLBACK (clock_changed_cb),\n'
        '                      self);\n\n'
        '    network_online (self);\n\n'
        '    left_hbox = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 0);\n',
        "network-online invocation",
    )
    panel_path.write_text(panel_text, encoding="utf-8")

    # cc88eff1: exact common.css bytes recovered from target ELF GResource.
    css_path = hancom / "data/theme/common.css"
    css_path.write_bytes(target_css)

    for relative in unique_paths:
        origin = hancom / relative
        destination = after / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(origin, destination)
    unique_patch = unified_patch(before, after, unique_paths)

    # Validate the strongest binary-derived anchors before packaging the source.
    panel_lines = panel_path.read_text(encoding="utf-8").splitlines()
    expected_lines = {
        49: '        g_warning ("Could not parse online command: %s", error->message);',
        68: '        g_warning ("Could not parse logout command: %s", error->message);',
        85: '        g_warning ("Could not run logout command: %s", error->message);',
    }
    for line_number, expected in expected_lines.items():
        if panel_lines[line_number - 1] != expected:
            raise SystemExit(f"network source line geometry mismatch at {line_number}")
    if css_path.read_bytes() != target_css:
        raise SystemExit("target embedded CSS relationship was not preserved")
    final_icon_text = icon_path.read_text(encoding="utf-8")
    if hidden_placement_block not in final_icon_text:
        raise SystemExit("hidden Placement submenu geometry was not preserved")
    if placement_block in final_icon_text:
        raise SystemExit("Placement submenu parent is still visible")
    if "GDK_KEY_Hangul" not in unlock_path.read_text(encoding="utf-8"):
        raise SystemExit("Hangul key evidence is absent")

    # Restore pre-unique applied files, unapply public/base quilt, then add the unique patch.
    for relative in unique_paths:
        shutil.copy2(before / relative, hancom / relative)
    run(["dpkg-source", "--after-build", "."], cwd=hancom)
    if (hancom / ".pc").exists():
        raise SystemExit("quilt state remained after unapply")
    unique_patch_path = patch_dir / UNIQUE_PATCH_NAME
    unique_patch_path.write_text(unique_patch, encoding="utf-8")
    with series.open("a", encoding="utf-8") as stream:
        stream.write(UNIQUE_PATCH_NAME + "\n")

    # Reapply every patch and prove the final reconstructed source anchors, then unapply cleanly.
    run(["dpkg-source", "--before-build", "."], cwd=hancom)
    if (hancom / "data/theme/common.css").read_bytes() != target_css:
        raise SystemExit("reapplied unique patch does not reproduce target CSS")
    reapplied_panel = (hancom / "gnome-flashback/libscreensaver/gf-panel-bottom.c").read_text(encoding="utf-8").splitlines()
    for line_number, expected in expected_lines.items():
        if reapplied_panel[line_number - 1] != expected:
            raise SystemExit(f"reapplied network line mismatch at {line_number}")
    run(["dpkg-source", "--after-build", "."], cwd=hancom)

    target_version = str(run(["dpkg-parsechangelog", "-l", "debian/changelog", "-SVersion"], cwd=hancom)).strip()
    if target_version != TARGET_VERSION:
        raise SystemExit(f"reconstructed source version mismatch: {target_version}")
    run(["git", "diff", "--check"], cwd=hancom)
    changed = set(filter(None, str(run(["git", "status", "--porcelain=v1"], cwd=hancom)).splitlines()))
    expected_suffixes = {
        " M debian/changelog",
        " M debian/patches/series",
        *(f"?? debian/patches/{name}" for name in PUBLIC_PATCHES),
        f"?? debian/patches/{UNIQUE_PATCH_NAME}",
    }
    if changed != expected_suffixes:
        raise SystemExit(f"reconstruction escaped bounded source path set: {sorted(changed)}")

    patch_bundle = str(run(["git", "diff", "--binary", "--full-index", "--no-ext-diff"], cwd=hancom))
    for name in [*PUBLIC_PATCHES, UNIQUE_PATCH_NAME]:
        payload = (patch_dir / name).read_bytes()
        patch_bundle += f"\n# NEW FILE debian/patches/{name} SHA256 {sha256_bytes(payload)}\n"
        patch_bundle += payload.decode("utf-8")
        if not patch_bundle.endswith("\n"):
            patch_bundle += "\n"
    (output / "reconstruction.patch").write_text(patch_bundle, encoding="utf-8")

    archive = output / "reconstructed-source.tar.gz"
    deterministic_tar_gz(hancom, archive)
    lock = {
        "schema": 1,
        "source": SOURCE,
        "source_version": TARGET_VERSION,
        "source_status": "candidate-reconstructed-git-tree",
        "base_source": {
            "repository_full_name": HANCOM_REPOSITORY,
            "commit_sha": HANCOM_COMMIT,
            "tree_sha": HANCOM_TREE,
            "source_version": BASE_VERSION,
        },
        "public_equivalent_source": {
            "repository_full_name": GOOROOM_REPOSITORY,
            "commit_sha": GOOROOM_COMMIT,
            "tree_sha": GOOROOM_TREE,
            "source_version": "3.38.0-2+grm3u7",
            "patches": [
                {"filename": name, "sha256": expected_hash}
                for name, expected_hash in PUBLIC_PATCHES.items()
            ],
        },
        "target_binary_authority": target_rows,
        "packaged_changelog": {
            "sha256": sha256_bytes(canonical_changelog),
            "authoritative_change_ids": AUTHORITATIVE_CHANGE_IDS,
        },
        "embedded_resource_relationship": {
            "resource_count": len(resource_rows),
            "resources": resource_rows,
            "changed_resource": TARGET_RESOURCE,
            "changed_resource_sha256": sha256_bytes(target_css),
            "all_other_resources_public_base_identical": True,
        },
        "unique_reconstruction": {
            "patch_filename": UNIQUE_PATCH_NAME,
            "patch_sha256": sha256_file(unique_patch_path),
            "changed_paths": unique_paths,
            "elf_confirmed_behaviors": [
                "desktop-placement-submenu-parent-not-shown",
                "password-entry-consumes-GDK_KEY_Hangul-0xff31",
                "screensaver-panel-calls-network_online-with-nm-online",
                "desktop-icon-label-common-css-matches-target-gresource",
            ],
            "network_warning_source_lines": sorted(expected_lines),
        },
        "archive": {
            "filename": archive.name,
            "size": archive.stat().st_size,
            "sha256": sha256_file(archive),
        },
        "claims": {
            "lost_original_source_archive_recovered": False,
            "reconstructed_source_claimed": True,
            "exact_shipped_embedded_css_used_as_source_input": True,
            "amd64_equivalence_verified": False,
            "native_arm64_build_verified": False,
            "promotion_allowed": False,
        },
    }
    write_json(output / "reconstruction-lock.json", lock)
    rows = []
    for path in sorted(output.iterdir()):
        if path.is_file() and path.name != "LOCKSUMS.sha256":
            rows.append(f"{sha256_file(path)}  {path.name}\n")
    (output / "LOCKSUMS.sha256").write_text("".join(rows), encoding="utf-8")
    print(json.dumps(lock, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
