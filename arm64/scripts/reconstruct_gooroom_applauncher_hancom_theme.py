#!/usr/bin/env python3
"""Reconstruct the Hancom theme/resource delta from the exact target ELF.

The public drag-and-drop commit is already locked independently.  This tool
recovers only the additional Hancom resource payload and the small theme
selection routine that is evidenced by the target ELF's strings, imports and
control flow.  It fails closed on every source and resource hash.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

BASE_HASHES = {
    "src/applauncher-applet.c": "af3dfe2256be94012a1222617820127dffb348cbb5de54e1cc88b791a15effe0",
    "src/gresource.xml": "1d97ba66690a84d6dafcf3350fc6af3855bcc6cafc13f8696495d8879fe56258",
    "src/applauncher-window.ui": "7047bd4939b2fb26c61b0756efcec1c44452e09ab0a32def97534bd0b71482e1",
    "data/style.css": "8b3c66ec0e5e988c1b2bd26e1b5632ea07cd21a88d247aa83dbc43aec90248ac",
}

RESOURCE_MAP = {
    "/kr/gooroom/applauncher/data/style.css": (
        "data/style.css",
        "161f09162c8046466c78e9ca8f6b57b9a5e96d2d4d98bb0a1ef84d322a755f74",
    ),
    "/kr/gooroom/applauncher/data/style1.css": (
        "data/style1.css",
        "171c9ff3a793565c19be9cc147c4d9018c10349601d7ecf6deabe974254a4ebe",
    ),
    "/kr/gooroom/applauncher/data/style2.css": (
        "data/style2.css",
        "ab3670964260fe29c4cdaf9d680ae12af914ce44d0c12034493c169c8e2e8227",
    ),
    "/kr/gooroom/applauncher/data/style3.css": (
        "data/style3.css",
        "fef990f264dc10e57f9939fc201187003fa934232b302a3b5b496dbdc7962d4d",
    ),
    "/kr/gooroom/applauncher/ui/applauncher-window.ui": (
        "src/applauncher-window.ui",
        "b3f8fde3c39f42bc8a25540cd07037a91ce9cbce9400de168eeba6a2a55c903f",
    ),
}

POST_HASHES = {
    "src/applauncher-applet.c": "c47525b2fcfe37a383c7ad5c45a8836589c911745189112c4a307df796bb105c",
    "src/gresource.xml": "e501c64c55cb6ee9d24973f7f93583b64581c78a76b7a93d7f64d73c36ed079d",
    **{destination: digest for destination, digest in RESOURCE_MAP.values()},
}

PRIVATE_STRUCT_OLD = """struct _GooroomApplauncherAppletPrivate
{
\tGtkWidget         *button;

\tApplauncherWindow *popup_window;
};"""
PRIVATE_STRUCT_NEW = """struct _GooroomApplauncherAppletPrivate
{
\tGtkWidget         *button;
\tGtkSettings       *settings;

\tApplauncherWindow *popup_window;
};"""

THEME_ROUTINES = r'''static void
set_style (GSettings *settings, gchar *icon_theme)
{
	GtkCssProvider *provider;

	provider = gtk_css_provider_new ();

	if (g_strrstr (icon_theme, "style1")) {
		gtk_css_provider_load_from_resource (provider, "/kr/gooroom/applauncher/data/style1.css");
		g_settings_set_string (settings, "gtk-theme", "Arc-Lighter");
	} else if (g_strrstr (icon_theme, "style4")) {
		gtk_css_provider_load_from_resource (provider, "/kr/gooroom/applauncher/data/style2.css");
		g_settings_set_string (settings, "gtk-theme", "Arc-Darker");
	} else if (g_strrstr (icon_theme, "style5")) {
		gtk_css_provider_load_from_resource (provider, "/kr/gooroom/applauncher/data/style3.css");
		g_settings_set_string (settings, "gtk-theme", "Arc-Dark");
	} else if (g_strrstr (icon_theme, "Hancom-Gooroom-Numix-Circle")) {
		gtk_css_provider_load_from_resource (provider, "/kr/gooroom/applauncher/data/style.css");
		g_settings_set_string (settings, "gtk-theme", "Colloid-light");
	} else {
		gtk_css_provider_load_from_resource (provider, "/kr/gooroom/applauncher/data/style.css");
		g_settings_set_string (settings, "gtk-theme", "Flat-Remix-GTK-Blue-Darker");
	}

	gtk_style_context_add_provider_for_screen (gdk_screen_get_default (),
	                                           GTK_STYLE_PROVIDER (provider),
	                                           GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
	g_object_unref (provider);
}

static void
icon_theme_changed_cb (GObject    *object,
                       GParamSpec *pspec,
                       gpointer    data)
{
	GSettings *settings;
	gchar *icon_theme;

	settings = g_settings_new ("org.gnome.desktop.interface");

	if (object) {
		GValue value = G_VALUE_INIT;

		g_value_init (&value, pspec->value_type);
		g_object_get_property (object, pspec->name, &value);
		icon_theme = g_strdup_value_contents (&value);
		g_value_unset (&value);
	} else {
		icon_theme = g_strdup (g_settings_get_string (settings, "icon-theme"));
	}

	set_style (settings, icon_theme);
	g_object_unref (settings);
	g_free (icon_theme);
}

'''


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one match, found {count}")
    return text.replace(old, new)


def run(command: list[str], *, binary: bool = False) -> bytes | str:
    completed = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=not binary,
    )
    if completed.returncode:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n"
            f"stderr: {completed.stderr!r}"
        )
    return completed.stdout


def extract_resources(target_elf: Path, source_dir: Path) -> dict[str, dict[str, object]]:
    evidence: dict[str, dict[str, object]] = {}
    with tempfile.TemporaryDirectory(prefix="applauncher-gresource-") as temporary:
        resource_file = Path(temporary) / "target.gresource"
        run(
            [
                "objcopy",
                "--dump-section",
                f".gresource.applauncher_applet={resource_file}",
                str(target_elf),
            ]
        )
        resource_digest = sha256_file(resource_file)
        if resource_digest != "2abe1443baba5103770ecf92c27dab0d5b5c5443f503ec3ab6c4287b7b77c3a8":
            raise RuntimeError(f"unexpected target GResource digest: {resource_digest}")

        for resource_path, (destination, expected_digest) in RESOURCE_MAP.items():
            payload = run(
                ["gresource", "extract", str(resource_file), resource_path],
                binary=True,
            )
            assert isinstance(payload, bytes)
            actual_digest = sha256_bytes(payload)
            if actual_digest != expected_digest:
                raise RuntimeError(
                    f"resource hash mismatch for {resource_path}: "
                    f"{actual_digest} != {expected_digest}"
                )
            destination_path = source_dir / destination
            destination_path.parent.mkdir(parents=True, exist_ok=True)
            destination_path.write_bytes(payload)
            evidence[resource_path] = {
                "destination": destination,
                "bytes": len(payload),
                "sha256": actual_digest,
            }
    return evidence


def patch_c_source(source_dir: Path) -> None:
    path = source_dir / "src/applauncher-applet.c"
    text = path.read_text(encoding="utf-8")
    text = replace_once(text, PRIVATE_STRUCT_OLD, PRIVATE_STRUCT_NEW, "private struct")
    realize_marker = """static void
gooroom_applauncher_applet_realize (GtkWidget *widget)
"""
    text = replace_once(
        text,
        realize_marker,
        THEME_ROUTINES + realize_marker,
        "theme routine insertion",
    )
    text = replace_once(
        text,
        """\tgtk_container_add (GTK_CONTAINER (applet), priv->button);

\ticon = gtk_image_new_from_icon_name""",
        """\tgtk_container_add (GTK_CONTAINER (applet), priv->button);

\tpriv->settings = gtk_widget_get_settings (GTK_WIDGET (applet));

\ticon = gtk_image_new_from_icon_name""",
        "GtkSettings initialization",
    )
    text = replace_once(
        text,
        """\tgtk_container_add (GTK_CONTAINER (priv->button), icon);

\tg_signal_connect (G_OBJECT (priv->button), \"toggled\",""",
        """\tgtk_container_add (GTK_CONTAINER (priv->button), icon);

\ticon_theme_changed_cb (NULL, NULL, NULL);

\tg_signal_connect (G_OBJECT (priv->button), \"toggled\",""",
        "initial theme application",
    )
    text = replace_once(
        text,
        """\tg_signal_connect (gdk_display_get_default_screen (display), \"monitors-changed\",
                      G_CALLBACK (monitors_changed_cb), applet);

\tGtkCssProvider *provider;
\tprovider = gtk_css_provider_new ();
\tgtk_css_provider_load_from_resource (provider, \"/kr/gooroom/applauncher/data/style.css\");
    gtk_style_context_add_provider_for_screen (gdk_screen_get_default (),
                                               GTK_STYLE_PROVIDER (provider),
                                               GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref (provider);
""",
        """\tg_signal_connect (gdk_display_get_default_screen (display), \"monitors-changed\",
                      G_CALLBACK (monitors_changed_cb), applet);

\tg_signal_connect (priv->settings, \"notify::gtk-icon-theme-name\",
                      G_CALLBACK (icon_theme_changed_cb), NULL);
""",
        "theme signal replacement",
    )
    path.write_text(text, encoding="utf-8")


def patch_gresource_manifest(source_dir: Path) -> None:
    path = source_dir / "src/gresource.xml"
    text = path.read_text(encoding="utf-8")
    old = """\t<file alias=\"gooroom-applauncher-applet\">../data/gooroom-applauncher-applet.svg</file>
\t<file compressed=\"true\" alias=\"style.css\">../data/style.css</file>"""
    new = """\t<file alias=\"gooroom-applauncher-applet\">../data/gooroom-applauncher-applet.svg</file>
\t<file compressed=\"true\" alias=\"style1.css\">../data/style1.css</file>
\t<file compressed=\"true\" alias=\"style2.css\">../data/style2.css</file>
\t<file compressed=\"true\" alias=\"style3.css\">../data/style3.css</file>
\t<file compressed=\"true\" alias=\"style.css\">../data/style.css</file>"""
    path.write_text(
        replace_once(text, old, new, "GResource manifest"),
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--target-elf", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    source_dir = args.source_dir.resolve()
    target_elf = args.target_elf.resolve()
    if not source_dir.is_dir() or not target_elf.is_file():
        raise SystemExit("source directory or target ELF is missing")

    before: dict[str, str] = {}
    for relative, expected in BASE_HASHES.items():
        path = source_dir / relative
        actual = sha256_file(path)
        if actual != expected:
            raise RuntimeError(
                f"base source hash mismatch for {relative}: {actual} != {expected}"
            )
        before[relative] = actual

    resources = extract_resources(target_elf, source_dir)
    patch_c_source(source_dir)
    patch_gresource_manifest(source_dir)

    after: dict[str, str] = {}
    for relative, expected in POST_HASHES.items():
        actual = sha256_file(source_dir / relative)
        if actual != expected:
            raise RuntimeError(
                f"reconstructed source hash mismatch for {relative}: "
                f"{actual} != {expected}"
            )
        after[relative] = actual

    evidence = {
        "schema": 1,
        "reconstruction_complete": True,
        "method": {
            "resources": "exact-target-ELF-GResource-extraction",
            "code": "control-flow-and-import-constrained-C-reconstruction",
        },
        "target_elf": {
            "sha256": sha256_file(target_elf),
            "gresource_section_sha256": "2abe1443baba5103770ecf92c27dab0d5b5c5443f503ec3ab6c4287b7b77c3a8",
        },
        "resources": resources,
        "source_before": before,
        "source_after": after,
        "claims": {
            "source_status": "reconstructed-candidate",
            "binary_validation_status": "not-yet-run",
            "byte_identity_claimed": False,
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
