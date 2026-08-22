#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

STYLE_RESOURCES = {
    "style1.css": "/kr/gooroom/IntegrationApplet/ui/style1.css",
    "style2.css": "/kr/gooroom/IntegrationApplet/ui/style2.css",
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one anchor, found {count}")
    return text.replace(old, new, 1)


def extract_resource(binary: Path, resource: str) -> bytes:
    process = subprocess.run(
        ["gresource", "extract", str(binary), resource],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if process.returncode != 0 or not process.stdout:
        raise RuntimeError(
            f"failed to extract {resource}: "
            f"{process.stderr.decode('utf-8', errors='replace')[-1000:]}"
        )
    return process.stdout


def patch_main(source: Path) -> list[str]:
    path = source / "src/goorom-integration-applet.c"
    text = path.read_text(encoding="utf-8")

    text = replace_once(
        text,
        "\tGtkWidget        *button;\n\n\tUserModule       *user_module;",
        "\tGtkWidget        *button;\n\tGtkSettings      *settings;\n\n\tUserModule       *user_module;",
        "private settings member",
    )

    anchor = """\n\nstatic void
gooroom_integration_applet_finalize (GObject *object)\n"""
    theme_block = """\nstatic void
set_style_from_theme (GSettings *settings, gchar *str)
{
\tGtkCssProvider *provider;\nprovider = gtk_css_provider_new ();
\nif (g_strrstr (str, \"style1\"))\n\tgtk_css_provider_load_from_resource (provider, \"/kr/gooroom/IntegrationApplet/ui/style1.css\");\n\nelse if (g_strrstr (str, \"style4\") || g_strrstr (str, \"style5\"))\n\tgtk_css_provider_load_from_resource (provider, \"/kr/gooroom/IntegrationApplet/ui/style2.css\");\n\nelse\n\tgtk_css_provider_load_from_resource (provider, \"/kr/gooroom/IntegrationApplet/ui/style.css\");\n\ngtk_style_context_add_provider_for_screen (gdk_screen_get_default (),\n\t                                           GTK_STYLE_PROVIDER (provider),\n\t                                           GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);\ng_object_unref (provider);\n}\n\nstatic void
theme_property_notified (GObject    *object,\n                         GParamSpec *pspec,\n                         gpointer    data)
{\ngchar *str;\nGSettings *settings;\n\nsettings = g_settings_new (\"org.gnome.desktop.interface\");\n\nif (object) {\n\tGValue value = G_VALUE_INIT;\n\tg_value_init (&value, pspec->value_type);\n\tg_object_get_property (object, pspec->name, &value);\n\tstr = g_strdup_value_contents (&value);\n\tg_value_unset (&value);\n} else {\n\tstr = g_strdup (g_settings_get_string (settings, \"icon-theme\"));\n\n}\nset_style_from_theme (settings, str);\n\ng_object_unref (settings);\ng_free (str);\n}\n\nstatic void
gooroom_integration_applet_finalize (GObject *object)\n"""
    text = replace_once(text, anchor, theme_block, "theme callback block")

    text = replace_once(
        text,
        "\tgtk_container_add (GTK_CONTAINER (applet), priv->button);\n\tgtk_widget_show (priv->button);",
        "\tgtk_container_add (GTK_CONTAINER (applet), priv->button);\n"
        "\tpriv->settings = gtk_widget_get_settings (GTK_WIDGET (applet));\n"
        "\tgtk_widget_show (priv->button);",
        "settings initialization",
    )

    text = replace_once(
        text,
        "\tif (user_tray) {\n\t\tgtk_box_pack_start (GTK_BOX (hbox), user_tray, FALSE, FALSE, 0);\n\t}\n\n"
        "\tg_signal_connect (G_OBJECT (priv->button), \"toggled\"",
        "\tif (user_tray) {\n\t\tgtk_box_pack_start (GTK_BOX (hbox), user_tray, FALSE, FALSE, 0);\n}\n\n"
        "\ttheme_property_notified (NULL, NULL, NULL);\n\n"
        "\tg_signal_connect (G_OBJECT (priv->button), \"toggled\"",
        "initial theme application",
    )

    text = replace_once(
        text,
        "\tg_signal_connect (gdk_display_get_default_screen (display),\n"
        "                      \"monitors-changed\", G_CALLBACK (monitors_changed_cb), applet);\n}",
        "\tg_signal_connect (gdk_display_get_default_screen (display),\n"
        "                      \"monitors-changed\", G_CALLBACK (monitors_changed_cb), applet);\n"
        "\tg_signal_connect (priv->settings, \"notify::gtk-icon-theme-name\",\n"
        "                      G_CALLBACK (theme_property_notified), NULL);\n}",
        "theme change signal",
    )

    path.write_text(text, encoding="utf-8")
    return [path.relative_to(source).as_posix()]


def patch_datetime(source: Path) -> list[str]:
    path = source / "modules/datetime/datetime-module.c"
    text = path.read_text(encoding="utf-8")
    text = replace_once(
        text,
        "\tpriv->control = gtk_button_new ();\n"
        "\tgtk_button_set_relief (GTK_BUTTON (priv->control), GTK_RELIEF_NONE);\n",
        "\tpriv->control = gtk_button_new ();\n"
        "\tgtk_button_set_relief (GTK_BUTTON (priv->control), GTK_RELIEF_NONE);\n"
        "\tgtk_widget_set_can_focus (priv->control, FALSE);\n",
        "datetime focus policy",
    )
    path.write_text(text, encoding="utf-8")
    return [path.relative_to(source).as_posix()]


def patch_popup(source: Path) -> list[str]:
    path = source / "src/popup-window.c"
    text = path.read_text(encoding="utf-8")
    text = replace_once(
        text,
        "\t\tcase CONTROL_TYPE_USER:\n\t\t{\n"
        "\t\t\tgtk_box_pack_start (GTK_BOX (priv->box_user), control, TRUE, FALSE, 0);",
        "\t\tcase CONTROL_TYPE_USER:\n\t\t{\n"
        "\t\t\tif (g_file_test (\"/tmp/.cleanmode\", G_FILE_TEST_EXISTS)) {\n"
        "\t\t\t\tGdkRGBA color = { 0.0, 0.0, 0.0, 0.5 };\n"
        "\t\t\t\tgtk_widget_override_background_color (priv->box_user, GTK_STATE_FLAG_NORMAL, &color);\n"
        "\t\t\t}\n"
        "\t\t\tgtk_box_pack_start (GTK_BOX (priv->box_user), control, TRUE, FALSE, 0);",
        "clean mode user background",
    )
    path.write_text(text, encoding="utf-8")
    return [path.relative_to(source).as_posix()]


def patch_resources(source: Path, target_main: Path, resource_root: Path | None = None) -> tuple[list[str], list[dict[str, object]]]:
    changed: list[str] = []
    rows: list[dict[str, object]] = []
    data_dir = source / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    for name, resource in STYLE_RESOURCES.items():
        if resource_root is not None:
            fallback = resource_root / resource.lstrip("/")
            if not fallback.is_file():
                raise RuntimeError(f"fallback resource is missing: {fallback}")
            data = fallback.read_bytes()
        else:
            data = extract_resource(target_main, resource)
        path = data_dir / name
        previous = path.read_bytes() if path.exists() else None
        path.write_bytes(data)
        changed.append(path.relative_to(source).as_posix())
        rows.append(
            {
                "name": name,
                "resource": resource,
                "size": len(data),
                "sha256": sha256(data),
                "previous_sha256": sha256(previous) if previous is not None else None,
            }
        )

    manifest = source / "src/gresource.xml"
    text = manifest.read_text(encoding="utf-8")
    old = '\t<file compressed="true" alias="style.css">../data/style.css</file>'
    new = (
        old
        + '\n\t<file compressed="true" alias="style1.css">../data/style1.css</file>'
        + '\n\t<file compressed="true" alias="style2.css">../data/style2.css</file>'
    )
    text = replace_once(text, old, new, "style resource manifest")
    manifest.write_text(text, encoding="utf-8")
    changed.append(manifest.relative_to(source).as_posix())
    return changed, rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--target-main", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--resource-root", type=Path)
    args = parser.parse_args()

    source = args.source.resolve()
    target_main = args.target_main.resolve()
    if not source.is_dir() or not target_main.is_file():
        raise RuntimeError("source tree or target ELF is missing")

    changed: list[str] = []
    changed += patch_main(source)
    changed += patch_datetime(source)
    changed += patch_popup(source)
    resource_paths, resource_rows = patch_resources(source, target_main, args.resource_root.resolve() if args.resource_root else None)
    changed += resource_paths

    unique = sorted(set(changed))
    report = {
        "schema": 1,
        "source": "gooroom-integration-applet",
        "version": "0.3.1+grm3u1+han3u3",
        "policy": "dwarf-and-exact-target-resource-guided-han3u3-reconstruction-v5",
        "changed_paths": unique,
        "resource_rows": resource_rows,
        "target_main_sha256": sha256(target_main.read_bytes()),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
