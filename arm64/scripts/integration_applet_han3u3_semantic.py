#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

TARGET_VERSION = "0.3.1+grm3u1+han3u3"
RESOURCE_PREFIX = "/kr/gooroom/IntegrationApplet/ui"
REQUIRED_THEME_STRINGS = [
    "/tmp/.cleanmode",
    "org.gnome.desktop.interface",
    "icon-theme",
    "notify::gtk-icon-theme-name",
    "style1.css",
    "style2.css",
    "style4",
    "style5",
]
REQUIRED_THEME_IMPORTS = [
    "g_object_get_property",
    "g_strdup_value_contents",
    "g_value_unset",
    "gtk_widget_get_settings",
]
FORBIDDEN_VENDOR_STRINGS = ["lbl_cleanmode", "Cleanmode on"]


def run(
    command: list[str],
    *,
    check: bool = True,
    text: bool = False,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess:
    return subprocess.run(
        command,
        check=check,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=text,
    )


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one anchor, found {count}")
    return text.replace(old, new, 1)


def extract_resource(binary: Path, resource_path: str) -> bytes:
    process = run(
        ["gresource", "extract", str(binary), resource_path],
        check=False,
        text=False,
    )
    if process.returncode != 0:
        raise RuntimeError(
            f"failed to extract {resource_path}: "
            + process.stderr.decode("utf-8", errors="replace")[-2000:]
        )
    return process.stdout


def load_style_payload(args: argparse.Namespace, name: str) -> bytes:
    direct = getattr(args, f"{name}_source")
    if direct:
        return Path(direct).read_bytes()
    target_elf = Path(args.target_elf)
    return extract_resource(target_elf, f"{RESOURCE_PREFIX}/{name}.css")


def patch_gresource(source: Path) -> dict[str, Any]:
    path = source / "src/gresource.xml"
    text = path.read_text(encoding="utf-8")
    if "alias=\"style1.css\"" not in text:
        anchor = '\t<file compressed="true" alias="style.css">../data/style.css</file>\n'
        replacement = (
            anchor
            + '\t<file compressed="true" alias="style1.css">../data/style1.css</file>\n'
            + '\t<file compressed="true" alias="style2.css">../data/style2.css</file>\n'
        )
        text = replace_once(text, anchor, replacement, "gresource style list")
        path.write_text(text, encoding="utf-8")
    return {"path": path.relative_to(source).as_posix(), "sha256": sha256_file(path)}


def patch_popup_window(source: Path) -> dict[str, Any]:
    path = source / "src/popup-window.c"
    text = path.read_text(encoding="utf-8")
    declaration = "\tGtkCssProvider\t   *provider;\n"
    if declaration in text:
        text = replace_once(text, declaration, "", "popup provider declaration")
    provider_block = (
        "\n\tprovider = gtk_css_provider_new ();\n"
        '\tgtk_css_provider_load_from_resource (provider, "/kr/gooroom/IntegrationApplet/ui/style.css");\n'
        "\tgtk_style_context_add_provider_for_screen (gdk_screen_get_default (),\n"
        "                                               GTK_STYLE_PROVIDER (provider),\n"
        "                                               GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);\n"
        "\tg_object_unref (provider);\n"
    )
    if provider_block in text:
        text = replace_once(text, provider_block, "", "popup provider block")
    if "GtkCssProvider" in text or "gtk_css_provider_load_from_resource" in text:
        raise RuntimeError("popup-window.c still owns a CSS provider")
    if '#define CLEANMODE "/tmp/.cleanmode"' not in text:
        raise RuntimeError("public gooroom-3.0 Cleanmode popup support is missing")
    if "gtk_widget_override_background_color" not in text:
        raise RuntimeError("public Cleanmode popup background override is missing")
    path.write_text(text, encoding="utf-8")
    return {"path": path.relative_to(source).as_posix(), "sha256": sha256_file(path)}


def patch_datetime(source: Path) -> dict[str, Any]:
    path = source / "modules/datetime/datetime-module.c"
    text = path.read_text(encoding="utf-8")
    statement = "\tgtk_widget_set_can_focus (GTK_WIDGET (priv->control), FALSE);\n"
    if statement not in text:
        anchor = "\tgtk_button_set_relief (GTK_BUTTON (priv->control), GTK_RELIEF_NONE);\n"
        text = replace_once(
            text,
            anchor,
            anchor + statement,
            "datetime context-menu focus policy",
        )
        path.write_text(text, encoding="utf-8")
    return {"path": path.relative_to(source).as_posix(), "sha256": sha256_file(path)}


THEME_FUNCTIONS = r'''
static void
load_icon_theme_css (const gchar *theme)
{
	GtkCssProvider *provider;

	provider = gtk_css_provider_new ();

	if (g_strrstr (theme, "style1")) {
		gtk_css_provider_load_from_resource (provider,
                                           "/kr/gooroom/IntegrationApplet/ui/style1.css");
	} else if (g_strrstr (theme, "style4") || g_strrstr (theme, "style5")) {
		gtk_css_provider_load_from_resource (provider,
                                           "/kr/gooroom/IntegrationApplet/ui/style2.css");
	} else {
		gtk_css_provider_load_from_resource (provider,
                                           "/kr/gooroom/IntegrationApplet/ui/style.css");
	}

	gtk_style_context_add_provider_for_screen (gdk_screen_get_default (),
                                               GTK_STYLE_PROVIDER (provider),
                                               GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
	g_object_unref (provider);
}

static void
icon_theme_name_changed_cb (GObject    *object,
                            GParamSpec *pspec,
                            gpointer    data)
{
	GSettings *settings;
	gchar *theme;

	settings = g_settings_new ("org.gnome.desktop.interface");

	if (object) {
		GValue value = G_VALUE_INIT;

		g_value_init (&value, pspec->value_type);
		g_object_get_property (object, pspec->name, &value);
		theme = g_strdup_value_contents (&value);
		g_value_unset (&value);
	} else {
		theme = g_strdup (g_settings_get_string (settings, "icon-theme"));
	}

	load_icon_theme_css (theme);

	g_object_unref (settings);
	g_free (theme);
}

'''


def patch_applet(source: Path) -> dict[str, Any]:
    path = source / "src/gooroom-integration-applet.c"
    text = path.read_text(encoding="utf-8")

    field = "\tGtkSettings      *settings;\n"
    if field not in text:
        anchor = "\tGtkWidget        *button;\n\n"
        text = replace_once(text, anchor, anchor + field + "\n", "applet settings field")

    if "load_icon_theme_css (const gchar *theme)" not in text:
        anchor = (
            "G_DEFINE_TYPE_WITH_PRIVATE (GooroomIntegrationApplet, "
            "gooroom_integration_applet, GP_TYPE_APPLET)\n\n\n\n"
        )
        text = replace_once(text, anchor, anchor + THEME_FUNCTIONS, "theme helpers")

    assignment = "\tpriv->settings = gtk_widget_get_settings (GTK_WIDGET (applet));\n"
    if assignment not in text:
        anchor = "\tgtk_container_add (GTK_CONTAINER (applet), priv->button);\n"
        text = replace_once(
            text,
            anchor,
            anchor + assignment,
            "initial GtkSettings authority",
        )

    initial_theme = (
        "\n\tGSettings *settings = g_settings_new (\"org.gnome.desktop.interface\");\n"
        "\tgchar *theme = g_strdup (g_settings_get_string (settings, \"icon-theme\"));\n"
        "\tload_icon_theme_css (theme);\n"
        "\tg_object_unref (settings);\n"
        "\tg_free (theme);\n"
    )
    if initial_theme not in text:
        anchor = (
            "\tGtkWidget *user_tray = user_module_tray_new (priv->user_module);\n"
            "\tif (user_tray) {\n"
            "\t\tgtk_box_pack_start (GTK_BOX (hbox), user_tray, FALSE, FALSE, 0);\n"
            "\t}\n"
        )
        text = replace_once(text, anchor, anchor + initial_theme, "initial theme load")

    signal = (
        "\n\tg_signal_connect (G_OBJECT (priv->settings),\n"
        "                      \"notify::gtk-icon-theme-name\",\n"
        "                      G_CALLBACK (icon_theme_name_changed_cb), NULL);\n"
    )
    if signal not in text:
        anchor = (
            "\tg_signal_connect (gdk_display_get_default_screen (display),\n"
            "                      \"monitors-changed\", G_CALLBACK (monitors_changed_cb), applet);\n"
        )
        text = replace_once(text, anchor, anchor + signal, "icon-theme signal")

    applet_markers = [
        value for value in REQUIRED_THEME_STRINGS if value != "/tmp/.cleanmode"
    ] + REQUIRED_THEME_IMPORTS
    for required in applet_markers:
        if required not in text:
            raise RuntimeError(f"applet source is missing semantic marker: {required}")

    path.write_text(text, encoding="utf-8")
    return {"path": path.relative_to(source).as_posix(), "sha256": sha256_file(path)}


def prune_cleanmode_icon(source: Path) -> dict[str, Any]:
    icon = source / "icons/cleanmode.svg"
    removed = False
    if icon.exists():
        icon.unlink()
        removed = True
    makefile = source / "icons/Makefile.am"
    text = makefile.read_text(encoding="utf-8")
    updated = re.sub(
        r"^\s*cleanmode\.svg\s*\\\s*\n",
        "",
        text,
        count=1,
        flags=re.MULTILINE,
    )
    if updated == text and "cleanmode.svg" in text:
        raise RuntimeError("could not remove cleanmode.svg from icons/Makefile.am")
    makefile.write_text(updated, encoding="utf-8")
    return {
        "removed_file": removed,
        "makefile": makefile.relative_to(source).as_posix(),
        "makefile_sha256": sha256_file(makefile),
    }


def patch_source(args: argparse.Namespace) -> int:
    source = Path(args.source).resolve()
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)

    style_rows = []
    for name in ("style1", "style2"):
        payload = load_style_payload(args, name)
        destination = source / "data" / f"{name}.css"
        destination.write_bytes(payload)
        style_rows.append(
            {
                "resource": f"{RESOURCE_PREFIX}/{name}.css",
                "source_path": destination.relative_to(source).as_posix(),
                "size": len(payload),
                "sha256": sha256_bytes(payload),
            }
        )

    rows = {
        "gresource": patch_gresource(source),
        "popup_window": patch_popup_window(source),
        "datetime": patch_datetime(source),
        "applet": patch_applet(source),
        "cleanmode_icon": prune_cleanmode_icon(source),
    }

    user_module = source / "modules/user/user-module.c"
    user_text = user_module.read_text(encoding="utf-8")
    old_user_selected = "lbl_cleanmode" not in user_text and "CLEANMODE" not in user_text
    if args.require_old_user and not old_user_selected:
        raise RuntimeError("hybrid candidate did not select the old Hancom user module")

    report = {
        "schema": 1,
        "source": "gooroom-integration-applet",
        "target_version": TARGET_VERSION,
        "candidate_label": args.candidate_label,
        "base_commit_sha": args.base_commit,
        "user_source_commit_sha": args.user_source_commit,
        "old_user_module_selected": old_user_selected,
        "style_resources": style_rows,
        "patched_files": rows,
        "semantic_policy": [
            "gooroom-3.0-0.3.5-base",
            "exact-target-mapped-resources-icons-locales-and-changelog",
            "exact-target-style1-style2-gresources",
            "hancom-context-menu-unfocusable-datetime-control",
            "hancom-runtime-icon-theme-css-switching",
            "target-payload-cleanmode-icon-pruned",
        ],
    }
    output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0


def extract_deb(deb: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    run(["dpkg-deb", "-x", str(deb), str(destination)])


def find_unique(root: Path, name: str) -> Path:
    matches = sorted(path for path in root.rglob(name) if path.is_file())
    if len(matches) != 1:
        raise RuntimeError(f"expected one {name}, found {len(matches)} below {root}")
    return matches[0]


def is_elf(path: Path) -> bool:
    return path.is_file() and path.read_bytes()[:4] == b"\x7fELF"


def payload_inventory(root: Path, *, include_elf: bool) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            result[relative] = {"kind": "symlink", "target": os.readlink(path)}
        elif path.is_file() and (include_elf or not is_elf(path)):
            result[relative] = {
                "kind": "elf" if is_elf(path) else "file",
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
            }
    return result


def dyn_symbols(path: Path) -> tuple[dict[str, dict[str, Any]], set[str]]:
    output = run(["readelf", "--dyn-syms", "-W", str(path)], text=True).stdout
    defined: dict[str, dict[str, Any]] = {}
    imports: set[str] = set()
    pattern = re.compile(
        r"^\s*\d+:\s+([0-9a-fA-F]+)\s+(\d+)\s+FUNC\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+?)\s*$"
    )
    for line in output.splitlines():
        match = pattern.match(line)
        if not match:
            continue
        value_text, size_text, bind, visibility, section, raw_name = match.groups()
        name = raw_name.split("@", 1)[0]
        if not name:
            continue
        if section == "UND":
            imports.add(name)
        elif int(value_text, 16):
            defined[name] = {
                "address": int(value_text, 16),
                "size": int(size_text),
                "bind": bind,
                "visibility": visibility,
            }
    return defined, imports


def function_fingerprint(path: Path, address: int, size: int) -> dict[str, Any]:
    process = run(
        [
            "objdump",
            "-d",
            "-M",
            "intel",
            "--no-show-raw-insn",
            f"--start-address={address}",
            f"--stop-address={address + size}",
            str(path),
        ],
        text=True,
    )
    mnemonics: list[str] = []
    calls: list[str] = []
    for line in process.stdout.splitlines():
        match = re.match(
            r"^\s*[0-9a-fA-F]+:\s+([a-zA-Z][a-zA-Z0-9.]*)\s*(.*)$",
            line,
        )
        if not match:
            continue
        mnemonic, operands = match.groups()
        mnemonics.append(mnemonic)
        if mnemonic.startswith("call"):
            symbol = re.search(r"<([^>]+)>", operands)
            if symbol:
                target = symbol.group(1).split("+", 1)[0].split("@", 1)[0]
            else:
                target = "indirect"
            calls.append(target)
    return {
        "mnemonic_sha256": sha256_bytes("\n".join(mnemonics).encode()),
        "call_sequence": calls,
        "instruction_count": len(mnemonics),
    }


def resource_inventory(binary: Path) -> dict[str, dict[str, Any]]:
    process = run(["gresource", "list", str(binary)], check=False, text=True)
    if process.returncode != 0:
        return {}
    result: dict[str, dict[str, Any]] = {}
    for resource_path in sorted(
        line.strip() for line in process.stdout.splitlines() if line.strip()
    ):
        payload = extract_resource(binary, resource_path)
        result[resource_path] = {
            "size": len(payload),
            "sha256": sha256_bytes(payload),
        }
    return result


def string_set(path: Path) -> set[str]:
    process = run(["strings", "-a", "-n", "4", str(path)], text=True)
    return set(process.stdout.splitlines())


def compare_elf(target: Path, candidate: Path) -> dict[str, Any]:
    target_defined, target_imports = dyn_symbols(target)
    candidate_defined, candidate_imports = dyn_symbols(candidate)
    function_rows = []
    for name in sorted(set(target_defined) | set(candidate_defined)):
        left = target_defined.get(name)
        right = candidate_defined.get(name)
        row: dict[str, Any] = {"name": name, "target": left, "candidate": right}
        if left and right:
            left_fingerprint = function_fingerprint(
                target, left["address"], left["size"]
            )
            right_fingerprint = function_fingerprint(
                candidate, right["address"], right["size"]
            )
            row.update(
                {
                    "size_equal": left["size"] == right["size"],
                    "mnemonic_equal": (
                        left_fingerprint["mnemonic_sha256"]
                        == right_fingerprint["mnemonic_sha256"]
                    ),
                    "call_sequence_equal": (
                        left_fingerprint["call_sequence"]
                        == right_fingerprint["call_sequence"]
                    ),
                    "target_fingerprint": left_fingerprint,
                    "candidate_fingerprint": right_fingerprint,
                }
            )
        else:
            row.update(
                {
                    "size_equal": False,
                    "mnemonic_equal": False,
                    "call_sequence_equal": False,
                }
            )
        function_rows.append(row)

    target_resources = resource_inventory(target)
    candidate_resources = resource_inventory(candidate)
    resource_rows = []
    for name in sorted(set(target_resources) | set(candidate_resources)):
        left = target_resources.get(name)
        right = candidate_resources.get(name)
        resource_rows.append(
            {"path": name, "target": left, "candidate": right, "equal": left == right}
        )

    target_strings = string_set(target)
    candidate_strings = string_set(candidate)
    return {
        "target_path": str(target),
        "candidate_path": str(candidate),
        "target_sha256": sha256_file(target),
        "candidate_sha256": sha256_file(candidate),
        "target_size": target.stat().st_size,
        "candidate_size": candidate.stat().st_size,
        "absolute_size_delta": abs(target.stat().st_size - candidate.stat().st_size),
        "defined_function_count": {
            "target": len(target_defined),
            "candidate": len(candidate_defined),
        },
        "defined_function_size_difference_count": sum(
            not row["size_equal"] for row in function_rows
        ),
        "mnemonic_difference_count": sum(
            not row["mnemonic_equal"] for row in function_rows
        ),
        "call_sequence_difference_count": sum(
            not row["call_sequence_equal"] for row in function_rows
        ),
        "different_functions": [
            row
            for row in function_rows
            if not (
                row["size_equal"]
                and row["mnemonic_equal"]
                and row["call_sequence_equal"]
            )
        ],
        "target_only_imports": sorted(target_imports - candidate_imports),
        "candidate_only_imports": sorted(candidate_imports - target_imports),
        "import_difference_count": len(target_imports ^ candidate_imports),
        "resource_count": {
            "target": len(target_resources),
            "candidate": len(candidate_resources),
        },
        "resource_difference_count": sum(
            not row["equal"] for row in resource_rows
        ),
        "different_resources": [row for row in resource_rows if not row["equal"]],
        "missing_required_theme_strings": [
            value
            for value in REQUIRED_THEME_STRINGS
            if not any(value in item for item in candidate_strings)
        ],
        "missing_required_theme_imports": [
            value for value in REQUIRED_THEME_IMPORTS if value not in candidate_imports
        ],
        "forbidden_vendor_strings_present": [
            value
            for value in FORBIDDEN_VENDOR_STRINGS
            if any(value in item for item in candidate_strings)
        ],
        "target_only_semantic_strings": sorted(
            item
            for item in target_strings - candidate_strings
            if any(
                token in item
                for token in (
                    "clean",
                    "style",
                    "theme",
                    "IntegrationApplet",
                    "gtk_",
                    "g_value",
                    "g_string",
                )
            )
        )[:500],
        "candidate_only_semantic_strings": sorted(
            item
            for item in candidate_strings - target_strings
            if any(
                token in item
                for token in (
                    "clean",
                    "style",
                    "theme",
                    "IntegrationApplet",
                    "gtk_",
                    "g_value",
                    "g_string",
                    "tablet",
                )
            )
        )[:500],
    }


def compare_packages(args: argparse.Namespace) -> int:
    target_deb = Path(args.target_deb).resolve()
    candidate_deb = Path(args.candidate_deb).resolve()
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        target_root = root / "target"
        candidate_root = root / "candidate"
        extract_deb(target_deb, target_root)
        extract_deb(candidate_deb, candidate_root)

        target_non_elf = payload_inventory(target_root, include_elf=False)
        candidate_non_elf = payload_inventory(candidate_root, include_elf=False)
        payload_rows = []
        for path in sorted(set(target_non_elf) | set(candidate_non_elf)):
            left = target_non_elf.get(path)
            right = candidate_non_elf.get(path)
            payload_rows.append(
                {"path": path, "target": left, "candidate": right, "equal": left == right}
            )

        main = compare_elf(
            find_unique(target_root, "libgooroom-integration-applet.so"),
            find_unique(candidate_root, "libgooroom-integration-applet.so"),
        )
        nimf = compare_elf(
            find_unique(target_root, "libnimf-gooroom.so"),
            find_unique(candidate_root, "libnimf-gooroom.so"),
        )
        non_elf_difference_count = sum(
            not row["equal"] for row in payload_rows
        )
        semantic_marker_difference_count = (
            len(main["missing_required_theme_strings"])
            + len(main["missing_required_theme_imports"])
            + len(main["forbidden_vendor_strings_present"])
        )
        rank = [
            non_elf_difference_count,
            main["resource_difference_count"]
            + nimf["resource_difference_count"],
            main["defined_function_size_difference_count"]
            + nimf["defined_function_size_difference_count"],
            main["import_difference_count"] + nimf["import_difference_count"],
            main["call_sequence_difference_count"]
            + nimf["call_sequence_difference_count"],
            main["mnemonic_difference_count"]
            + nimf["mnemonic_difference_count"],
            semantic_marker_difference_count,
            main["absolute_size_delta"] + nimf["absolute_size_delta"],
        ]
        strong_semantic_match = (
            rank[0] == 0
            and rank[1] == 0
            and rank[2] == 0
            and rank[3] == 0
            and rank[4] == 0
            and semantic_marker_difference_count == 0
        )
        summary = {
            "schema": 1,
            "source": "gooroom-integration-applet",
            "target_version": TARGET_VERSION,
            "candidate_label": args.candidate_label,
            "candidate_commit_sha": args.candidate_commit,
            "user_source_commit_sha": args.user_source_commit,
            "target_deb_sha256": sha256_file(target_deb),
            "candidate_deb_sha256": sha256_file(candidate_deb),
            "non_elf_difference_count": non_elf_difference_count,
            "different_non_elf_payload": [
                row for row in payload_rows if not row["equal"]
            ],
            "main_elf": main,
            "nimf_elf": nimf,
            "semantic_marker_difference_count": semantic_marker_difference_count,
            "comparison_rank": rank,
            "strong_semantic_match": strong_semantic_match,
        }
        (output / "summary.json").write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        (output / "non-elf-comparison.json").write_text(
            json.dumps(payload_rows, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    return 0


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    commands = root.add_subparsers(dest="command", required=True)

    patch = commands.add_parser("patch")
    patch.add_argument("--source", required=True)
    patch.add_argument("--target-elf")
    patch.add_argument("--style1-source")
    patch.add_argument("--style2-source")
    patch.add_argument("--output", required=True)
    patch.add_argument("--candidate-label", required=True)
    patch.add_argument("--base-commit", required=True)
    patch.add_argument("--user-source-commit", required=True)
    patch.add_argument("--require-old-user", action="store_true")
    patch.set_defaults(function=patch_source)

    compare = commands.add_parser("compare")
    compare.add_argument("--target-deb", required=True)
    compare.add_argument("--candidate-deb", required=True)
    compare.add_argument("--output", required=True)
    compare.add_argument("--candidate-label", required=True)
    compare.add_argument("--candidate-commit", required=True)
    compare.add_argument("--user-source-commit", required=True)
    compare.set_defaults(function=compare_packages)
    return root


def main() -> int:
    args = parser().parse_args()
    if args.command == "patch" and not (
        args.target_elf or (args.style1_source and args.style2_source)
    ):
        raise SystemExit(
            "patch requires --target-elf or both --style1-source/--style2-source"
        )
    return int(args.function(args))


if __name__ == "__main__":
    raise SystemExit(main())
