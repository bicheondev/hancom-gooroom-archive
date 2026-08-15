#!/usr/bin/env python3
"""Replace the hidden Placement submenu reconstruction with exact removal."""
from pathlib import Path

PATH = Path("arm64/scripts/reconstruct_gnome_flashback_han3u4.py")
text = PATH.read_text(encoding="utf-8")

old = '''    # ef9a0790: preserve the Placement submenu machinery and line geometry, but hide its parent item.
    icon_path = hancom / "gnome-flashback/libdesktop/gf-icon-view.c"
    icon_text = icon_path.read_text(encoding="utf-8")
    placement_block = (
        '  item = gtk_menu_item_new_with_label (_("Placement"));\\n'
        '  gtk_menu_shell_append (GTK_MENU_SHELL (popup_menu), item);\\n'
        '  gtk_widget_show (item);\\n\\n'
        '  append_placement_submenu (self, item);\\n\\n'
    )
    hidden_placement_block = (
        '  item = gtk_menu_item_new_with_label (_("Placement"));\\n'
        '  gtk_menu_shell_append (GTK_MENU_SHELL (popup_menu), item);\\n'
        '\\n\\n'
        '  append_placement_submenu (self, item);\\n\\n'
    )
    icon_text = replace_once(
        icon_text,
        placement_block,
        hidden_placement_block,
        "hidden desktop Placement submenu",
    )
    icon_path.write_text(icon_text, encoding="utf-8")
'''
new = '''    # ef9a0790: the shipped ELF has no standalone "Placement" menu-label literal.
    # Remove the parent item and submenu construction, while retaining the underlying
    # placement implementation used elsewhere in the desktop code.
    icon_path = hancom / "gnome-flashback/libdesktop/gf-icon-view.c"
    icon_text = icon_path.read_text(encoding="utf-8")
    placement_block = (
        '  item = gtk_menu_item_new_with_label (_("Placement"));\\n'
        '  gtk_menu_shell_append (GTK_MENU_SHELL (popup_menu), item);\\n'
        '  gtk_widget_show (item);\\n\\n'
        '  append_placement_submenu (self, item);\\n\\n'
    )
    icon_text = replace_once(
        icon_text,
        placement_block,
        "",
        "removed desktop Placement submenu",
    )
    icon_path.write_text(icon_text, encoding="utf-8")
'''
if text.count(old) != 1:
    raise SystemExit(f"Placement reconstruction anchor count: {text.count(old)}")
text = text.replace(old, new)

old_validation = '''    final_icon_text = icon_path.read_text(encoding="utf-8")
    if hidden_placement_block not in final_icon_text:
        raise SystemExit("hidden Placement submenu geometry was not preserved")
    if placement_block in final_icon_text:
        raise SystemExit("Placement submenu parent is still visible")
'''
new_validation = '''    final_icon_text = icon_path.read_text(encoding="utf-8")
    if 'gtk_menu_item_new_with_label (_("Placement"))' in final_icon_text:
        raise SystemExit("Placement submenu parent survived reconstruction")
    if 'append_placement_submenu (self, item);' in final_icon_text:
        raise SystemExit("Placement submenu construction survived reconstruction")
'''
if text.count(old_validation) != 1:
    raise SystemExit(f"Placement validation anchor count: {text.count(old_validation)}")
text = text.replace(old_validation, new_validation)

old_behavior = '                "desktop-placement-submenu-parent-not-shown",\n'
new_behavior = '                "desktop-placement-submenu-removed",\n'
if text.count(old_behavior) != 1:
    raise SystemExit(f"Placement provenance anchor count: {text.count(old_behavior)}")
text = text.replace(old_behavior, new_behavior)

PATH.write_text(text, encoding="utf-8")
