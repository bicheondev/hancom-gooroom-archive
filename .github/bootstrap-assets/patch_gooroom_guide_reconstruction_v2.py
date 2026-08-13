#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

RECONSTRUCTION = Path("arm64/scripts/reconstruct_gooroom_guide_han3u1.py")
WORKFLOW = Path(".github/workflows/arm64-reconstruct-build-promote-gooroom-guide-han3u1.yml")


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if new in text and old not in text:
        return text
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one old anchor, found {count}")
    return text.replace(old, new, 1)


def main() -> int:
    source = RECONSTRUCTION.read_text(encoding="utf-8")

    source = replace_once(
        source,
        '''changes described by its packaged changelog: source cleanup, removal of the\nduplicate GtkOverlay insertion, and the Hancom Gooroom 3.3 guide contents.\n''',
        '''changes described by its packaged changelog and independently confirmed by the\nexact shipped AMD64 ELF: source cleanup, runtime correctness fixes, removal of the\nduplicate GtkOverlay insertion, and the Hancom Gooroom 3.3 guide contents.\n''',
        "module description",
    )

    constant_anchor = '''OVERLAY_BLOCK = """\n\n  gtk_overlay_add_overlay (GTK_OVERLAY(self->guide_overlay), self->bar_stack);\n"""\n'''
    constants = constant_anchor + '''PIXBUF_CALL_BLOCK = """  pixbuf = gdk_pixbuf_new_from_file (uri,error);\n"""\nTARGET_PIXBUF_CALL_BLOCK = """  pixbuf = gdk_pixbuf_new_from_file (uri, &error);\n"""\nWINDOW_MOVE_BLOCK = """  gtk_window_move (self,point.x ,point.y );\n"""\nTARGET_WINDOW_MOVE_BLOCK = """  gtk_window_move (self,point.x ,point.y );\n  g_timeout_add (100, guide_window_present, self);\n"""\nCONSTRUCTOR_BLOCK = """  return g_object_new (GUIDE_WINDOW_TYPE,\n                       \"application\", app,\n                       \"resizable\", FALSE,\n                       \"title\", _(\"Hancom Gooroom Guide\"),\n                       \"icon-name\", \"gooroom-guide\",\n                       \"window-position\", GTK_WIN_POS_CENTER,\n                       \"show-menubar\", FALSE,\n                       NULL);\n"""\nTARGET_CONSTRUCTOR_BLOCK = """  return g_object_new (GUIDE_WINDOW_TYPE,\n                       \"application\", app,\n                       \"resizable\", FALSE,\n                       \"icon-name\", \"gooroom-guide\",\n                       NULL);\n"""\nUI_HEADER_BLOCK = """        <property name=\"title\" translatable=\"yes\">Hancom Gooroom Quick Guide</property>\n        <property name=\"has-subtitle\">False</property>\n        <property name=\"spacing\">0</property>\n"""\nTARGET_UI_HEADER_BLOCK = """        <property name=\"title\" translatable=\"yes\">Hancom Gooroom Guide</property>\n        <property name=\"has-subtitle\">False</property>\n        <property name=\"spacing\">0</property>\n        <property name=\"show-close-button\">True</property>\n"""\n'''
    source = replace_once(source, constant_anchor, constants, "source anchors")

    source = replace_once(
        source,
        '''    "src/guide-window.c",\n    "data/guide/toc.json",\n''',
        '''    "src/guide-window.c",\n    "src/data/guide-window.ui",\n    "data/guide/toc.json",\n''',
        "bounded path set",
    )

    old_transform = '''    source_c = repository / "src/guide-window.c"\n    source_text = source_c.read_text(encoding="utf-8")\n    if source_text.count(DIMENSION_BLOCK) != 1:\n        raise SystemExit("duplicate dimension-block anchor was not found exactly once")\n    if source_text.count(OVERLAY_BLOCK) != 1:\n        raise SystemExit("GtkOverlay insertion anchor was not found exactly once")\n    source_text = source_text.replace(DIMENSION_BLOCK, CLEAN_DIMENSION_BLOCK)\n    source_text = source_text.replace(OVERLAY_BLOCK, "")\n    source_c.write_text(source_text, encoding="utf-8")\n'''
    new_transform = '''    source_c = repository / "src/guide-window.c"\n    source_text = source_c.read_text(encoding="utf-8")\n    source_replacements = (\n        (\n            DIMENSION_BLOCK,\n            CLEAN_DIMENSION_BLOCK,\n            "duplicate dimension-block",\n        ),\n        (\n            OVERLAY_BLOCK,\n            "",\n            "duplicate GtkOverlay insertion",\n        ),\n        (\n            PIXBUF_CALL_BLOCK,\n            TARGET_PIXBUF_CALL_BLOCK,\n            "GError pointer handoff",\n        ),\n        (\n            WINDOW_MOVE_BLOCK,\n            TARGET_WINDOW_MOVE_BLOCK,\n            "delayed window presentation",\n        ),\n        (\n            CONSTRUCTOR_BLOCK,\n            TARGET_CONSTRUCTOR_BLOCK,\n            "constructor property cleanup",\n        ),\n    )\n    for old, new, label in source_replacements:\n        if source_text.count(old) != 1:\n            raise SystemExit(f"{label} anchor was not found exactly once")\n        source_text = source_text.replace(old, new)\n    source_c.write_text(source_text, encoding="utf-8")\n\n    source_ui = repository / "src/data/guide-window.ui"\n    ui_text = source_ui.read_text(encoding="utf-8")\n    if ui_text.count(UI_HEADER_BLOCK) != 1:\n        raise SystemExit("embedded guide header anchor was not found exactly once")\n    ui_text = ui_text.replace(UI_HEADER_BLOCK, TARGET_UI_HEADER_BLOCK)\n    source_ui.write_text(ui_text, encoding="utf-8")\n'''
    source = replace_once(source, old_transform, new_transform, "source transformation")

    source = replace_once(
        source,
        '"policy": "minimal-source-cleanup-plus-exact-shipped-static-guide-assets",',
        '"policy": "minimal-source-cleanup-plus-elf-confirmed-runtime-fixes-plus-exact-shipped-guide-assets",',
        "reconstruction policy",
    )

    source = replace_once(
        source,
        '''            "source_cleanup_anchors_verified": True,\n            "removed_obsolete_path": "data/guide/toc.json",\n''',
        '''            "source_cleanup_anchors_verified": True,\n            "elf_confirmed_runtime_anchors_verified": True,\n            "embedded_ui_relationship_verified": True,\n            "removed_obsolete_path": "data/guide/toc.json",\n''',
        "evidence fields",
    )

    RECONSTRUCTION.write_text(source, encoding="utf-8")

    workflow = WORKFLOW.read_text(encoding="utf-8")
    workflow = replace_once(
        workflow,
        "and (.reconstruction.changed_paths | length) == 23",
        "and (.reconstruction.changed_paths | length) == 24",
        "workflow changed-path count",
    )
    WORKFLOW.write_text(workflow, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
