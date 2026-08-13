#!/usr/bin/env python3
"""Apply the final three ELF-confirmed gooroom-guide source deltas."""

from __future__ import annotations

import hashlib
from pathlib import Path

TARGET = Path("arm64/scripts/reconstruct_gooroom_guide_han3u1.py")
EXPECTED_BLOB = "a9f9f0fc0995f2d2a8f93e9ce3302d2542afd3bb"


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one anchor, found {count}")
    return text.replace(old, new)


def main() -> int:
    payload = TARGET.read_bytes()
    actual = hashlib.sha1(f"blob {len(payload)}\0".encode() + payload).hexdigest()
    if actual != EXPECTED_BLOB:
        raise SystemExit(f"unexpected reconstruction blob: {actual}")
    text = payload.decode("utf-8")

    text = replace_once(
        text,
        '    "src/guide-window.c",\n    "src/data/guide-window.ui",\n',
        '    "src/guide-window.c",\n    "src/guide-utils.h",\n    "src/data/guide-window.ui",\n',
        "bounded guide-utils path",
    )

    constants = '''CLASS_INIT_ORDER_BLOCK = """  GtkWidgetClass *widget_class = GTK_WIDGET_CLASS (class);\n  GObjectClass *object_class = G_OBJECT_CLASS (class);\n"""\nTARGET_CLASS_INIT_ORDER_BLOCK = """  GObjectClass *object_class = G_OBJECT_CLASS (class);\n  GtkWidgetClass *widget_class = GTK_WIDGET_CLASS (class);\n"""\nCONSTRUCTED_SELF_BLOCK = """  GuideWindow *self = GUIDE_WINDOW (obj);\n  GtkRequisition req;\n"""\nTARGET_CONSTRUCTED_SELF_BLOCK = """  GuideWindow *self;\n  GtkRequisition req;\n"""\nCONSTRUCTED_PARENT_BLOCK = """  G_OBJECT_CLASS (guide_window_parent_class)->constructed (obj);\n\n  display = gdk_display_get_default ();\n"""\nTARGET_CONSTRUCTED_PARENT_BLOCK = """  G_OBJECT_CLASS (guide_window_parent_class)->constructed (obj);\n  self = GUIDE_WINDOW (obj);\n\n  display = gdk_display_get_default ();\n"""\nHEADER_PROTOTYPE_BLOCK = "gchar *     get_norun_file_path ();\\n"\nTARGET_HEADER_PROTOTYPE_BLOCK = "gchar *     get_norun_file_path (void);\\n"\n'''
    text = replace_once(
        text,
        '\nCONSTRUCTOR_BLOCK = """',
        '\n' + constants + 'CONSTRUCTOR_BLOCK = """',
        "ELF-confirmed source constants",
    )

    entries = '''        (\n            CLASS_INIT_ORDER_BLOCK,\n            TARGET_CLASS_INIT_ORDER_BLOCK,\n            "GObject and widget class initialization order",\n        ),\n        (\n            CONSTRUCTED_SELF_BLOCK,\n            TARGET_CONSTRUCTED_SELF_BLOCK,\n            "deferred GuideWindow cast declaration",\n        ),\n        (\n            CONSTRUCTED_PARENT_BLOCK,\n            TARGET_CONSTRUCTED_PARENT_BLOCK,\n            "parent construction before GuideWindow cast",\n        ),\n'''
    text = replace_once(
        text,
        '        (\n            FINALIZE_BLOCK,\n',
        entries + '        (\n            FINALIZE_BLOCK,\n',
        "ELF-confirmed guide-window replacements",
    )

    header_patch = '''\n    source_h = repository / "src/guide-utils.h"\n    source_h_text = source_h.read_text(encoding="utf-8")\n    if source_h_text.count(HEADER_PROTOTYPE_BLOCK) != 1:\n        raise SystemExit("get_norun_file_path prototype anchor was not found exactly once")\n    source_h_text = source_h_text.replace(\n        HEADER_PROTOTYPE_BLOCK, TARGET_HEADER_PROTOTYPE_BLOCK\n    )\n    source_h.write_text(source_h_text, encoding="utf-8")\n'''
    text = replace_once(
        text,
        '    source_c.write_text(source_text, encoding="utf-8")\n\n    source_ui =',
        '    source_c.write_text(source_text, encoding="utf-8")\n'
        + header_patch
        + '\n    source_ui =',
        "guide-utils prototype reconstruction",
    )

    text = replace_once(
        text,
        '                EXPECTED_CHANGED_PATHS - {"src/data/guide-window.ui"}\n',
        '                EXPECTED_CHANGED_PATHS\n'
        '                - {"src/data/guide-window.ui", "src/guide-utils.h"}\n',
        "stable historical changed-path count",
    )
    text = replace_once(
        text,
        '            "elf_confirmed_changed_paths": [\n'
        '                "src/data/guide-window.ui",\n'
        '            ],\n',
        '            "elf_confirmed_changed_paths": [\n'
        '                "src/data/guide-window.ui",\n'
        '                "src/guide-utils.h",\n'
        '            ],\n',
        "ELF-confirmed path evidence",
    )
    text = replace_once(
        text,
        '            "elf_confirmed_runtime_anchors_verified": True,\n',
        '            "elf_confirmed_runtime_anchors_verified": True,\n'
        '            "elf_confirmed_header_prototype_verified": True,\n',
        "header prototype evidence",
    )

    TARGET.write_text(text, encoding="utf-8")
    print(TARGET)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
