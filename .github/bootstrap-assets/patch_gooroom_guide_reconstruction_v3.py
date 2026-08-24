#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

RECONSTRUCTION = Path("arm64/scripts/reconstruct_gooroom_guide_han3u1.py")


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if new in text and old not in text:
        return text
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one old anchor, found {count}")
    return text.replace(old, new, 1)


def main() -> int:
    source = RECONSTRUCTION.read_text(encoding="utf-8")

    pixbuf_anchor = '''TARGET_PIXBUF_CALL_BLOCK = """  pixbuf = gdk_pixbuf_new_from_file (uri, &error);\n"""\n'''
    pixbuf_constants = pixbuf_anchor + '''LOAD_IMAGE_PRESENT_BLOCK = """  set_page_label(self);\n  guide_window_present(self);\n"""\nTARGET_LOAD_IMAGE_PRESENT_BLOCK = """  set_page_label(self);\n  g_object_unref (pixbuf);\n"""\nACCEL_INIT_BLOCK = """  guide_window_accel_init (self, NULL);\n"""\nTARGET_ACCEL_INIT_BLOCK = """  guide_window_accel_init (GTK_WINDOW (self), NULL);\n"""\n'''
    source = replace_once(
        source,
        pixbuf_anchor,
        pixbuf_constants,
        "runtime cleanup constants",
    )

    old_window_constants = '''WINDOW_MOVE_BLOCK = """  gtk_window_move (self,point.x ,point.y );\n"""\nTARGET_WINDOW_MOVE_BLOCK = """  gtk_window_move (self,point.x ,point.y );\n  g_timeout_add (100, guide_window_present, self);\n"""\n'''
    new_window_constants = '''WINDOW_MOVE_BLOCK = """  gtk_window_move (self,point.x ,point.y );\n"""\nTARGET_WINDOW_MOVE_BLOCK = """  gtk_window_move (GTK_WINDOW (self), point.x, point.y);\n  g_timeout_add (100, guide_window_present, self);\n"""\n'''
    source = replace_once(
        source,
        old_window_constants,
        new_window_constants,
        "typed delayed window presentation constants",
    )

    old_sequence = '''        (\n            PIXBUF_CALL_BLOCK,\n            TARGET_PIXBUF_CALL_BLOCK,\n            "GError pointer handoff",\n        ),\n        (\n            WINDOW_MOVE_BLOCK,\n            TARGET_WINDOW_MOVE_BLOCK,\n            "delayed window presentation",\n        ),\n        (\n            CONSTRUCTOR_BLOCK,\n'''
    new_sequence = '''        (\n            PIXBUF_CALL_BLOCK,\n            TARGET_PIXBUF_CALL_BLOCK,\n            "GError pointer handoff",\n        ),\n        (\n            LOAD_IMAGE_PRESENT_BLOCK,\n            TARGET_LOAD_IMAGE_PRESENT_BLOCK,\n            "pixbuf lifetime and deferred presentation",\n        ),\n        (\n            WINDOW_MOVE_BLOCK,\n            TARGET_WINDOW_MOVE_BLOCK,\n            "typed delayed window presentation",\n        ),\n        (\n            ACCEL_INIT_BLOCK,\n            TARGET_ACCEL_INIT_BLOCK,\n            "typed accelerator window handoff",\n        ),\n        (\n            CONSTRUCTOR_BLOCK,\n'''
    source = replace_once(
        source,
        old_sequence,
        new_sequence,
        "runtime source transformation sequence",
    )

    RECONSTRUCTION.write_text(source, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
