#!/usr/bin/env python3
"""Reconstruct the Gooroom 0.1.7 XSM source for native ARM64.

The package commit contains only a stripped AMD64 xsm.so. This tool starts from
the immutable public XSM source and applies only changes supported by the exact
0.1.7 binary history. It deliberately records the result as a constrained
reconstruction, not as recovered original source or a byte-identical build.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

PUBLISHED_SOURCE_SHA256 = "6ba6fbf4468d0b7f72a15483c43226ffcf686a0cde95998a8bd117aad91d0ddb"
FINAL_AMD64_BINARY_SHA256 = "d28c255bb00061b0df60f977e9c022a01e8d98e957b1cbcd145aaa3940aa37c8"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one anchor, found {count}")
    return text.replace(old, new, 1)


def replace_region(text: str, start: str, end: str, replacement: str, label: str) -> str:
    start_count = text.count(start)
    end_count = text.count(end)
    if start_count != 1 or end_count != 1:
        raise SystemExit(
            f"{label}: ambiguous region anchors start={start_count} end={end_count}"
        )
    start_index = text.index(start)
    end_index = text.index(end, start_index)
    return text[:start_index] + replacement.rstrip() + "\n\n" + text[end_index:]


def extract_region(text: str, start: str, end: str) -> str:
    return text[text.index(start):text.index(end, text.index(start))]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("published_source", type=Path)
    parser.add_argument("output_source", type=Path)
    parser.add_argument("manifest", type=Path)
    parser.add_argument(
        "--target-multiarch",
        default="aarch64-linux-gnu",
        choices=("aarch64-linux-gnu",),
    )
    args = parser.parse_args()

    source_bytes = args.published_source.read_bytes()
    actual_source_sha256 = sha256_bytes(source_bytes)
    if actual_source_sha256 != PUBLISHED_SOURCE_SHA256:
        raise SystemExit(
            "published XSM source SHA-256 mismatch: "
            f"{actual_source_sha256} != {PUBLISHED_SOURCE_SHA256}"
        )
    original = source_bytes.decode("utf-8")
    text = original

    preserved_boundaries = {
        "XsmResource": ("static void \nXsmResource", "/*\n * Control Xrecord"),
        "XsmExtension": ("static void \nXsmExtension", "/*\n * Control clipboard"),
        "XsmSelection": ("static void\nXsmSelection", "static void \nXsmResetProc"),
    }
    preserved_original = {
        name: extract_region(original, start, end)
        for name, (start, end) in preserved_boundaries.items()
    }

    text = replace_once(
        text,
        "#include <json-c/json.h>\n",
        "#include <dlfcn.h>\n\nstruct json_object;\n",
        "replace compile-time json-c dependency",
    )

    macro_start = '#define POLICY_BUF_SIZE\t1024\n'
    macro_end = '#define PID_SAVE_TIMEOUT\t5\n'
    macro_block = f'''#define POLICY_BUF_SIZE\t1024
#define USER_POLICY_PATH "/etc/gooroom/grac.d/user.rules"
#define DEFAULT_POLICY_PATH "/etc/gooroom/grac.d/default.rules"
#define JSON_C_LIBRARY_PATH "/usr/lib/{args.target_multiarch}/libjson-c.so.5"

#define XSM_ALLOW\t1
#define XSM_DISALLOW 0

#define XSM_SCREENSHOT\t0
#define XSM_SCREENCAST\t1
#define XSM_XRECORD\t\t3
#define XSM_CLIPBOARD\t4

#define LOG_ID "GRAC-EXT"

#define LOG_SCREENSHOT\t0
#define LOG_SCREENCAST\t1
#define LOG_XRECORD\t\t3
#define LOG_CLIPBOARD\t4

#define LOG_SCREENSHOT_BODY\t"Screenshot action restricted.\\n"
#define LOG_SCREENCAST_BODY\t"Screencast action restricted.\\n"
#define LOG_XRECORD_BODY\t"Xsession record or replay action restricted.\\n"
#define LOG_CLIPBOARD_BODY\t"Clipboard action restricted.\\n"
#define LOG_UNKNOWN_BODY\t"Unknown action restricted.\\n"

#define NOTIFY_MSG_SCR\t"040019:비인가된 행위(스크린캡쳐)가 탐지되어 차단하였습니다"
#define NOTIFY_MSG_CLP\t"040020:비인가된 행위(클립보드)가 탐지되어 차단하였습니다"
#define GRAC_CODE_SCR\t"040019"
#define GRAC_CODE_CLP\t"040020"

#define INOTIFY_MAX_EVENTS\t1024
#define INOTIFY_LEN_NAME \t16
#define INOTIFY_EVENT_SIZE  ( sizeof (struct inotify_event) )
#define INOTIFY_BUF_LEN     ( INOTIFY_MAX_EVENTS * ( INOTIFY_EVENT_SIZE + INOTIFY_LEN_NAME ))

#define POLICY_DIR_PATH\t\t"/etc/gooroom/grac.d/"
#define POLICY_SCRS_ATTR\t"screen_capture"
#define POLICY_CLIP_ATTR\t"clipboard"

#define POLICY_ALLOW_STR\t"allow"
#define POLICY_DISALLOW_STR\t"disallow"

#define PID_SAVE_TIMEOUT\t5
'''
    macro_region = text[text.index(macro_start): text.index(macro_end) + len(macro_end)]
    text = replace_once(text, macro_region, macro_block, "replace final policy constants")

    text = replace_once(
        text,
        '\t"ultract@nsr.re.kr",\t/* MODULEVENDORSTRING */',
        '\t"Gooroom",\t/* MODULEVENDORSTRING */',
        "restore final module vendor",
    )

    dbus_function = r'''void dbus_notify_signal(const char *noti_msg)
{
    DBusError err;
    dbus_error_init(&err);

    DBusConnection *conn = dbus_bus_get(DBUS_BUS_SYSTEM, &err);
    if (conn == NULL || dbus_error_is_set(&err)) {
        dbus_error_free(&err);
        exit(1);
    }

    DBusMessage *dbus_msg = dbus_message_new_signal(
        "/kr/gooroom/GRACDEVD",
        "kr.gooroom.GRACDEVD",
        "grac_noti_forward");
    if (dbus_msg == NULL)
        exit(1);

    dbus_message_append_args(
        dbus_msg, DBUS_TYPE_STRING, &noti_msg, DBUS_TYPE_INVALID);

    dbus_uint32_t serial = 0;
    if (!dbus_connection_send(conn, dbus_msg, &serial))
        exit(1);

    printf("sent (serial=%d)\\n", serial);
    dbus_message_unref(dbus_msg);
}'''
    text = replace_region(
        text,
        "void dbus_notify_signal(const char *noti_msg)",
        "/* LOG_EMERG",
        dbus_function,
        "replace GRAC D-Bus notification",
    )

    journal_function = r'''static void write_journal_log(int priority, const char *logmsg, const char *custom_fields)
{
    sd_journal_send_with_location(
        "CODE_FILE=xsm.c",
        "CODE_LINE=220",
        "write_journal_log",
        "SYSLOG_IDENTIFIER=%s", LOG_ID,
        "PRIORITY=%d", priority,
        "GRMCODE=%s", custom_fields,
        "MESSAGE=%s", logmsg,
        NULL);
}'''
    text = replace_region(
        text,
        "static void write_journal_log",
        "/* \n *\tDefault rule set",
        journal_function,
        "replace GRAC journal fields",
    )

    read_policy_function = r'''static void read_policy(void)
{
    FILE *fp;
    char policy_buf[POLICY_BUF_SIZE];
    struct json_object *parsed_json;
    struct json_object *screen_capture;
    struct json_object *clipboard;
    const char *screen_capture_policy;
    const char *clipboard_policy;
    const char *json_library = JSON_C_LIBRARY_PATH;

    typedef struct json_object *(*json_tokener_parse_fn)(const char *);
    typedef int (*json_object_object_get_ex_fn)(
        const struct json_object *, const char *, struct json_object **);
    typedef const char *(*json_object_get_string_fn)(struct json_object *);

    fp = fopen(USER_POLICY_PATH, "r");
    if (fp == NULL) {
        write_journal_log(LOG_WARNING, "User-policy file: Not exist!", "");
        fp = fopen(DEFAULT_POLICY_PATH, "r");
        if (fp == NULL) {
            write_journal_log(LOG_WARNING, "Default-policy file: Not exist!!", "");
            write_journal_log(
                LOG_WARNING,
                "Screen-capture, xrecord, clipboard allowd.",
                "");
            screenshot_allow = XSM_ALLOW;
            screencast_allow = XSM_ALLOW;
            xrecord_allow = XSM_ALLOW;
            clipboard_allow = XSM_ALLOW;
            return;
        }
        write_journal_log(LOG_NOTICE, "Default-policy file: Loaded", "");
        LogMessage(X_INFO, "Default-policy file: Loaded");
    } else {
        write_journal_log(LOG_NOTICE, "User-policy file: Loaded", "");
    }

    fread(policy_buf, POLICY_BUF_SIZE, 1, fp);
    fclose(fp);

    void *json_handle = dlopen(json_library, RTLD_LAZY);
    if (json_handle == NULL) {
        LogMessage(X_INFO, "libjson-c dlopen() error!: %s\\n", json_library);
        return;
    }

    json_tokener_parse_fn parse_json = (json_tokener_parse_fn)dlsym(
        json_handle, "json_tokener_parse");
    json_object_object_get_ex_fn get_object =
        (json_object_object_get_ex_fn)dlsym(
            json_handle, "json_object_object_get_ex");
    json_object_get_string_fn get_string =
        (json_object_get_string_fn)dlsym(
            json_handle, "json_object_get_string");

    if (parse_json == NULL || get_object == NULL || get_string == NULL) {
        LogMessage(X_INFO, "libjson-c dlsym() error!\\n");
        dlclose(json_handle);
        return;
    }

    parsed_json = parse_json(policy_buf);
    if (parsed_json == NULL) {
        write_journal_log(LOG_WARNING, "Policy-file: Json parsing error!", "");
        return;
    }

    get_object(parsed_json, POLICY_SCRS_ATTR, &screen_capture);
    get_object(parsed_json, POLICY_CLIP_ATTR, &clipboard);
    screen_capture_policy = get_string(screen_capture);
    clipboard_policy = get_string(clipboard);

    if (screen_capture_policy != NULL) {
        if (!strcmp(screen_capture_policy, POLICY_ALLOW_STR)) {
            screenshot_allow = XSM_ALLOW;
            screencast_allow = XSM_ALLOW;
            xrecord_allow = XSM_ALLOW;
            write_journal_log(LOG_NOTICE, "Screen-capture: Allow", "");
        } else if (!strcmp(screen_capture_policy, POLICY_DISALLOW_STR)) {
            screenshot_allow = XSM_DISALLOW;
            screencast_allow = XSM_DISALLOW;
            xrecord_allow = XSM_DISALLOW;
            write_journal_log(LOG_NOTICE, "Screen-capture: Disallow", "");
        }
    } else {
        screenshot_allow = XSM_ALLOW;
        screencast_allow = XSM_ALLOW;
        xrecord_allow = XSM_ALLOW;
        write_journal_log(
            LOG_WARNING,
            "Policy-file: Screen-capture value not exist!",
            "");
        write_journal_log(LOG_WARNING, "Screen-capture: No restrict", "");
    }

    if (clipboard_policy != NULL) {
        if (!strcmp(clipboard_policy, POLICY_ALLOW_STR)) {
            clipboard_allow = XSM_ALLOW;
            write_journal_log(LOG_NOTICE, "Clipboard: Allow", "");
        } else if (!strcmp(clipboard_policy, POLICY_DISALLOW_STR)) {
            clipboard_allow = XSM_DISALLOW;
            write_journal_log(LOG_NOTICE, "Clipboard: Disallow", "");
        }
    } else {
        clipboard_allow = XSM_ALLOW;
        write_journal_log(
            LOG_WARNING,
            "Policy-file: Clibboard value not exist!",
            "");
        write_journal_log(LOG_WARNING, "Clipboard: No restrict", "");
    }
}'''
    text = replace_region(
        text,
        "static void read_policy(void)",
        "/*\n * pthread for reading policy file",
        read_policy_function,
        "replace final GRAC policy loader",
    )

    text = replace_once(
        text,
        'LogMessage(X_INFO, "inotify_policy : Watching policy dir: %s\\n", POLICY_DIR_PATH);',
        'LogMessage(X_INFO, "inotify_policy : Watching Gooroom Policy Dir:: %s\\n", POLICY_DIR_PATH);',
        "restore final inotify message",
    )

    make_log_function = r'''static void make_log(int idx, pid_t cmdpid)
{
    if (timer == 0) {
        clock_gettime(CLOCK_REALTIME, &before);
        timer = 1;
    }

    if (idx == LOG_SCREENSHOT && cmdpid != screenshot_pid) {
        screenshot_pid = cmdpid;
        dbus_notify_signal(NOTIFY_MSG_SCR);
        write_journal_log(LOG_CRIT, LOG_SCREENSHOT_BODY, GRAC_CODE_SCR);
        LogMessage(X_INFO, LOG_SCREENSHOT_BODY);
    } else if (idx == LOG_SCREENCAST && cmdpid != screencast_pid) {
        screencast_pid = cmdpid;
        dbus_notify_signal(NOTIFY_MSG_SCR);
        write_journal_log(LOG_CRIT, LOG_SCREENCAST_BODY, GRAC_CODE_SCR);
        LogMessage(X_INFO, LOG_SCREENCAST_BODY);
    } else if (idx == LOG_XRECORD && cmdpid != xrecord_pid) {
        xrecord_pid = cmdpid;
        dbus_notify_signal(NOTIFY_MSG_SCR);
        write_journal_log(LOG_CRIT, LOG_XRECORD_BODY, GRAC_CODE_SCR);
        LogMessage(X_INFO, LOG_XRECORD_BODY);
    } else if (idx == LOG_CLIPBOARD && cmdpid != clipboard_pid) {
        clipboard_pid = cmdpid;
        dbus_notify_signal(NOTIFY_MSG_CLP);
        write_journal_log(LOG_CRIT, LOG_CLIPBOARD_BODY, GRAC_CODE_CLP);
        LogMessage(X_INFO, LOG_CLIPBOARD_BODY);
    }

    clock_gettime(CLOCK_REALTIME, &after);
    elapsed_secs = after.tv_sec - before.tv_sec;
    if (elapsed_secs > PID_SAVE_TIMEOUT) {
        renew_pid();
        timer = 0;
    }
}'''
    text = replace_region(
        text,
        "static void make_log(int idx, pid_t cmdpid)",
        "/*\n * Check whitelist of application",
        make_log_function,
        "replace final GRAC deny logging",
    )

    whitelist_function = r'''static int is_whitelist(const char *cmdname)
{
    if (!strcmp(cmdname, "/usr/bin/gnome-shell"))
        return 1;
    else if (!strcmp(cmdname, "xfce4-session"))
        return 1;
    else if (!strcmp(cmdname, "cinnamon"))
        return 1;
    else if (!strcmp(cmdname, "/usr/lib/at-spi2-core/at-spi2-registryd"))
        return 1;
    else if (!strcmp(cmdname, "/usr/lib/vmware-tools/sbin64/vmtoolsd"))
        return 1;
    else if (!strcmp(cmdname, "/usr/libexec/at-spi2-registryd"))
        return 1;
    else if (!strcmp(cmdname, "metacity"))
        return 1;
    else if (!strcmp(cmdname, "/usr/bin/metacity"))
        return 1;
    else if (!strcmp(cmdname, "/usr/bin/gnome-flashback"))
        return 1;
    else if (!strcmp(cmdname, "/usr/libexec/gnome-terminal-server"))
        return 1;

    return 0;
}'''
    text = replace_region(
        text,
        "static int is_whitelist(const char *cmdname)",
        "static void *\nXsmSetup",
        whitelist_function,
        "replace final whitelist",
    )

    for name, (start, end) in preserved_boundaries.items():
        reconstructed_region = extract_region(text, start, end)
        if reconstructed_region != preserved_original[name]:
            raise SystemExit(f"untouched core function changed unexpectedly: {name}")

    forbidden_literals = [
        "/usr/lib/x86_64-linux-gnu/libjson-c.so.5",
        "/etc/xsm/default.rules",
        "/etc/xsm/",
        '"XSM-LOG"',
    ]
    for literal in forbidden_literals:
        if literal in text:
            raise SystemExit(f"superseded literal remains in reconstructed source: {literal}")

    required_literals = [
        "/etc/gooroom/grac.d/user.rules",
        "/etc/gooroom/grac.d/default.rules",
        f"/usr/lib/{args.target_multiarch}/libjson-c.so.5",
        "grac_noti_forward",
        "kr.gooroom.GRACDEVD",
        "/kr/gooroom/GRACDEVD",
        "GRAC-EXT",
        "screen_capture",
        "/usr/libexec/at-spi2-registryd",
        "/usr/bin/gnome-flashback",
        "/usr/libexec/gnome-terminal-server",
        "040019:비인가된 행위(스크린캡쳐)가 탐지되어 차단하였습니다",
        "040020:비인가된 행위(클립보드)가 탐지되어 차단하였습니다",
    ]
    for literal in required_literals:
        if literal not in text:
            raise SystemExit(f"required final semantic literal is absent: {literal}")

    args.output_source.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    output_bytes = text.encode("utf-8")
    args.output_source.write_bytes(output_bytes)

    manifest = {
        "schema": 3,
        "policy": "binary-history-constrained-source-reconstruction",
        "source_status": "reconstructed-not-recovered-original-source",
        "byte_identity_claimed": False,
        "published_source": {
            "repository": "ultract/X.org-Security-Module",
            "commit": "fb0a3de9cab9b9f5b89aabd7943a5b5f13f37ab7",
            "tree": "aef0ff9c73f625763b3822c7cfa7179799f26637",
            "xsm_c_sha256": PUBLISHED_SOURCE_SHA256,
        },
        "exact_packaging": {
            "repository": "gooroom/gooroom-libsecurity-extensions",
            "commit": "4990bab95ae1dcaa29f38836da83edfa0969ed73",
            "tree": "e1dce97d3cd69331047c01940b2593a0eaf2307a",
            "source_version": "0.1.7+grm3u1",
        },
        "final_amd64_binary_evidence": {
            "commit": "40d69bd620b022aa4ecb6f7d968c87e7f8df5a28",
            "blob": "416fbb7260c30d5075b1da6dd32aa8d81ef4a49f",
            "sha256": FINAL_AMD64_BINARY_SHA256,
            "size": 27072,
        },
        "reconstructed_semantics": [
            "GRAC D-Bus deny notification",
            "GRAC journal identifier and GRMCODE field",
            "user-policy then default-policy precedence",
            "screen_capture controls screenshot, screencast and Xrecord together",
            "runtime json-c symbol resolution",
            "final 0.1.7 whitelist additions",
        ],
        "architecture_adaptations": [
            {
                "final_amd64_literal": "/usr/lib/x86_64-linux-gnu/libjson-c.so.5",
                "arm64_literal": f"/usr/lib/{args.target_multiarch}/libjson-c.so.5",
                "reason": "Debian multiarch runtime path; no version substitution",
            }
        ],
        "preserved_core_function_sha256": {
            name: sha256_bytes(region.encode("utf-8"))
            for name, region in preserved_original.items()
        },
        "required_semantic_literals": required_literals,
        "generator_sha256": sha256_bytes(Path(__file__).read_bytes()),
        "output_source_sha256": sha256_bytes(output_bytes),
    }
    args.manifest.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(manifest, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
