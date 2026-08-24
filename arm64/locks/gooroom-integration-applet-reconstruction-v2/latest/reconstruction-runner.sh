#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="${1:-work/integration-applet-reconstruction-v1}"
PUBLIC_REPO='https://github.com/gooroom/gooroom-integration-applet.git'
PUBLIC_COMMIT='168ff81421ea1f5bae9e715c5ccdd559e015d44c'
VERSION='0.3.1+grm3u1+han3u3'
POOL='https://update.hancomgooroom.com/hancom/pool/main/g/gooroom-integration-applet'
TARGET_URL="$POOL/gooroom-integration-applet_${VERSION}_amd64.deb"
TARGET_SHA='1771ded81658d0e4bcce730ab69d162a1e58327cdabf1918c341cfbd02f495a9'
DEBUG_URL="$POOL/gooroom-integration-applet-dbgsym_${VERSION}_amd64.deb"
DEBUG_SHA='806661ab9b9fef0bf14bb4a1f3e5b090ba5be84f15069f387c99ffd2c3f24c91'

rm -rf "$ROOT"
mkdir -p "$ROOT"/{downloads,target,debug,public,candidate,build-tree,build-output,recovered-resources,target-sections,analysis,output}
ROOT="$(cd "$ROOT" && pwd)"

sha_file() { sha256sum "$1" | awk '{print $1}'; }
fetch() {
  local url="$1" out="$2" expected="$3"
  curl --fail --show-error --location --retry 8 --retry-delay 2 --retry-all-errors "$url" -o "$out"
  test "$(sha_file "$out")" = "$expected"
}

fetch "$TARGET_URL" "$ROOT/downloads/target.deb" "$TARGET_SHA"
fetch "$DEBUG_URL" "$ROOT/downloads/debug.deb" "$DEBUG_SHA"
test "$(dpkg-deb -f "$ROOT/downloads/target.deb" Package)" = gooroom-integration-applet
test "$(dpkg-deb -f "$ROOT/downloads/target.deb" Version)" = "$VERSION"
test "$(dpkg-deb -f "$ROOT/downloads/target.deb" Architecture)" = amd64
dpkg-deb -x "$ROOT/downloads/target.deb" "$ROOT/target"
dpkg-deb -x "$ROOT/downloads/debug.deb" "$ROOT/debug"
dpkg-deb -f "$ROOT/downloads/target.deb" > "$ROOT/output/target-control-fields.txt"
gzip -dc "$ROOT/target/usr/share/doc/gooroom-integration-applet/changelog.gz" > "$ROOT/output/vendor-changelog.txt"

MAIN_ELF="$ROOT/target/usr/lib/x86_64-linux-gnu/gnome-panel/modules/libgooroom-integration-applet.so"
NIMF_ELF="$ROOT/target/usr/lib/x86_64-linux-gnu/nimf/modules/services/libnimf-gooroom.so"
for elf in "$MAIN_ELF" "$NIMF_ELF"; do test -f "$elf"; done

git clone --quiet --no-tags "$PUBLIC_REPO" "$ROOT/public"
git -C "$ROOT/public" checkout --quiet --detach "$PUBLIC_COMMIT"
test "$(git -C "$ROOT/public" rev-parse HEAD)" = "$PUBLIC_COMMIT"
cp -a "$ROOT/public/." "$ROOT/candidate/"

# Match the target's Debian bullseye-era GLib resource compiler rather than the
# newer host GLib/zlib implementation. Keep one helper container alive for the
# bounded reconstruction search.
RESOURCE_CONTAINER=hancom-gooroom-gresource-$$
docker run -d --name "$RESOURCE_CONTAINER" -v "$ROOT:/work" debian:bullseye sleep infinity >/dev/null
cleanup_resource_container() { docker rm -f "$RESOURCE_CONTAINER" >/dev/null 2>&1 || true; }
trap cleanup_resource_container EXIT
docker exec "$RESOURCE_CONTAINER" bash -lc 'set -Eeuo pipefail; apt-get update; apt-get install -y --no-install-recommends libglib2.0-dev-bin libxml2-utils; command -v glib-compile-resources; glib-compile-resources --version' \
  > "$ROOT/output/bullseye-gresource-tooling.log" 2>&1

# Extract every architecture-neutral GResource payload directly from the target ELF.
while IFS= read -r section; do
  name="${section#.}"
  objcopy --dump-section "$section=$ROOT/target-sections/$name.gresource" "$MAIN_ELF"
done < <(readelf -S --wide "$MAIN_ELF" | awk '$2 ~ /^\.gresource\./ {print $2}')
while IFS= read -r resource; do
  out="$ROOT/recovered-resources/${resource#/}"
  mkdir -p "$(dirname "$out")"
  gresource extract "$MAIN_ELF" "$resource" > "$out"
done < <(gresource list "$MAIN_ELF")

copy_resource() {
  local resource="$1" destination="$2"
  local source="$ROOT/recovered-resources/${resource#/}"
  test -f "$source"
  mkdir -p "$(dirname "$ROOT/candidate/$destination")"
  cp "$source" "$ROOT/candidate/$destination"
}
copy_resource '/kr/gooroom/IntegrationApplet/ui/popup-window.ui' 'src/popup-window.ui'
copy_resource '/kr/gooroom/IntegrationApplet/ui/style.css' 'data/style.css'
copy_resource '/kr/gooroom/IntegrationApplet/ui/style1.css' 'data/style1.css'
copy_resource '/kr/gooroom/IntegrationApplet/ui/style2.css' 'data/style2.css'
copy_resource '/kr/gooroom/IntegrationApplet/modules/datetime/datetime-control-menu.ui' 'modules/datetime/datetime-control-menu.ui'
copy_resource '/kr/gooroom/IntegrationApplet/modules/endsession/endsession-control.ui' 'modules/endsession/endsession-control.ui'
copy_resource '/kr/gooroom/IntegrationApplet/modules/nimf/nimf-control.ui' 'modules/nimf/nimf-control.ui'
copy_resource '/kr/gooroom/IntegrationApplet/modules/security/security-control-menu.ui' 'modules/security/security-control-menu.ui'
copy_resource '/kr/gooroom/IntegrationApplet/modules/security/security-control.ui' 'modules/security/security-control.ui'
copy_resource '/kr/gooroom/IntegrationApplet/modules/updater/updater-control-menu.ui' 'modules/updater/updater-control-menu.ui'
copy_resource '/kr/gooroom/IntegrationApplet/modules/updater/updater-control.ui' 'modules/updater/updater-control.ui'
copy_resource '/kr/gooroom/IntegrationApplet/modules/user/user-control.ui' 'modules/user/user-control.ui'

# Recover the main resource XML by compiling a bounded set of equivalent descriptions
# and accepting only an exact match to the target .gresource.applet section.
python3 - "$ROOT" "$RESOURCE_CONTAINER" <<'PY'
from pathlib import Path
from collections import Counter
import hashlib, itertools, json, subprocess, sys
root=Path(sys.argv[1]); container=sys.argv[2]; candidate=root/'candidate'; target=root/'target-sections/gresource.applet.gresource'
target_bytes=target.read_bytes(); target_sha=hashlib.sha256(target_bytes).hexdigest(); attempts=[]; found=None; successes=0; errors=Counter(); best=None

def section_match(resource_bytes):
    if len(resource_bytes)>len(target_bytes) or not target_bytes.startswith(resource_bytes): return None
    padding=target_bytes[len(resource_bytes):]
    if len(padding)>16 or any(padding): return None
    return len(padding)

popup=('popup-window.ui','popup-window.ui')
styles=(('style.css','../data/style.css'),('style1.css','../data/style1.css'),('style2.css','../data/style2.css'))
for file_order in itertools.permutations((popup,)+styles):
  for compressed in itertools.product((False,True), repeat=3):
    compression=dict(zip((x[0] for x in styles),compressed))
    for strip in (False,True):
      for grouping in ('single','popup-first','popup-last','separate'):
        def file_line(item):
          name,path=item; attrs=[]
          if name=='popup-window.ui' and strip: attrs.append('preprocess="xml-stripblanks"')
          if name!='popup-window.ui' and compression[name]: attrs.append('compressed="true"')
          if name!=path: attrs.append(f'alias="{name}"')
          suffix=(' '+ ' '.join(attrs)) if attrs else ''
          return f'    <file{suffix}>{path}</file>'
        if grouping=='single': groups=[file_order]
        elif grouping=='popup-first': groups=[(popup,),tuple(x for x in file_order if x!=popup)]
        elif grouping=='popup-last': groups=[tuple(x for x in file_order if x!=popup),(popup,)]
        else: groups=[(x,) for x in file_order]
        lines=['<?xml version="1.0" encoding="UTF-8"?>','<gresources>']
        for group in groups:
          if not group: continue
          lines.append('  <gresource prefix="/kr/gooroom/IntegrationApplet/ui">')
          lines.extend(file_line(x) for x in group); lines.append('  </gresource>')
        lines.extend(['</gresources>','']); xml='\n'.join(lines)
        probe=candidate/'src/gresource-probe.xml'; probe.write_text(xml,encoding='utf-8')
        output=root/'analysis/probe.gresource'; output.unlink(missing_ok=True)
        p=subprocess.run(['docker','exec',container,'glib-compile-resources','/work/candidate/src/gresource-probe.xml','--target','/work/analysis/probe.gresource','--sourcedir','/work/candidate/src'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        row={'file_order':[x[0] for x in file_order],'compressed':compression,'stripblanks':strip,'grouping':grouping,'exit':p.returncode}
        if p.returncode==0 and output.exists():
          successes+=1; blob=output.read_bytes(); padding=section_match(blob)
          row.update({'sha256':hashlib.sha256(blob).hexdigest(),'size':len(blob),'elf_zero_padding_bytes':padding,'section_prefix_match':padding is not None})
          score=(0 if padding is not None else 1,abs(len(target_bytes)-len(blob)))
          if best is None or score<best[0]: best=(score,{**row,'xml':xml},blob)
          if padding is not None:
            found={**row,'xml':xml}; (candidate/'src/gresource.xml').write_text(xml,encoding='utf-8'); attempts.append(row); break
        else:
          message=(p.stderr or p.stdout or 'compiler produced no output').strip()[-1000:]
          errors[message]+=1; row['error']=message
        attempts.append(row)
      if found: break
    if found: break
  if found: break
(candidate/'src/gresource-probe.xml').unlink(missing_ok=True)
if best is not None:
  (root/'analysis/best-main.gresource').write_bytes(best[2])
report={'target_section_sha256':target_sha,'target_section_size':len(target_bytes),'matched':bool(found),'match':found,'attempt_count':len(attempts),'successful_compile_count':successes,'unique_compile_error_count':len(errors),'compile_error_samples':[{'count':n,'message':msg} for msg,n in errors.most_common(10)],'best_candidate':best[1] if best else None}
(root/'output/main-gresource-reconstruction.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
(root/'output/main-gresource-attempts.json').write_text(json.dumps(attempts,indent=2,sort_keys=True)+'\n')
if not found: raise SystemExit('no compiled standalone GResource matched the target ELF section prefix plus zero padding')
PY

# Check whether public module resource descriptions reproduce each target section
# after replacing the UI source payloads.
python3 - "$ROOT" "$RESOURCE_CONTAINER" <<'PY'
from pathlib import Path
import hashlib,itertools,json,subprocess,sys
root=Path(sys.argv[1]); container=sys.argv[2]; rows=[]

def section_match(section,resource):
  if len(resource)>len(section) or not section.startswith(resource): return None
  padding=section[len(resource):]
  return len(padding) if len(padding)<=16 and not any(padding) else None

def compile_variant(module,xml,index):
  xmlpath=root/f'candidate/modules/{module}/gresource-probe.xml'; xmlpath.write_text(xml,encoding='utf-8')
  out=root/f'analysis/module-{module}-{index}.gresource'; out.unlink(missing_ok=True)
  p=subprocess.run(['docker','exec',container,'glib-compile-resources',f'/work/candidate/modules/{module}/gresource-probe.xml','--target',f'/work/analysis/module-{module}-{index}.gresource','--sourcedir',f'/work/candidate/modules/{module}'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
  return p,out

for module in ('datetime','endsession','nimf','security','updater','user'):
  section=(root/f'target-sections/gresource.{module}_control.gresource').read_bytes()
  prefix=f'/kr/gooroom/IntegrationApplet/modules/{module}'
  files=sorted(p.name for p in (root/f'candidate/modules/{module}').glob('*.ui'))
  variants=[]
  public=(root/f'candidate/modules/{module}/gresource.xml').read_text(encoding='utf-8'); variants.append(('public',public))
  for order in itertools.permutations(files):
    for strip in (False,True):
      lines=['<?xml version="1.0" encoding="UTF-8"?>','<gresources>',f'  <gresource prefix="{prefix}">']
      for name in order:
        attr=' preprocess="xml-stripblanks"' if strip else ''
        lines.append(f'    <file{attr}>{name}</file>')
      lines.extend(['  </gresource>','</gresources>','']); variants.append((f'canonical-strip-{strip}-order-{",".join(order)}','\n'.join(lines)))
  found=None; attempts=[]
  for idx,(label,xml) in enumerate(variants):
    p,out=compile_variant(module,xml,idx); row={'variant':label,'exit':p.returncode}
    if p.returncode==0 and out.exists():
      blob=out.read_bytes(); padding=section_match(section,blob); row.update({'standalone_sha256':hashlib.sha256(blob).hexdigest(),'standalone_size':len(blob),'target_section_sha256':hashlib.sha256(section).hexdigest(),'target_section_size':len(section),'elf_zero_padding_bytes':padding,'section_prefix_match':padding is not None})
      if padding is not None:
        found={**row,'xml':xml}; (root/f'candidate/modules/{module}/gresource.xml').write_text(xml,encoding='utf-8'); attempts.append(row); break
    else: row['error']=(p.stderr or p.stdout or 'compiler produced no output').strip()[-1000:]
    attempts.append(row)
  (root/f'candidate/modules/{module}/gresource-probe.xml').unlink(missing_ok=True)
  rows.append({'module':module,'matched':bool(found),'match':found,'attempts':attempts})
(root/'output/module-gresource-reconstruction.json').write_text(json.dumps(rows,indent=2,sort_keys=True)+'\n')
if not all(r['matched'] for r in rows): raise SystemExit('one or more module standalone GResources did not match target ELF section prefixes')
PY
# Recover exact installed icon payloads and an explicit source install manifest.
rm -f "$ROOT/candidate/icons/"*.svg
cp "$ROOT/target/usr/share/icons/hicolor/scalable/status/"*.svg "$ROOT/candidate/icons/"
cp "$ROOT/target/usr/share/icons/hicolor/scalable/actions/"*.svg "$ROOT/candidate/icons/"
python3 - "$ROOT" <<'PY'
from pathlib import Path
import sys
root=Path(sys.argv[1]); target=root/'target/usr/share/icons/hicolor/scalable'; dest=root/'candidate/icons/Makefile.am'
status=sorted(p.name for p in (target/'status').glob('*.svg')); actions=sorted(p.name for p in (target/'actions').glob('*.svg'))
def block(var,items):
  lines=[f'{var} = \\']
  for i,name in enumerate(items): lines.append(f'\t{name}' + (' \\' if i+1<len(items) else ''))
  return '\n'.join(lines)
text='\n'.join(['iconsymbolicstatusdir = $(datadir)/icons/hicolor/scalable/status',block('iconsymbolicstatus_DATA',status),'','iconsymbolicactionsdir = $(datadir)/icons/hicolor/scalable/actions',block('iconsymbolicactions_DATA',actions),'','gtk_update_icon_cache = gtk-update-icon-cache -f -t $(datadir)/icons/hicolor','','install-data-hook:','\t@-if test -z "$(DESTDIR)"; then \\','\t\t$(gtk_update_icon_cache); \\','\tfi','','EXTRA_DIST = $(iconsymbolicstatus_DATA) $(iconsymbolicactions_DATA)',''])
dest.write_text(text,encoding='utf-8')
PY

# Recover PO source where round-trippable, while retaining exact target MOs as a
# deterministic packaging override.
mkdir -p "$ROOT/candidate/debian/vendor-locale/en_GB" "$ROOT/candidate/debian/vendor-locale/ko"
: > "$ROOT/output/locale-roundtrip.tsv"
printf 'locale\ttarget_sha256\troundtrip_sha256\texact\n' >> "$ROOT/output/locale-roundtrip.tsv"
for locale in en_GB ko; do
  target_mo="$ROOT/target/usr/share/locale/$locale/LC_MESSAGES/gooroom-integration-applet.mo"
  recovered_po="$ROOT/candidate/po/$locale.po"
  roundtrip="$ROOT/analysis/$locale.mo"
  msgunfmt "$target_mo" -o "$recovered_po"
  msgfmt "$recovered_po" -o "$roundtrip"
  target_hash="$(sha_file "$target_mo")"; roundtrip_hash="$(sha_file "$roundtrip")"
  exact=false; [[ "$target_hash" == "$roundtrip_hash" ]] && exact=true
  printf '%s\t%s\t%s\t%s\n' "$locale" "$target_hash" "$roundtrip_hash" "$exact" >> "$ROOT/output/locale-roundtrip.tsv"
  cp "$target_mo" "$ROOT/candidate/debian/vendor-locale/$locale/gooroom-integration-applet.mo"
done

# Recover direct architecture-neutral payloads.
gschema_target="$ROOT/target/usr/share/glib-2.0/schemas/apps.gooroom-security-status.gschema.xml"
gschema_source="$(find "$ROOT/candidate" -type f -name apps.gooroom-security-status.gschema.xml -print -quit)"
test -n "$gschema_source"; cp "$gschema_target" "$gschema_source"
gzip -dc "$ROOT/target/usr/share/doc/gooroom-integration-applet/changelog.gz" > "$ROOT/candidate/debian/changelog"
cp "$ROOT/target/usr/share/doc/gooroom-integration-applet/copyright" "$ROOT/candidate/debian/copyright"

# Install exact MO payloads after the normal build to preserve byte identity.
cat >> "$ROOT/candidate/debian/rules" <<'RULES'

override_dh_auto_install:
	dh_auto_install
	find debian/gooroom-integration-applet -name '*.la' -delete
	install -D -m 0644 debian/vendor-locale/en_GB/gooroom-integration-applet.mo debian/gooroom-integration-applet/usr/share/locale/en_GB/LC_MESSAGES/gooroom-integration-applet.mo
	install -D -m 0644 debian/vendor-locale/ko/gooroom-integration-applet.mo debian/gooroom-integration-applet/usr/share/locale/ko/LC_MESSAGES/gooroom-integration-applet.mo
RULES
# Remove the original duplicate override block before retaining the appended one.
python3 - "$ROOT/candidate/debian/rules" <<'PY'
from pathlib import Path
import re,sys
p=Path(sys.argv[1]); t=p.read_text()
blocks=list(re.finditer(r'(?ms)^override_dh_auto_install:\n(?:\t.*\n)+',t))
if len(blocks)>1:
  first=blocks[0]; t=t[:first.start()]+t[first.end():]
p.write_text(t)
PY
chmod +x "$ROOT/candidate/debian/rules" "$ROOT/candidate/autogen.sh"

# Reconstruct the Hancom-only C delta identified from the exact vendor DWARF.
python3 - "$ROOT/candidate" "$ROOT/output/han3u3-source-reconstruction.json" <<'PY_HAN3_SOURCE'
from __future__ import annotations

from pathlib import Path
import hashlib
import json
import sys

root = Path(sys.argv[1])
report_path = Path(sys.argv[2]) if len(sys.argv) > 2 else root / "han3u3-source-reconstruction.json"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one anchor, found {count}")
    return text.replace(old, new, 1)


applet = root / "src/gooroom-integration-applet.c"
popup = root / "src/popup-window.c"
datetime = root / "modules/datetime/datetime-module.c"
user = root / "modules/user/user-module.c"
source_paths = (applet, popup, datetime, user)
for path in source_paths:
    if not path.is_file():
        raise RuntimeError(f"missing source file: {path}")

before = {path.as_posix(): sha(path) for path in source_paths}

applet_text = applet.read_text(encoding="utf-8")
applet_text = replace_once(
    applet_text,
    "\tPopupWindow      *popup;\n\tGtkWidget        *button;\n\n\tUserModule       *user_module;\n",
    "\tPopupWindow      *popup;\n\tGtkWidget        *button;\n\tGtkSettings      *settings;\n\n\tUserModule       *user_module;\n",
    "add GtkSettings private member",
)

theme_functions = """static void
set_style_from_theme (GtkSettings *settings, const gchar *str)
{
\tGtkCssProvider *provider = gtk_css_provider_new ();

\tif (g_strrstr (str, \"style1\")) {
\t\tgtk_css_provider_load_from_resource (provider, \"/kr/gooroom/IntegrationApplet/ui/style1.css\");
\t} else if (g_strrstr (str, \"style4\")) {
\t\tgtk_css_provider_load_from_resource (provider, \"/kr/gooroom/IntegrationApplet/ui/style2.css\");
\t} else if (g_strrstr (str, \"style5\")) {
\t\tgtk_css_provider_load_from_resource (provider, \"/kr/gooroom/IntegrationApplet/ui/style2.css\");
\t} else {
\t\tgtk_css_provider_load_from_resource (provider, \"/kr/gooroom/IntegrationApplet/ui/style.css\");
\t}

\tgtk_style_context_add_provider_for_screen (gdk_screen_get_default (),
\t                                           GTK_STYLE_PROVIDER (provider),
\t                                           GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
\tg_object_unref (provider);
}

static void
theme_property_notified (GObject    *object,
                         GParamSpec *pspec,
                         gpointer    data)
{
\tgchar *str;
\tGSettings *settings = g_settings_new (\"org.gnome.desktop.interface\");

\tif (object) {
\t\tGValue value = G_VALUE_INIT;

\t\tg_value_init (&value, pspec->value_type);
\t\tg_object_get_property (object, pspec->name, &value);
\t\tstr = g_strdup_value_contents (&value);
\t\tg_value_unset (&value);
\t} else {
\t\tstr = g_strdup (g_settings_get_string (settings, \"icon-theme\"));
\t}

\tset_style_from_theme (settings, str);
\tg_object_unref (settings);
\tg_free (str);
}


"""
applet_text = replace_once(
    applet_text,
    "static void\ngooroom_integration_applet_init (GooroomIntegrationApplet *applet)\n",
    theme_functions + "static void\ngooroom_integration_applet_init (GooroomIntegrationApplet *applet)\n",
    "insert Hancom icon-theme callbacks",
)
applet_text = replace_once(
    applet_text,
    "\tpriv->button = gtk_toggle_button_new ();\n\tgtk_button_set_relief (GTK_BUTTON (priv->button), GTK_RELIEF_NONE);\n\tgtk_container_add (GTK_CONTAINER (applet), priv->button);\n\tgtk_widget_show (priv->button);\n",
    "\tpriv->button = gtk_toggle_button_new ();\n\tgtk_button_set_relief (GTK_BUTTON (priv->button), GTK_RELIEF_NONE);\n\tgtk_container_add (GTK_CONTAINER (applet), priv->button);\n\n\tpriv->settings = gtk_widget_get_settings (GTK_WIDGET (applet));\n\n\tgtk_widget_show (priv->button);\n",
    "capture GtkSettings in applet init",
)
applet_text = replace_once(
    applet_text,
    "\tg_signal_connect (G_OBJECT (priv->button), \"toggled\", G_CALLBACK (on_applet_button_toggled), applet);\n",
    "\ttheme_property_notified (NULL, NULL, NULL);\n\n\tg_signal_connect (G_OBJECT (priv->button), \"toggled\", G_CALLBACK (on_applet_button_toggled), applet);\n",
    "apply initial icon theme",
)
applet_text = replace_once(
    applet_text,
    "\tg_signal_connect (gdk_display_get_default_screen (display),\n                      \"monitors-changed\", G_CALLBACK (monitors_changed_cb), applet);\n}\n",
    "\tg_signal_connect (gdk_display_get_default_screen (display),\n                      \"monitors-changed\", G_CALLBACK (monitors_changed_cb), applet);\n\n\tg_signal_connect (priv->settings,\n                      \"notify::gtk-icon-theme-name\", G_CALLBACK (theme_property_notified), NULL);\n}\n",
    "monitor Gtk icon-theme changes",
)
applet.write_text(applet_text, encoding="utf-8")

popup_text = popup.read_text(encoding="utf-8")
popup_text = replace_once(
    popup_text,
    "\tPopupWindowPrivate *priv;\n\tGtkCssProvider\t   *provider;\n\n",
    "\tPopupWindowPrivate *priv;\n\n",
    "remove obsolete popup CSS provider variable",
)
popup_text = replace_once(
    popup_text,
    "\tprovider = gtk_css_provider_new ();\n"
    "\tgtk_css_provider_load_from_resource (provider, \"/kr/gooroom/IntegrationApplet/ui/style.css\");\n"
    "\tgtk_style_context_add_provider_for_screen (gdk_screen_get_default (),\n"
    "                                               GTK_STYLE_PROVIDER (provider),\n"
    "                                               GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);\n"
    "\tg_object_unref (provider);\n\n",
    "",
    "remove duplicate popup CSS provider setup",
)
popup.write_text(popup_text, encoding="utf-8")

datetime_text = datetime.read_text(encoding="utf-8")
datetime_text = replace_once(
    datetime_text,
    "\tpriv->control = gtk_button_new ();\n"
    "\tgtk_button_set_relief (GTK_BUTTON (priv->control), GTK_RELIEF_NONE);\n\n",
    "\tpriv->control = gtk_button_new ();\n"
    "\tgtk_button_set_relief (GTK_BUTTON (priv->control), GTK_RELIEF_NONE);\n"
    "\tgtk_widget_set_can_focus (GTK_WIDGET (priv->control), FALSE);\n\n",
    "disable focus on datetime control button",
)
datetime.write_text(datetime_text, encoding="utf-8")

user_text = user.read_text(encoding="utf-8")
user_text = replace_once(
    user_text,
    '#define CLEANMODE "/tmp/.cleanmode"\n',
    "",
    "remove clean-mode path macro",
)
user_text = replace_once(
    user_text,
    "\tGtkWidget  *tray;\n\tGtkWidget  *user_name;\n\tGtkWidget  *lbl_cleanmode;\n\tGtkWidget  *img_status;\n\tGtkWidget  *control;\n",
    "\tGtkWidget  *tray;\n\tGtkWidget  *user_name;\n\tGtkWidget  *img_status;\n\tGtkWidget  *control;\n",
    "remove clean-mode private member",
)
canonical_user_info_update = """static void
user_info_update (ActUserManager *um, GParamSpec *pspec, gpointer data)
{
\tg_return_if_fail (data != NULL);

\tconst char *user_name;
\tconst char *icon_name = NULL;

\tUserModule *module = USER_MODULE (data);
\tUserModulePrivate *priv = module->priv;

\tif (!act_user_manager_no_service (um)) {
\t\tActUser *user = act_user_manager_get_user_by_id (um, getuid ());
\t\tif (user) {
\t\t\ticon_name = act_user_get_icon_file (user);
\t\t\tuser_name = act_user_get_real_name (user);
\t\t\tif (user_name == NULL)
\t\t\t\tuser_name = act_user_get_user_name (user);
\t\t} else {
\t\t\tuser_name = NULL;
\t\t}
\t} else {
\t\tuser_name = NULL;
\t}

\tif (priv->tray) {
\t\tGdkPixbuf *pix = get_user_face (icon_name, TRAY_ICON_SIZE);
\t\tif (pix) {
\t\t\tgtk_image_set_from_pixbuf (GTK_IMAGE (priv->tray), pix);
\t\t\tg_object_unref (G_OBJECT (pix));
\t\t}
\t}

\tif (priv->control) {
\t\tif (priv->user_name) {
\t\t\tconst gchar *s = user_name ? user_name : _(\"Unknown\");
\t\t\tgchar *markup = g_strdup_printf (\"%s\", s);
\t\t\tgtk_label_set_markup (GTK_LABEL (priv->user_name), markup);
\t\t\tg_free (markup);
\t\t}
\t\tif (priv->img_status) {
\t\t\tGdkPixbuf *pix = get_user_face (icon_name, 24);
\t\t\tif (pix) {
\t\t\t\tgtk_image_set_from_pixbuf (GTK_IMAGE (priv->img_status), pix);
\t\t\t\tg_object_unref (G_OBJECT (pix));
\t\t\t}
\t\t}
\t}
}

"""
start = user_text.index("static void\nuser_info_update (")
end = user_text.index("static void\nbuild_control_ui (", start)
user_text = user_text[:start] + canonical_user_info_update + user_text[end:]
user_text = replace_once(
    user_text,
    "\tpriv->control = GET_WIDGET (priv->builder, \"control\");\n\tpriv->user_name = GET_WIDGET (priv->builder, \"lbl_user_name\");\n\tpriv->lbl_cleanmode = GET_WIDGET (priv->builder, \"lbl_cleanmode\");\n\tpriv->img_status = GET_WIDGET (priv->builder, \"img_status\");\n",
    "\tpriv->control = GET_WIDGET (priv->builder, \"control\");\n\tpriv->user_name = GET_WIDGET (priv->builder, \"lbl_user_name\");\n\tpriv->img_status = GET_WIDGET (priv->builder, \"img_status\");\n",
    "remove clean-mode builder lookup",
)
user_text = replace_once(
    user_text,
    "\tpriv->tray          = NULL;\n\tpriv->user_name     = NULL;\n\tpriv->lbl_cleanmode = NULL;\n\tpriv->control       = NULL;\n",
    "\tpriv->tray          = NULL;\n\tpriv->user_name     = NULL;\n\tpriv->control       = NULL;\n",
    "remove clean-mode initialization",
)
canonical_tray_new = """GtkWidget *
user_module_tray_new (UserModule *module)
{
\tg_return_val_if_fail (module != NULL, NULL);

\tUserModulePrivate *priv = module->priv;

\tif (!priv->tray) {
\t\tpriv->tray = gtk_image_new_from_icon_name (\"avatar-default-symbolic\",
                                                   GTK_ICON_SIZE_LARGE_TOOLBAR);
\t\tgtk_image_set_pixel_size (GTK_IMAGE (priv->tray), TRAY_ICON_SIZE);
\t}

\tgboolean loaded = FALSE;
\tg_object_get (priv->um, \"is-loaded\", &loaded, NULL);
\tif (loaded)
\t\tuser_info_update (priv->um, NULL, module);

\tgtk_widget_show (priv->tray);

\treturn priv->tray;
}

"""
start = user_text.index("GtkWidget *\nuser_module_tray_new (")
end = user_text.index("GtkWidget *\nuser_module_control_new (", start)
user_text = user_text[:start] + canonical_tray_new + user_text[end:]
user.write_text(user_text, encoding="utf-8")

after = {path.as_posix(): sha(path) for path in source_paths}
checks = {
    "settings_member_count": applet_text.count("GtkSettings      *settings;"),
    "set_style_from_theme_count": applet_text.count("set_style_from_theme ("),
    "theme_property_notified_count": applet_text.count("theme_property_notified ("),
    "theme_signal_count": applet_text.count("notify::gtk-icon-theme-name"),
    "popup_css_provider_variable_count": popup_text.count("GtkCssProvider\t   *provider;"),
    "popup_css_provider_load_count": popup_text.count("gtk_css_provider_load_from_resource (provider"),
    "datetime_control_can_focus_false_count": datetime_text.count(
        "gtk_widget_set_can_focus (GTK_WIDGET (priv->control), FALSE);"
    ),
    "cleanmode_token_count": user_text.count("cleanmode"),
    "clean_mode_token_count": user_text.count("clean_mode"),
    "clean_mode_markup_count": user_text.count("<b><span foreground="),
}
expected_checks = {
    "settings_member_count": 1,
    "set_style_from_theme_count": 2,
    "theme_property_notified_count": 2,
    "theme_signal_count": 1,
    "popup_css_provider_variable_count": 0,
    "popup_css_provider_load_count": 0,
    "datetime_control_can_focus_false_count": 1,
    "cleanmode_token_count": 0,
    "clean_mode_token_count": 0,
    "clean_mode_markup_count": 0,
}
if checks != expected_checks:
    raise RuntimeError(f"post-patch verification failed: {checks}")

report = {
    "schema": 1,
    "source": "gooroom-integration-applet",
    "version": "0.3.1+grm3u1+han3u3",
    "policy": "matching-vendor-dwarf-and-runtime-string-guided-source-delta",
    "changes": [
        "add GtkSettings pointer to GooroomIntegrationApplet private data",
        "apply style1/style2/default CSS according to the Hancom icon theme",
        "monitor notify::gtk-icon-theme-name",
        "remove duplicate popup CSS provider setup absent from vendor DWARF",
        "disable focus on the datetime control button",
        "remove public clean-mode user-module extension absent from vendor DWARF",
    ],
    "before_sha256": before,
    "after_sha256": after,
    "checks": checks,
    "promotion_allowed": False,
    "iso_assembly_allowed": False,
}
report_path.parent.mkdir(parents=True, exist_ok=True)
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(json.dumps(report, indent=2, sort_keys=True))
PY_HAN3_SOURCE

# Record the exact overlay before build products alter the tree.
git -C "$ROOT/candidate" add -A
git -C "$ROOT/candidate" diff --cached --binary > "$ROOT/output/public-168ff-to-han3u3-candidate.patch"
git -C "$ROOT/candidate" diff --cached --name-status > "$ROOT/output/overlay-name-status.tsv"
git -C "$ROOT/candidate" status --short > "$ROOT/output/candidate-status.txt"
tar --exclude=.git -C "$ROOT/candidate" -cf "$ROOT/output/gooroom-integration-applet_${VERSION}.candidate-source.tar" .
xz -9e -f "$ROOT/output/gooroom-integration-applet_${VERSION}.candidate-source.tar"
cp -a "$ROOT/candidate/." "$ROOT/build-tree/"

# Rebuild under Debian bullseye, matching the target's GCC 10.2.1 generation.
set +e
docker run --rm -v "$ROOT:/work" -w /work/build-tree debian:bullseye bash -lc '
  set -Eeuo pipefail
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y --no-install-recommends \
    automake build-essential ca-certificates debhelper devscripts dpkg-dev fakeroot \
    gnome-common gnome-pkg-tools intltool libaccountsservice-dev libcanberra-gtk3-dev \
    libglib2.0-dev libgnome-desktop-3-dev libgnome-panel-dev libgtk-3-dev libjson-c-dev \
    libnotify-dev libpolkit-gobject-1-dev libpulse-dev libstartup-notification0-dev \
    libudev-dev libupower-glib-dev libx11-dev nimf-dev pkg-config
  gcc --version | head -1
  dpkg-buildpackage -us -uc -b
  cp -v /work/gooroom-integration-applet_*_amd64.deb /work/build-output/
  cp -v /work/gooroom-integration-applet-dbgsym_*_amd64.deb /work/build-output/ 2>/dev/null || true
' > "$ROOT/output/build.log" 2>&1
BUILD_EXIT=$?
set -e
printf '%s\n' "$BUILD_EXIT" > "$ROOT/output/build.exit"

python3 - "$ROOT" "$VERSION" "$BUILD_EXIT" <<'PY'
from pathlib import Path
import hashlib,json,os,re,shutil,stat,subprocess,sys
root=Path(sys.argv[1]); version=sys.argv[2]; build_exit=int(sys.argv[3])
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1<<20),b''): h.update(b)
 return h.hexdigest()
def elf(p):
 try:return p.open('rb').read(4)==b'\x7fELF'
 except:return False
def run(a,**kw): return subprocess.run(a,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,**kw)
def buildid(p):
 q=run(['readelf','-n',str(p)]); m=re.search(r'Build ID:\s*([0-9a-fA-F]+)',q.stdout); return m.group(1).lower() if m else None
def section_inventory(p):
 q=run(['readelf','-SW',str(p)]); rows={}
 for line in q.stdout.splitlines():
  m=re.match(r'^\s*\[\s*\d+\]\s+(.*)$',line)
  if not m: continue
  fields=m.group(1).split()
  if not fields or not fields[0].startswith('.') or len(fields) not in (9,10): continue
  if len(fields)==10:
   name,typ,address,offset,size,entsize,flags,link,info,align=fields
  else:
   name,typ,address,offset,size,entsize,link,info,align=fields; flags=''
  row={'type':typ,'size':int(size,16),'entsize':int(entsize,16),'flags':flags,'align':int(align)}
  if typ!='NOBITS' and row['size']:
   out=root/'analysis/sections'/hashlib.sha1((str(p)+name).encode()).hexdigest()
   out.parent.mkdir(parents=True,exist_ok=True)
   r=run(['objcopy','--dump-section',f'{name}={out}',str(p)])
   if r.returncode!=0 or not out.exists(): raise RuntimeError(f'failed to dump {p}: {name}: {r.stderr}')
   row['sha256']=sha(out)
  rows[name]=row
 return rows
def normalized_allocated(rows):
 # The GNU build-id note and the non-allocated debuglink are packaging metadata.
 # Every other allocated section, including dynamic tables, relocations, unwind
 # data, writable data, BSS shape, and embedded resources, must match exactly.
 return {name:row for name,row in rows.items() if 'A' in row['flags'] and name!='.note.gnu.build-id'}
def filesystem_inventory(base):
 result={}
 for p in sorted(base.rglob('*')):
  rel=p.relative_to(base).as_posix(); st=p.lstat(); mode=stat.S_IMODE(st.st_mode)
  if p.is_symlink(): result[rel]={'kind':'symlink','mode':mode,'target':os.readlink(p)}
  elif p.is_dir(): result[rel]={'kind':'directory','mode':mode}
  elif p.is_file(): result[rel]={'kind':'file','mode':mode,'size':st.st_size,'sha256':sha(p),'elf':elf(p)}
 return result
def control_text(deb): return run(['dpkg-deb','-f',str(deb)]).stdout
summary={'schema':2,'version':version,'public_commit':'168ff81421ea1f5bae9e715c5ccdd559e015d44c','build_exit':build_exit,'build_succeeded':False,'exact_vendor_source_recovered':False,'candidate_source_reconstructed':True,'amd64_normalized_equivalence_verified':False,'native_arm64_candidate_build_allowed':False,'native_arm64_build_allowed':False,'package_promotion_allowed':False,'iso_assembly_allowed':False,'fail_closed':True}
comparison=[]; elf_rows=[]
if build_exit==0:
 debs=sorted(root.glob(f'build-output/gooroom-integration-applet_{version}_amd64.deb'))
 if len(debs)==1:
  built_deb=debs[0]; built=root/'built-root'; shutil.rmtree(built,ignore_errors=True); built.mkdir(); subprocess.run(['dpkg-deb','-x',str(built_deb),str(built)],check=True)
  target=root/'target'; target_entries=filesystem_inventory(target); built_entries=filesystem_inventory(built)
  target_paths={p.relative_to(target).as_posix():p for p in target.rglob('*')}; built_paths={p.relative_to(built).as_posix():p for p in built.rglob('*')}
  for path in sorted(set(target_entries)|set(built_entries)):
   tm=target_entries.get(path); bm=built_entries.get(path); row={'path':path,'target':tm,'built':bm,'entry_equal':False}
   if tm and bm and tm['kind']==bm['kind'] and tm['mode']==bm['mode']:
    if tm['kind'] in ('directory','symlink'):
     row['entry_equal']=tm==bm
    elif tm['kind']=='file':
     tp=target_paths[path]; bp=built_paths[path]
     if tm['elf'] and bm['elf']:
      ts=section_inventory(tp); bs=section_inventory(bp); ta=normalized_allocated(ts); ba=normalized_allocated(bs)
      er={'path':path,'target_build_id':buildid(tp),'built_build_id':buildid(bp),'target_allocated_sections':ta,'built_allocated_sections':ba,'allocated_section_names_equal':set(ta)==set(ba),'allocated_sections_equal':ta==ba,'text_equal':ts.get('.text')==bs.get('.text'),'rodata_equal':ts.get('.rodata')==bs.get('.rodata'),'resources_equal':{n:v for n,v in ts.items() if n.startswith('.gresource.')}=={n:v for n,v in bs.items() if n.startswith('.gresource.')},'raw_equal':tm['sha256']==bm['sha256']}
      elf_rows.append(er); row['entry_equal']=er['allocated_sections_equal']; row['elf_comparison']=er
     elif not tm['elf'] and not bm['elf']:
      row['entry_equal']=tm['sha256']==bm['sha256'] and tm['size']==bm['size']
     else:
      row['entry_equal']=False; row['elf_type_mismatch']=True
   comparison.append(row)
  target_elf_count=sum(1 for m in target_entries.values() if m.get('kind')=='file' and m.get('elf'))
  tree_equiv=bool(comparison) and all(r['entry_equal'] for r in comparison)
  control_target=control_text(root/'downloads/target.deb'); control_built=control_text(built_deb)
  (root/'output/target-control.normalized.txt').write_text(control_target)
  (root/'output/built-control.normalized.txt').write_text(control_built)
  control_equal=control_target==control_built
  normalized_equiv=tree_equiv and control_equal and len(elf_rows)==target_elf_count and target_elf_count>0
  summary.update({'build_succeeded':True,'built_deb':built_deb.name,'built_deb_sha256':sha(built_deb),'target_entry_count':len(target_entries),'built_entry_count':len(built_entries),'entry_mismatch_count':sum(not r['entry_equal'] for r in comparison),'target_elf_count':target_elf_count,'compared_elf_count':len(elf_rows),'control_fields_equal':control_equal,'filesystem_and_payload_equal':tree_equiv,'elf_allocated_sections_equal':bool(elf_rows) and all(r['allocated_sections_equal'] for r in elf_rows),'amd64_normalized_equivalence_verified':normalized_equiv,'native_arm64_candidate_build_allowed':normalized_equiv,'next_action':'build and verify an explicitly provisional native ARM64 candidate; promotion remains disabled' if normalized_equiv else 'inspect candidate control, filesystem, payload, and allocated ELF-section differences'})
 else:
  summary.update({'build_error':'built package selection failed','built_package_candidate_count':len(debs),'next_action':'inspect build-output package naming and build log'})
else:
 summary.update({'build_error':'Debian bullseye build failed','next_action':'repair candidate build inputs or dependency environment'})
(root/'output/payload-comparison.json').write_text(json.dumps(comparison,indent=2,sort_keys=True)+'\n')
(root/'output/elf-section-comparison.json').write_text(json.dumps(elf_rows,indent=2,sort_keys=True)+'\n')
(root/'output/summary.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n')
print(json.dumps(summary,indent=2,sort_keys=True))
PY
find "$ROOT/output" -type f -printf '%P\t%s\n' | LC_ALL=C sort > "$ROOT/output/FILE-INVENTORY.tsv"
(
 cd "$ROOT/output"
 find . -type f ! -name LOCKSUMS.sha256 -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > LOCKSUMS.sha256
 sha256sum --check --strict LOCKSUMS.sha256
)
cat "$ROOT/output/summary.json"
