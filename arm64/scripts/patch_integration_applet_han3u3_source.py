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
