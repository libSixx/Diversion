import sys
import os
import json
import time
import shutil
import threading
from collections import defaultdict

import dearpygui.dearpygui as dpg
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ====================== CATPPUCCIN MOCHA (PINK ACCENT) ======================
def _hex(h):
    h = h.lstrip("#")
    return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))


CAT = {
    "rosewater": _hex("f5e0dc"),
    "flamingo":  _hex("f2cdcd"),
    "pink":      _hex("f5c2e7"),
    "mauve":     _hex("cba6f7"),
    "red":       _hex("f38ba8"),
    "maroon":    _hex("eba0ac"),
    "peach":     _hex("fab387"),
    "yellow":    _hex("f9e2af"),
    "green":     _hex("a6e3a1"),
    "teal":      _hex("94e2d5"),
    "sky":       _hex("89dceb"),
    "sapphire":  _hex("74c7ec"),
    "blue":      _hex("89b4fa"),
    "lavender":  _hex("b4befe"),
    "text":      _hex("cdd6f4"),
    "subtext1":  _hex("bac2de"),
    "subtext0":  _hex("a6adc8"),
    "overlay2":  _hex("9399b2"),
    "overlay1":  _hex("7f849c"),
    "overlay0":  _hex("6c7086"),
    "surface2":  _hex("585b70"),
    "surface1":  _hex("45475a"),
    "surface0":  _hex("313244"),
    "base":      _hex("1e1e2e"),
    "mantle":    _hex("181825"),
    "crust":     _hex("11111b"),
}


class FlagBrowserDemo:
    def get_app_dir(self):
        if getattr(sys, "frozen", False):
            return os.path.dirname(sys.executable)
        return os.path.dirname(os.path.abspath(__file__))

    def __init__(self):
        self.APP_DIR = self.get_app_dir()
        self.DEFAULT_JSON_PATH = os.path.join(self.APP_DIR, "flags_demo.json")
        self.JSON_PATH = self.DEFAULT_JSON_PATH

        self.FLAGS_URL = "https://raw.githubusercontent.com/MaximumADHD/Roblox-Client-Tracker/refs/heads/roblox/FVariables.txt"

        self.flags_list = []
        self.settings = {}
        self.selected_flag = None
        self.modified_search_query = ""

        self.appsettings_filter_query = ""
        self.appsettings_category = "local"
        self.appsettings_flag_groups = {}
        self.all_appsettings_flags = []

        self.notification_timer = None
        self.log_entries = []
        self.active_panel = "flag_browser"

        self.create_default_json_if_needed()
        self.load_json_data()
        self.fetch_flags()

        self.setup_gui()

    # ====================== JSON DATA ======================
    def create_default_json_if_needed(self):
        if not os.path.exists(self.JSON_PATH):
            with open(self.JSON_PATH, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "applicationSettings": {},
                        "disabledFlags": {},
                        "flagOrder": [],
                        "originalApplicationSettings": {},
                    },
                    f,
                    indent=4,
                )

    def load_json_data(self):
        try:
            with open(self.JSON_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = {}
        data.setdefault("applicationSettings", {})
        data.setdefault("disabledFlags", {})
        data.setdefault("flagOrder", [])
        data.setdefault("originalApplicationSettings", {})
        self.settings = data

    def save_json(self):
        save_data = self.settings.copy()
        save_data["flagOrder"] = [
            f
            for f in save_data.get("flagOrder", [])
            if f in save_data.get("applicationSettings", {})
            or f in save_data.get("disabledFlags", {})
        ]
        with open(self.JSON_PATH, "w", encoding="utf-8") as f:
            json.dump(save_data, f, indent=4)

    # ====================== FLAG NAME LIST (names only, no traffic tampering) ======================
    def fetch_flags(self):
        try:
            r = requests.get(self.FLAGS_URL, verify=False, timeout=10)
            lines = r.text.split("\n")
            flags = []
            for line in lines:
                if line.startswith(("[C++]", "[Lua]")) and " " in line:
                    flag = line.split(" ", 1)[1].strip()
                    if not flag.startswith(("DFLog", "FLog")) and "_" not in flag:
                        flags.append(flag)
            self.flags_list = sorted(flags)
        except Exception as e:
            print(f"Error fetching flags: {e}")
            self.flags_list = []

    # ====================== FEEDBACK ======================
    def show_feedback(self, message, color):
        if self.notification_timer:
            try:
                self.notification_timer.cancel()
            except Exception:
                pass
        if dpg.does_item_exist("json_feedback"):
            dpg.set_value("json_feedback", message)
            dpg.configure_item("json_feedback", color=color)
        self.notification_timer = threading.Timer(5.0, self.hide_feedback)
        self.notification_timer.daemon = True
        self.notification_timer.start()
        level = "SUCCESS" if list(color) == list(CAT["green"]) else (
            "ERROR" if list(color) == list(CAT["red"]) else "INFO")
        self.log(message, level=level)

    def hide_feedback(self):
        if dpg.does_item_exist("json_feedback"):
            dpg.set_value("json_feedback", "")

    # ====================== LOG CONSOLE ======================
    def log(self, message, level="INFO"):
        ts = time.strftime("%H:%M:%S")
        entry = (ts, level, message)
        self.log_entries.append(entry)
        if len(self.log_entries) > 300:
            self.log_entries = self.log_entries[-300:]
        self._append_log_line(entry)

    def _log_color(self, level):
        return {
            "INFO": CAT["subtext1"],
            "WARNING": CAT["peach"],
            "ERROR": CAT["red"],
            "SUCCESS": CAT["green"],
        }.get(level, CAT["subtext1"])

    def _append_log_line(self, entry):
        if not dpg.does_item_exist("app_log_list"):
            return
        ts, level, message = entry
        with dpg.group(horizontal=True, parent="app_log_list"):
            dpg.add_text(f"[{ts}]", color=CAT["overlay0"])
            dpg.add_text(f"[{level}]", color=self._log_color(level))
            dpg.add_text(message, color=CAT["text"])

    def clear_log(self, sender=None, app_data=None):
        self.log_entries.clear()
        if dpg.does_item_exist("app_log_list"):
            dpg.delete_item("app_log_list", children_only=True)

    def center_popup(self, tag):
        try:
            vp_w = dpg.get_viewport_width()
            vp_h = dpg.get_viewport_height()
            win_w = dpg.get_item_width(tag)
            win_h = dpg.get_item_height(tag)
            x = (vp_w - win_w) // 2
            y = (vp_h - win_h) // 2
            dpg.set_item_pos(tag, [max(20, x), max(20, y)])
        except Exception:
            pass

    # ====================== THEME ======================
    def create_theme(self):
        """Catppuccin Mocha, pink accent. Applied globally; this is a normal
        decorated/resizable window, not an overlay."""
        with dpg.theme() as theme:
            with dpg.theme_component(dpg.mvAll):
                dpg.add_theme_color(dpg.mvThemeCol_WindowBg, CAT["base"])
                dpg.add_theme_color(dpg.mvThemeCol_ChildBg, CAT["mantle"])
                dpg.add_theme_color(dpg.mvThemeCol_PopupBg, CAT["mantle"])
                dpg.add_theme_color(dpg.mvThemeCol_Border, CAT["surface1"])
                dpg.add_theme_color(dpg.mvThemeCol_BorderShadow, CAT["crust"])

                dpg.add_theme_color(dpg.mvThemeCol_Text, CAT["text"])
                dpg.add_theme_color(dpg.mvThemeCol_TextDisabled, CAT["overlay0"])

                dpg.add_theme_color(dpg.mvThemeCol_FrameBg, CAT["surface0"])
                dpg.add_theme_color(dpg.mvThemeCol_FrameBgHovered, CAT["surface1"])
                dpg.add_theme_color(dpg.mvThemeCol_FrameBgActive, CAT["surface2"])

                dpg.add_theme_color(dpg.mvThemeCol_TitleBg, CAT["crust"])
                dpg.add_theme_color(dpg.mvThemeCol_TitleBgActive, CAT["surface0"])
                dpg.add_theme_color(dpg.mvThemeCol_TitleBgCollapsed, CAT["crust"])

                dpg.add_theme_color(dpg.mvThemeCol_MenuBarBg, CAT["mantle"])

                dpg.add_theme_color(dpg.mvThemeCol_ScrollbarBg, CAT["mantle"])
                dpg.add_theme_color(dpg.mvThemeCol_ScrollbarGrab, CAT["surface2"])
                dpg.add_theme_color(dpg.mvThemeCol_ScrollbarGrabHovered, CAT["pink"])
                dpg.add_theme_color(dpg.mvThemeCol_ScrollbarGrabActive, CAT["mauve"])

                dpg.add_theme_color(dpg.mvThemeCol_CheckMark, CAT["pink"])
                dpg.add_theme_color(dpg.mvThemeCol_SliderGrab, CAT["pink"])
                dpg.add_theme_color(dpg.mvThemeCol_SliderGrabActive, CAT["mauve"])

                dpg.add_theme_color(dpg.mvThemeCol_Button, CAT["surface1"])
                dpg.add_theme_color(dpg.mvThemeCol_ButtonHovered, CAT["pink"])
                dpg.add_theme_color(dpg.mvThemeCol_ButtonActive, CAT["mauve"])

                dpg.add_theme_color(dpg.mvThemeCol_Header, CAT["surface1"])
                dpg.add_theme_color(dpg.mvThemeCol_HeaderHovered, CAT["pink"])
                dpg.add_theme_color(dpg.mvThemeCol_HeaderActive, CAT["mauve"])

                dpg.add_theme_color(dpg.mvThemeCol_Separator, CAT["surface1"])
                dpg.add_theme_color(dpg.mvThemeCol_SeparatorHovered, CAT["pink"])
                dpg.add_theme_color(dpg.mvThemeCol_SeparatorActive, CAT["mauve"])

                dpg.add_theme_color(dpg.mvThemeCol_ResizeGrip, CAT["surface2"])
                dpg.add_theme_color(dpg.mvThemeCol_ResizeGripHovered, CAT["pink"])
                dpg.add_theme_color(dpg.mvThemeCol_ResizeGripActive, CAT["mauve"])

                dpg.add_theme_color(dpg.mvThemeCol_Tab, CAT["surface0"])
                dpg.add_theme_color(dpg.mvThemeCol_TabHovered, CAT["pink"])
                dpg.add_theme_color(dpg.mvThemeCol_TabActive, CAT["surface2"])
                dpg.add_theme_color(dpg.mvThemeCol_TabUnfocused, CAT["surface0"])
                dpg.add_theme_color(dpg.mvThemeCol_TabUnfocusedActive, CAT["surface1"])

                dpg.add_theme_style(dpg.mvStyleVar_WindowRounding, 8)
                dpg.add_theme_style(dpg.mvStyleVar_ChildRounding, 6)
                dpg.add_theme_style(dpg.mvStyleVar_FrameRounding, 5)
                dpg.add_theme_style(dpg.mvStyleVar_PopupRounding, 6)
                dpg.add_theme_style(dpg.mvStyleVar_ScrollbarRounding, 8)
                dpg.add_theme_style(dpg.mvStyleVar_GrabRounding, 5)
                dpg.add_theme_style(dpg.mvStyleVar_TabRounding, 5)
                dpg.add_theme_style(dpg.mvStyleVar_FramePadding, 8, 4)
                dpg.add_theme_style(dpg.mvStyleVar_ItemSpacing, 8, 6)

        dpg.bind_theme(theme)

    # ====================== GUI SETUP ======================
    def setup_gui(self):
        dpg.create_context()
        dpg.create_viewport(title="Flag Browser Dashboard - Demo (Catppuccin Mocha Pink)",
                             width=1280, height=800)
        dpg.setup_dearpygui()

        self.create_theme()
        self.create_dashboard()

        dpg.set_primary_window("root_window", True)
        dpg.show_viewport()
        self.log("Application started")
        self.log("Loading configuration")
        self.log(f"JSON file: {self.JSON_PATH}")
        if not self.flags_list:
            self.log("Flag name list is empty (fetch may have failed)", level="WARNING")
        else:
            self.log(f"Loaded {len(self.flags_list)} known flag names", level="SUCCESS")

    def create_dashboard(self):
        """One all-in-one docked window: sidebar nav, main content panel that
        swaps between Flag Browser / ApplicationSettings, and a log console
        docked at the bottom -- styled after the DearPyGui demo layout."""
        with dpg.window(tag="root_window", no_title_bar=True, no_move=True,
                         no_resize=True, no_collapse=True, no_scrollbar=True):
            with dpg.group(horizontal=True):
                # ---- Sidebar ----
                with dpg.child_window(tag="sidebar", width=190, height=-165):
                    dpg.add_text("PANELS", color=CAT["overlay1"])
                    dpg.add_separator()
                    dpg.add_selectable(label="  Flag Browser", tag="nav_flag_browser",
                                        default_value=True,
                                        callback=lambda: self.switch_panel("flag_browser"))
                    dpg.add_selectable(label="  ApplicationSettings", tag="nav_app_settings",
                                        callback=lambda: self.switch_panel("app_settings"))
                    dpg.add_spacer(height=10)
                    dpg.add_separator()
                    dpg.add_spacer(height=10)
                    dpg.add_text("STATUS", color=CAT["overlay1"])
                    dpg.add_separator()
                    with dpg.group(horizontal=True):
                        dpg.add_text("●", color=CAT["green"])
                        dpg.add_text("Local JSON demo")
                    dpg.add_text(f"{len(self.flags_list)} known flags", color=CAT["subtext0"],
                                 tag="sidebar_flag_count")

                # ---- Main content ----
                with dpg.child_window(tag="main_panel_area", width=-1, height=-165):
                    self.create_flag_browser_panel()
                    self.create_application_settings_panel()

            # ---- Bottom: Application Log ----
            with dpg.child_window(tag="log_panel", height=155, autosize_x=True):
                with dpg.group(horizontal=True):
                    dpg.add_text("Application Log", color=CAT["pink"])
                    dpg.add_spacer(width=10)
                    dpg.add_button(label="Clear", small=True, callback=self.clear_log)
                dpg.add_separator()
                with dpg.child_window(tag="app_log_list", autosize_x=True, autosize_y=True):
                    pass

            dpg.add_separator()
            with dpg.group(horizontal=True):
                dpg.add_text("© 2026 Flag Browser | Made by lumyna.cc", color=CAT["pink"])
                dpg.add_text("  •  Catppuccin Mocha (Pink)  •  Demo build, no network interception",
                             color=CAT["overlay0"])

        with dpg.item_handler_registry(tag="root_resize_handler"):
            pass

    def switch_panel(self, panel):
        self.active_panel = panel
        dpg.configure_item("flag_browser_panel", show=(panel == "flag_browser"))
        dpg.configure_item("app_settings_panel", show=(panel == "app_settings"))
        dpg.set_value("nav_flag_browser", panel == "flag_browser")
        dpg.set_value("nav_app_settings", panel == "app_settings")

    # ====================== FLAG BROWSER PANEL ======================
    def create_flag_browser_panel(self):
        with dpg.group(tag="flag_browser_panel", show=True):
            with dpg.group(horizontal=True):
                dpg.add_text("Flag Browser", color=CAT["pink"])
                dpg.add_spacer(width=8)
                dpg.add_text("browse, search, and set flag values", color=CAT["overlay1"])
            dpg.add_separator()

            with dpg.group(horizontal=True):
                # --- Left: available flags + editor ---
                with dpg.child_window(width=430, height=-1):
                    dpg.add_text("Available Flags")
                    dpg.add_input_text(callback=self.update_search, width=-1,
                                        tag="search_input", hint="Search")

                    with dpg.child_window(tag="available_flags_list", height=220):
                        self.update_flag_list()

                    dpg.add_spacer(height=8)
                    dpg.add_text("Selected Flag: None", tag="selected_flag_text")

                    with dpg.group(horizontal=True, tag="value_group"):
                        dpg.add_input_text(tag="flag_value_input", width=-150, hint="Value")

                    dpg.add_button(label="Set Value", callback=self.set_flag_value)

                    dpg.add_spacer(height=10)
                    dpg.add_separator()
                    dpg.add_spacer(height=6)

                    dpg.add_text("JSON Path", color=CAT["overlay1"])
                    dpg.add_input_text(default_value=self.JSON_PATH, readonly=True,
                                        tag="json_path_input", width=-1)
                    with dpg.group(horizontal=True):
                        dpg.add_button(label="Refresh Flag Names", callback=self.fetch_flags_manual)
                        dpg.add_button(label="Clear All Modified Flags", callback=self.show_clear_confirmation)
                    dpg.add_text("", tag="json_feedback")

                # --- Right: modified flags ---
                with dpg.child_window(width=-1, height=-1):
                    with dpg.group(horizontal=True):
                        dpg.add_text("Modified Flags")
                        dpg.add_input_text(hint="Search", callback=self.update_modified_search,
                                            width=-1, tag="modified_search_input")
                    dpg.add_separator()
                    with dpg.child_window(tag="enabled_flags_list", autosize_x=True, autosize_y=True):
                        self.update_enabled_flags_list()

    def fetch_flags_manual(self, sender=None, app_data=None):
        self.fetch_flags()
        self.update_flag_list()
        if dpg.does_item_exist("sidebar_flag_count"):
            dpg.set_value("sidebar_flag_count", f"{len(self.flags_list)} known flags")
        self.show_feedback("Flag names refreshed.", list(CAT["green"]))
        self.log(f"Refreshed flag names ({len(self.flags_list)} loaded)", level="SUCCESS")

    # ---- Flag list ----
    def update_flag_list(self, query=""):
        if not dpg.does_item_exist("available_flags_list"):
            return
        dpg.delete_item("available_flags_list", children_only=True)
        q = query.lower()
        for flag in self.flags_list:
            if q in flag.lower():
                dpg.add_button(label=flag, parent="available_flags_list",
                               callback=self.select_flag, user_data=flag)

    def update_search(self, s, data):
        self.update_flag_list(data)

    def is_boolean_flag(self, flag):
        return bool(flag) and flag.startswith(("DFFlag", "FFlag", "SFFlag"))

    def get_effective_value(self, flag):
        app_settings = self.settings.get("applicationSettings", {})
        disabled_flags = self.settings.get("disabledFlags", {})
        original = self.settings.get("originalApplicationSettings", {})
        if flag in app_settings:
            return app_settings[flag]
        if flag in disabled_flags:
            return disabled_flags[flag]
        if flag in original:
            return original[flag]
        return ""

    def should_use_boolean_widget(self, flag):
        if not self.is_boolean_flag(flag):
            return False
        value = str(self.get_effective_value(flag)).strip()
        if ";" in value or len(value.split()) > 1 or (value.isdigit() and len(value) > 2):
            return False
        return True

    def replace_value_widget(self):
        if not dpg.does_item_exist("value_group"):
            return
        dpg.delete_item("value_group", children_only=True)
        if self.selected_flag and self.should_use_boolean_widget(self.selected_flag):
            dpg.add_button(label="False", tag="flag_value_bool_button", width=-150,
                            callback=self.toggle_bool_value, parent="value_group")
        else:
            dpg.add_input_text(tag="flag_value_input", width=-150, hint="Value", parent="value_group")

    def toggle_bool_value(self, sender, app_data):
        if dpg.does_item_exist("flag_value_bool_button"):
            current = dpg.get_item_label("flag_value_bool_button")
            dpg.set_item_label("flag_value_bool_button", "True" if current == "False" else "False")

    def select_flag(self, s, a, flag):
        self.selected_flag = flag
        dpg.set_value("selected_flag_text", f"Selected Flag: {flag}")
        self.replace_value_widget()
        current_val = self.get_effective_value(flag)
        if self.should_use_boolean_widget(flag) and dpg.does_item_exist("flag_value_bool_button"):
            bool_val = str(current_val).lower() in ("true", "1")
            dpg.set_item_label("flag_value_bool_button", "True" if bool_val else "False")
        elif dpg.does_item_exist("flag_value_input"):
            dpg.set_value("flag_value_input", str(current_val))

    def set_flag_value(self, s, a):
        if not self.selected_flag:
            return
        if self.should_use_boolean_widget(self.selected_flag) and dpg.does_item_exist("flag_value_bool_button"):
            val = dpg.get_item_label("flag_value_bool_button")
        elif dpg.does_item_exist("flag_value_input"):
            val = dpg.get_value("flag_value_input")
        else:
            val = ""
        self.save_flag(self.selected_flag, val)
        dpg.delete_item("value_group", children_only=True)
        dpg.add_input_text(tag="flag_value_input", width=-150, hint="Value", parent="value_group")
        self.selected_flag = None
        dpg.set_value("selected_flag_text", "Selected Flag: None")

    def save_flag(self, name, value):
        if name not in self.settings.get("flagOrder", []):
            self.settings.setdefault("flagOrder", []).append(name)
        if name in self.settings.get("disabledFlags", {}):
            self.settings["disabledFlags"][name] = value
        else:
            self.settings["applicationSettings"][name] = value
        self.save_json()
        self.update_enabled_flags_list()
        self.update_appsettings_modified_indicator_cached(name)

    # ---- Modified flags list ----
    def update_modified_search(self, s, data):
        self.modified_search_query = data.lower() if data else ""
        self.update_enabled_flags_list()

    def create_edit_widget_for_flag(self, flag, parent):
        if self.should_use_boolean_widget(flag):
            current_val = self.get_effective_value(flag)
            bool_val = str(current_val).lower() in ("true", "1")
            dpg.add_button(label="True" if bool_val else "False",
                            tag=f"edit_bool_button_{flag}", width=-130,
                            callback=self.toggle_edit_bool_value, user_data=flag, parent=parent)
        else:
            dpg.add_input_text(tag=f"edit_value_{flag}", default_value="", width=-130,
                                hint="New Value", parent=parent)

    def toggle_edit_bool_value(self, sender, app_data, flag):
        if dpg.does_item_exist(f"edit_bool_button_{flag}"):
            current = dpg.get_item_label(f"edit_bool_button_{flag}")
            dpg.set_item_label(f"edit_bool_button_{flag}", "True" if current == "False" else "False")

    def update_enabled_flags_list(self):
        if not dpg.does_item_exist("enabled_flags_list"):
            return
        dpg.delete_item("enabled_flags_list", children_only=True)
        flag_order = self.settings.setdefault("flagOrder", [])
        search = self.modified_search_query

        for index, flag in enumerate(flag_order):
            if search and search not in flag.lower():
                continue
            enabled = flag in self.settings.get("applicationSettings", {})
            val = self.get_effective_value(flag)

            with dpg.group(parent="enabled_flags_list"):
                dpg.add_input_text(default_value=f"{flag}: {val}", readonly=True, width=-1)
                with dpg.group(horizontal=True):
                    self.create_edit_widget_for_flag(flag, dpg.last_item())
                    dpg.add_button(label="Update Value", callback=self.update_flag_value, user_data=flag)
                with dpg.group(horizontal=True):
                    dpg.add_checkbox(label="Enabled", default_value=enabled,
                                      callback=self.toggle_flag_visibility, user_data=flag)
                    dpg.add_button(label="Remove", callback=self.remove_flag, user_data=flag)

            if index < len(flag_order) - 1:
                dpg.add_spacer(height=10, parent="enabled_flags_list")

    def update_flag_value(self, s, a, flag):
        if self.should_use_boolean_widget(flag) and dpg.does_item_exist(f"edit_bool_button_{flag}"):
            new_val = dpg.get_item_label(f"edit_bool_button_{flag}")
        else:
            new_val = dpg.get_value(f"edit_value_{flag}")
        if new_val is not None and str(new_val).strip() != "":
            if flag in self.settings.get("applicationSettings", {}):
                self.settings["applicationSettings"][flag] = new_val
            else:
                self.settings["disabledFlags"][flag] = new_val
            self.save_json()
            self.update_enabled_flags_list()
            self.update_appsettings_modified_indicator_cached(flag)

    def toggle_flag_visibility(self, s, a, flag):
        if flag in self.settings.get("applicationSettings", {}):
            self.settings["disabledFlags"][flag] = self.settings["applicationSettings"].pop(flag)
        else:
            self.settings["applicationSettings"][flag] = self.settings["disabledFlags"].pop(flag)
        if flag not in self.settings.get("flagOrder", []):
            self.settings.setdefault("flagOrder", []).append(flag)
        self.save_json()
        self.update_enabled_flags_list()
        self.update_appsettings_modified_indicator_cached(flag)

    def remove_flag(self, s, a, flag):
        original = self.settings.get("originalApplicationSettings", {})
        app_settings = self.settings["applicationSettings"]
        disabled_flags = self.settings["disabledFlags"]
        if flag in original:
            app_settings[flag] = original[flag]
            disabled_flags.pop(flag, None)
        else:
            app_settings.pop(flag, None)
            disabled_flags.pop(flag, None)
        if flag in self.settings.get("flagOrder", []):
            self.settings["flagOrder"].remove(flag)
        self.save_json()
        self.update_enabled_flags_list()
        self.update_appsettings_modified_indicator_cached(flag)
        self.show_feedback(f"Removed '{flag}'.", list(CAT["green"]))

    def show_clear_confirmation(self, s, a):
        if dpg.does_item_exist("clear_confirm_popup"):
            dpg.show_item("clear_confirm_popup")
            self.center_popup("clear_confirm_popup")
            return
        with dpg.window(label="Confirm Clear", modal=True, no_resize=True, no_close=True,
                         width=400, height=140, tag="clear_confirm_popup"):
            dpg.add_text("Remove all modified flags?", wrap=370)
            dpg.add_spacer(height=15)
            with dpg.group(horizontal=True):
                dpg.add_button(label="Yes", width=80, callback=self.clear_all_flags_confirmed)
                dpg.add_button(label="No", width=80, callback=lambda: dpg.delete_item("clear_confirm_popup"))
        self.center_popup("clear_confirm_popup")

    def clear_all_flags_confirmed(self, s, a):
        dpg.delete_item("clear_confirm_popup")
        original = self.settings.get("originalApplicationSettings", {})
        app_settings = self.settings["applicationSettings"]
        disabled_flags = self.settings["disabledFlags"]
        flag_order = list(self.settings.get("flagOrder", []))
        for flag in flag_order:
            if flag in original:
                app_settings[flag] = original[flag]
                disabled_flags.pop(flag, None)
            else:
                app_settings.pop(flag, None)
                disabled_flags.pop(flag, None)
            self.update_appsettings_modified_indicator_cached(flag)
        self.settings["flagOrder"] = []
        self.save_json()
        self.update_enabled_flags_list()
        self.show_feedback(f"Cleared {len(flag_order)} modified flags.", list(CAT["green"]))

    # ====================== APPLICATION SETTINGS PANEL ======================
    def create_application_settings_panel(self):
        with dpg.group(tag="app_settings_panel", show=False):
            with dpg.group(horizontal=True):
                dpg.add_text("ApplicationSettings", color=CAT["pink"])
                dpg.add_spacer(width=8)
                dpg.add_text("filter, categorize, and edit values inline", color=CAT["overlay1"])
            dpg.add_separator()

            with dpg.group(horizontal=True):
                dpg.add_input_text(tag="appsettings_filter_input", hint="filter", width=-200,
                                    callback=self.update_appsettings_filter)
                dpg.add_button(label="Clear", callback=self.clear_appsettings_filter)

            dpg.add_radio_button(items=["Local", "Dynamic", "Static"], default_value="Local",
                                  callback=self.set_appsettings_category,
                                  tag="appsettings_category_radio", horizontal=True)
            dpg.add_spacer(height=4)

            with dpg.child_window(tag="appsettings_list", autosize_x=True, autosize_y=True):
                pass

            self.refresh_application_settings_list()

    def refresh_application_settings_list(self, sender=None, app_data=None):
        if not dpg.does_item_exist("appsettings_list"):
            return
        self.appsettings_flag_groups.clear()
        dpg.delete_item("appsettings_list", children_only=True)

        app_settings = self.settings.get("applicationSettings", {})
        disabled_flags = self.settings.get("disabledFlags", {})
        original = self.settings.get("originalApplicationSettings", {})

        combined = original.copy()
        for flag, value in app_settings.items():
            if flag in original:
                combined[flag] = value
        for flag, value in disabled_flags.items():
            if flag in original:
                combined[flag] = value

        if not combined:
            dpg.add_text("No ApplicationSettings loaded. Use the Flag Browser to add some.",
                          parent="appsettings_list")
            return

        allowed_prefixes = ("DF", "FF", "FInt", "FS", "SF")
        self.all_appsettings_flags = sorted(
            f for f in combined
            if any(f.startswith(p) for p in allowed_prefixes) and not f.startswith(("DFLog", "FLog"))
        )

        for flag in self.all_appsettings_flags:
            value = combined[flag]
            orig_val = original.get(flag, "N/A")
            is_modified = str(value) != str(orig_val) and orig_val != "N/A"

            group_tag = f"appsettings_group_{flag}"
            with dpg.group(parent="appsettings_list", horizontal=True, tag=group_tag):
                self.create_appsettings_value_widget(flag, value)
                dpg.add_text(flag)
                if is_modified:
                    dpg.add_text("*", color=CAT["pink"], tag=f"appsettings_asterisk_{flag}")

            self.appsettings_flag_groups[flag] = {
                "group": group_tag, "is_modified": is_modified, "visible": True
            }

        self._apply_appsettings_filter()

    def is_integer_flag(self, flag):
        return bool(flag) and flag.startswith(("DFInt", "FInt"))

    def create_appsettings_value_widget(self, flag, value=None):
        if value is None:
            value = self.get_effective_value(flag)

        if self.is_integer_flag(flag):
            dpg.add_input_text(default_value=str(value), width=150,
                                tag=f"appsettings_int_input_{flag}",
                                callback=self.update_appsettings_value, user_data=flag)
            dpg.add_button(label="+", width=20, callback=self.increment_appsettings_int, user_data=flag)
            dpg.add_button(label="-", width=20, callback=self.decrement_appsettings_int, user_data=flag)
        elif self.should_use_boolean_widget(flag):
            bool_val = str(value).lower() in ("true", "1")
            dpg.add_button(label="True" if bool_val else "False",
                            tag=f"appsettings_bool_button_{flag}", width=198.5,
                            callback=self.toggle_appsettings_bool, user_data=flag)
        else:
            dpg.add_input_text(default_value=str(value), width=198.5,
                                tag=f"appsettings_text_input_{flag}",
                                callback=self.update_appsettings_value, user_data=flag)

    def update_appsettings_value(self, sender, app_data, flag):
        if app_data is None:
            return
        self.settings["applicationSettings"][flag] = app_data
        self.settings["disabledFlags"].pop(flag, None)
        self.save_json()
        self.update_enabled_flags_list()
        self.update_appsettings_modified_indicator_cached(flag)

    def increment_appsettings_int(self, sender, app_data, flag):
        self._bump_int(flag, 1)

    def decrement_appsettings_int(self, sender, app_data, flag):
        self._bump_int(flag, -1)

    def _bump_int(self, flag, delta):
        try:
            current = int(self.get_effective_value(flag) or 0)
        except ValueError:
            current = 0
        new_value = str(current + delta)
        self.settings["applicationSettings"][flag] = new_value
        self.settings["disabledFlags"].pop(flag, None)
        self.save_json()
        if dpg.does_item_exist(f"appsettings_int_input_{flag}"):
            dpg.set_value(f"appsettings_int_input_{flag}", new_value)
        self.update_enabled_flags_list()
        self.update_appsettings_modified_indicator_cached(flag)

    def toggle_appsettings_bool(self, sender, app_data, flag):
        if not dpg.does_item_exist(f"appsettings_bool_button_{flag}"):
            return
        current = dpg.get_item_label(f"appsettings_bool_button_{flag}")
        new_label = "True" if current == "False" else "False"
        dpg.set_item_label(f"appsettings_bool_button_{flag}", new_label)
        self.settings["applicationSettings"][flag] = new_label
        self.settings["disabledFlags"].pop(flag, None)
        self.save_json()
        self.update_enabled_flags_list()
        self.update_appsettings_modified_indicator_cached(flag)

    def update_appsettings_modified_indicator_cached(self, flag):
        if flag not in self.appsettings_flag_groups:
            return
        original = self.settings.get("originalApplicationSettings", {})
        current_value = self.get_effective_value(flag)
        orig_val = original.get(flag, "N/A")
        is_modified = str(current_value) != str(orig_val) and orig_val != "N/A"

        cache_entry = self.appsettings_flag_groups[flag]
        was_modified = cache_entry["is_modified"]
        asterisk_tag = f"appsettings_asterisk_{flag}"
        group_tag = cache_entry["group"]

        if self.is_integer_flag(flag):
            if dpg.does_item_exist(f"appsettings_int_input_{flag}"):
                dpg.set_value(f"appsettings_int_input_{flag}", str(current_value))
        elif self.is_boolean_flag(flag):
            if dpg.does_item_exist(f"appsettings_bool_button_{flag}"):
                bool_val = str(current_value).lower() in ("true", "1")
                dpg.set_item_label(f"appsettings_bool_button_{flag}", "True" if bool_val else "False")
        else:
            if dpg.does_item_exist(f"appsettings_text_input_{flag}"):
                dpg.set_value(f"appsettings_text_input_{flag}", str(current_value))

        if is_modified and not was_modified:
            if dpg.does_item_exist(group_tag):
                dpg.add_text("*", color=CAT["pink"], tag=asterisk_tag, parent=group_tag)
            cache_entry["is_modified"] = True
        elif not is_modified and was_modified:
            if dpg.does_item_exist(asterisk_tag):
                dpg.delete_item(asterisk_tag)
            cache_entry["is_modified"] = False

    def _apply_appsettings_filter(self):
        if not dpg.does_item_exist("appsettings_list"):
            return
        q = self.appsettings_filter_query.lower().strip()
        cat = self.appsettings_category
        original = self.settings.get("originalApplicationSettings", {})
        app_settings = self.settings.get("applicationSettings", {})
        disabled_flags = self.settings.get("disabledFlags", {})

        visible_count = 0
        for flag, cache_entry in self.appsettings_flag_groups.items():
            matches = True
            current_value = str(app_settings.get(flag, disabled_flags.get(flag, original.get(flag, ""))))
            if q and q not in flag.lower() and q not in current_value.lower():
                matches = False
            if matches:
                if cat == "dynamic" and not flag.startswith("DF"):
                    matches = False
                elif cat == "static" and not flag.startswith(("FF", "FInt", "FS", "SF")):
                    matches = False

            group_tag = cache_entry["group"]
            if dpg.does_item_exist(group_tag):
                if matches:
                    dpg.show_item(group_tag)
                    visible_count += 1
                else:
                    dpg.hide_item(group_tag)
                cache_entry["visible"] = matches

        no_flags_tag = "appsettings_no_flags_message"
        if visible_count == 0:
            if not dpg.does_item_exist(no_flags_tag):
                dpg.add_text("No flags match the current filter.", parent="appsettings_list", tag=no_flags_tag)
            else:
                dpg.show_item(no_flags_tag)
        elif dpg.does_item_exist(no_flags_tag):
            dpg.hide_item(no_flags_tag)

    def update_appsettings_filter(self, sender, app_data):
        self.appsettings_filter_query = (app_data or "").lower().strip()
        self._apply_appsettings_filter()

    def clear_appsettings_filter(self, sender=None, app_data=None):
        self.appsettings_filter_query = ""
        if dpg.does_item_exist("appsettings_filter_input"):
            dpg.set_value("appsettings_filter_input", "")
        self._apply_appsettings_filter()

    def set_appsettings_category(self, sender, app_data):
        self.appsettings_category = app_data.lower()
        self._apply_appsettings_filter()

    # ====================== RUN LOOP ======================
    def run(self):
        dpg.set_exit_callback(self.on_exit)
        while dpg.is_dearpygui_running():
            dpg.render_dearpygui_frame()
            time.sleep(1 / 60)
        dpg.destroy_context()

    def on_exit(self):
        self.save_json()


if __name__ == "__main__":
    app = FlagBrowserDemo()
    app.run()
