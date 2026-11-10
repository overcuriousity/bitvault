use std::sync::Arc;

use askama::Template;

use crate::assets::Assets;
use crate::config::Config;

pub struct NavItem {
    pub href: &'static str,
    pub label: &'static str,
    pub icon: &'static str,
    pub current: bool,
    /// Shown in the top bar only: the tab bar keeps to a few destinations.
    pub wide_only: bool,
}

/// The page frame: top bar, main region, bottom tab bar and the notices region.
#[derive(Template)]
#[template(path = "layout.html")]
pub struct Layout {
    pub title: String,
    pub current: &'static str,
    pub body: String,
    pub admin: bool,
    pub extra_css: Vec<String>,
    /// ES modules.
    pub extra_js: Vec<String>,
    /// Classic scripts, deferred, run in order before the modules (e.g. a UMD bundle).
    pub extra_scripts: Vec<String>,
    pub cfg: Arc<Config>,
}

pub const KIT_CSS: [&str; 7] = [
    "vendor/oc/css/00-tokens.css",
    "vendor/oc/css/10-base.css",
    "vendor/oc/css/20-layout.css",
    "vendor/oc/css/30-components.css",
    "vendor/oc/css/40-tables.css",
    "vendor/oc/css/50-touch.css",
    "vendor/oc/css/profile-everyday.css",
];

pub const MODULES: [&str; 8] = [
    "js/prefs.js",
    "js/pwa.js",
    "vendor/oc/js/copy.js",
    "vendor/oc/js/notices.js",
    "vendor/oc/js/menu.js",
    "vendor/oc/js/dialog.js",
    "vendor/oc/js/keys.js",
    "vendor/oc/js/busy.js",
];

impl Layout {
    fn asset(&self, path: &str) -> String {
        Assets::url(path)
    }

    fn stylesheets(&self) -> Vec<String> {
        let own = [Assets::url("css/app.css")];
        KIT_CSS.iter().map(|p| Assets::url(p)).chain(own).chain(self.extra_css.iter().cloned()).collect()
    }

    fn modules(&self) -> Vec<String> {
        MODULES.iter().map(|p| Assets::url(p)).chain(self.extra_js.iter().cloned()).collect()
    }

    fn nav(&self) -> Vec<NavItem> {
        let item =
            |href, label, icon, key| NavItem { href, label, icon, current: self.current == key, wide_only: false };
        let mut items = vec![item("/", "New", "plus", "new")];
        if self.cfg.app.listing {
            items.push(item("/list", "List", "list", "list"));
        }
        items.push(item("/guide", "Guide", "circle-question-mark", "guide"));
        items.push(NavItem { wide_only: true, ..item("/docs", "API", "file", "docs") });
        if self.admin {
            items.push(item("/admin", "Admin", "settings", "admin"));
        }
        items
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn icon(&self, name: &str) -> String {
        super::icon(name, super::IconSize::Tool)
    }

    fn logo(&self) -> String {
        Assets::get("icon.svg").map(|f| String::from_utf8_lossy(&f.data).trim_end().to_owned()).unwrap_or_default()
    }
}
