use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use common::ux::TagValue;

use crate::{
    ux::{has_page_api, step_pos},
    ux_generated,
};

/// A Handler is a function that is called when a message is received from the host, and
/// returns the app's response.
pub type Handler = fn(&mut App, &[u8]) -> Vec<u8>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum View {
    None,
    // views for the Page API
    HomePage,
    AppInfoPage,
    // views for the Step API
    HomeIntroStep,
    HomeAppInfoStep,
    HomeQuitStep,
    AppInfoStep(u8), // generic step to show the app info
}
/// The App struct represents the context of the application.
pub struct App {
    handler: Handler,
    app_name: &'static str,
    version: &'static str,
    description: Option<String>,
    // Optional developer name
    developer: Option<String>,
    // The current view being displayed.
    current_view: View,
    // Cached raw bytes for the home info page (TopRight action). Computed lazily.
    home_info_page: Option<Vec<u8>>,
    // Set to true whenever the app's ux is changed, and therefore the home page
    // must be shown again at the end of the message handler.
    ux_dirty: bool,
}

impl App {
    /// Creates a new App instance with the given handler.
    ///
    /// # Arguments
    ///
    /// * `app_name` - The name of the application.
    /// * `version` - The version of the application.
    /// * `handler` - The function to handle incoming messages.
    pub fn new(app_name: &'static str, version: &'static str, handler: Handler) -> Self {
        Self {
            handler,
            app_name,
            version,
            description: None,
            developer: None,
            home_info_page: None,
            current_view: View::None,
            ux_dirty: true, // force showing home at startup
        }
    }

    /// Sets the V-App description shown on the dashboard
    pub fn description(mut self, description: &str) -> Self {
        self.description = Some(description.to_string());
        self
    }

    /// Sets the developer name
    pub fn developer(mut self, developer: &str) -> Self {
        self.developer = Some(developer.to_string());
        self
    }

    // Pages
    fn show_page_home(&mut self) {
        let description = self
            .description
            .as_deref()
            .unwrap_or("Application is ready");

        ux_generated::show_page_home(description);

        self.current_view = View::HomePage;
    }

    fn show_page_app_info(&mut self) {
        let page_raw = self.home_info_page();
        crate::ux::show_page_raw(page_raw);
        self.current_view = View::AppInfoPage;
    }

    // Steps
    fn show_step_home_intro(&mut self) {
        let description = self
            .description
            .as_deref()
            .unwrap_or("Application is ready");

        ux_generated::show_step_text_subtext(step_pos(3, 0), description, "");

        self.current_view = View::HomeIntroStep;
    }

    fn show_step_home_app_info(&mut self) {
        ux_generated::show_step_text_subtext(step_pos(3, 1), "App Info", "");

        self.current_view = View::HomeAppInfoStep;
    }

    fn show_step_home_quit(&mut self) {
        ux_generated::show_step_text_subtext(step_pos(3, 2), "Quit", "");

        self.current_view = View::HomeQuitStep;
    }

    fn show_step_app_info(&mut self, index: u8) {
        let n_steps = self.n_appinfo_steps() as u32;
        match index {
            0 => ux_generated::show_step_btext_subtext(
                step_pos(n_steps, 0),
                "V-App Name",
                self.app_name,
            ),
            1 => {
                ux_generated::show_step_btext_subtext(step_pos(n_steps, 1), "Version", self.version)
            }
            2 if self.developer.is_some() => ux_generated::show_step_btext_subtext(
                step_pos(n_steps, 2),
                "Developer",
                self.developer.as_deref().unwrap(),
            ),
            i if i == (n_steps - 1) as u8 => {
                ux_generated::show_step_text_subtext(step_pos(n_steps, n_steps - 1), "Back", "")
            }
            _ => panic!("Invalid app info step index"),
        }

        self.current_view = View::AppInfoStep(index);
    }

    fn n_appinfo_steps(&self) -> u8 {
        // app name, app version, optionally developer name, back button
        3 + self.developer.is_some() as u8
    }

    /// This function shows the dashboard, then enters the core loop of the app.
    /// It never returns, as it keeps the app running until sdk::exit() is called,
    /// or a fatal error occurs.
    pub fn run(&mut self) -> ! {
        use common::ux::Action::*;
        use common::ux::Event::Action;

        loop {
            if self.ux_dirty {
                // TODO: when the previous view is finished but ended with an on-screen notification
                // shown for a few seconds, we shouldn't immediately show the home at this point. This
                // will require a smarter state machine.
                if has_page_api() {
                    self.show_page_home();
                } else {
                    self.show_step_home_intro();
                }
                self.ux_dirty = false;
            }

            let ev = crate::ux::get_event();
            match (self.current_view, ev) {
                // Page API navigation
                (View::HomePage, Action(Quit)) => crate::ecalls::exit(0),
                (View::HomePage, Action(TopRight)) => self.show_page_app_info(),
                (View::AppInfoPage, Action(Quit)) => self.show_page_home(),
                // Step API navigation
                (View::HomeIntroStep, Action(NextPage)) => self.show_step_home_app_info(),
                (View::HomeAppInfoStep, Action(PreviousPage)) => self.show_step_home_intro(),
                (View::HomeAppInfoStep, Action(Confirm)) => self.show_step_app_info(0),
                (View::HomeAppInfoStep, Action(NextPage)) => self.show_step_home_quit(),
                (View::HomeQuitStep, Action(PreviousPage)) => self.show_step_home_app_info(),
                (View::HomeQuitStep, Action(Confirm)) => crate::ecalls::exit(0),
                (View::AppInfoStep(n), Action(NextPage)) => {
                    if n + 1 < self.n_appinfo_steps() {
                        self.show_step_app_info(n + 1);
                    }
                }
                (View::AppInfoStep(n), Action(Confirm)) => {
                    if n == self.n_appinfo_steps() - 1 {
                        self.show_step_home_app_info();
                    }
                }
                (View::AppInfoStep(n), Action(PreviousPage)) => {
                    if n > 0 {
                        self.show_step_app_info(n - 1);
                    }
                }
                (view, ev) => {
                    crate::println!("Unhandled event {:?} in view {:?}", ev, view);
                }
            }

            let req_msg = match crate::comm::receive_message() {
                Ok(msg) => msg,
                Err(crate::comm::MessageError::NoMessage) => continue, // TODO: should we wait before retrying, to avoid spamming the channel?
                Err(e) => panic!("Communication error: {}", e),
            };
            let resp_msg = (self.handler)(self, &req_msg);
            crate::comm::send_message(&resp_msg);
        }
    }

    /// This is only useful to produce a valid app instance in tests.
    pub fn singleton() -> Self {
        App::new("test_app", "0.0.1", |_app, _msg| Vec::new())
    }

    /// Returns a reference to the cached home info page, computing it if needed.
    fn home_info_page(&mut self) -> &Vec<u8> {
        if self.home_info_page.is_none() {
            let mut fields: Vec<TagValue> = Vec::new();
            fields.push(TagValue {
                tag: "V-App name".into(),
                value: self.app_name.to_string(),
            });
            fields.push(TagValue {
                tag: "Version".into(),
                value: self.version.to_string(),
            });
            if let Some(dev) = &self.developer {
                fields.push(TagValue {
                    tag: "Developer".into(),
                    value: dev.clone(),
                });
            }
            let raw = crate::ux_generated::make_page_home_info(&fields);
            self.home_info_page = Some(raw);
        }
        self.home_info_page.as_ref().unwrap() // safe, just populated
    }

    // --- UX Flows ---
    pub fn review_pairs(
        &mut self,
        intro_text: &str,
        intro_subtext: &str,
        pairs: &[TagValue],
        final_text: &str,
        final_button_text: &str,
        long_press: bool,
    ) -> bool {
        self.ux_dirty = true;
        crate::ux::review_pairs(
            intro_text,
            intro_subtext,
            pairs,
            final_text,
            final_button_text,
            long_press,
        )
    }

    pub fn show_spinner(&mut self, text: &str) {
        self.ux_dirty = true;
        crate::ux::show_spinner(text);
    }

    pub fn show_info(&mut self, icon: crate::ux::Icon, text: &str) {
        self.ux_dirty = true;
        crate::ux::show_info(icon, text);
    }

    pub fn show_confirm_reject(
        &mut self,
        title: &str,
        text: &str,
        confirm: &str,
        reject: &str,
    ) -> bool {
        self.ux_dirty = true;
        crate::ux::show_confirm_reject(title, text, confirm, reject)
    }
}
