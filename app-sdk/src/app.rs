use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use common::ux::TagValue;

use crate::{
    comm::MessageError,
    ux::{has_page_api, step_pos},
    ux_generated,
};

/// A Handler is a function that is called when a message is received from the host, and
/// returns the app's response.
pub type Handler<S = ()> = fn(&mut App<S>, &[u8]) -> Vec<u8>;

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

/// The AppBuilder is used to configure the App during the building phase.
pub struct AppBuilder<S = ()> {
    handler: Handler<S>,
    app_name: &'static str,
    version: &'static str,
    description: Option<String>,
    developer: Option<String>,
}

impl<S> AppBuilder<S>
where
    S: Default,
{
    /// Creates a new AppBuilder instance with the given handler.
    ///
    /// # Arguments
    ///
    /// * `app_name` - The name of the application.
    /// * `version` - The version of the application.
    /// * `handler` - The function to handle incoming messages.
    pub fn new(app_name: &'static str, version: &'static str, handler: Handler<S>) -> Self {
        Self {
            handler,
            app_name,
            version,
            description: None,
            developer: None,
        }
    }

    /// Sets the V-App description shown on the dashboard.
    pub fn description(mut self, description: &str) -> Self {
        self.description = Some(description.to_string());
        self
    }

    /// Sets the developer name.
    pub fn developer(mut self, developer: &str) -> Self {
        self.developer = Some(developer.to_string());
        self
    }

    /// Builds the App instance.
    pub(crate) fn build(self) -> App<S> {
        App {
            handler: self.handler,
            app_name: self.app_name,
            version: self.version,
            description: self.description,
            developer: self.developer,
            current_view: View::None,
            home_info_page: None,
            ux_dirty: true, // force showing home at startup
            cleanup_ticks: 0,
            state: S::default(),
        }
    }

    /// This function shows the dashboard, then enters the core loop of the app.
    /// It never returns, as it keeps the app running until sdk::exit() is called,
    /// or a fatal error occurs.
    pub fn run(self) -> ! {
        self.build().run_loop()
    }
}

/// The App struct represents the context of the application.
pub struct App<S = ()> {
    handler: Handler<S>,
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

    // If set to non-zero, it is decremented at each ticker event, and the dashboard is shown once
    // this reaches zero. It is reset whenever something is shown on-screen, marking the ux dirty.
    // This allows to show screens with a timeout at the end of a UX flow, without blocking and allowing
    // further UX flows to override the timeout.
    cleanup_ticks: usize,

    /// Application-specific persistent state.
    /// Apps that don't need it just use the default `S = ()`.
    pub state: S,
}

impl<S> App<S>
where
    S: Default,
{
    /// Sends a message to the host and waits for a response, processing UX events in the meantime to keep the app responsive.
    ///
    /// # Arguments
    ///
    /// * `msg` - The message to send to the host.
    ///
    /// # Returns
    ///
    /// A `Result` containing the response message from the host on success, or a `MessageError` on failure.
    ///
    /// # Behavior
    ///
    /// This method enters a loop where it continuously processes user interface events and checks for incoming messages.
    /// It will not return until a message is received or an error occurs.
    pub fn exchange(&mut self, msg: &[u8]) -> Result<Vec<u8>, MessageError> {
        crate::comm::send_message(msg);
        loop {
            self.process_ux_events();
            match crate::comm::receive_message() {
                Ok(msg) => return Ok(msg),
                Err(crate::comm::MessageError::NoMessage) => continue,
                Err(e) => return Err(e),
            }
        }
    }

    fn set_ux_dirty(&mut self) {
        self.ux_dirty = true;
        // if a timeout to show the dashboard was set, cancel it: a new screen is being shown
        self.cleanup_ticks = 0;
    }

    fn process_ux_events(&mut self) {
        use common::ux::Action::*;
        use common::ux::Event::{Action, Ticker};

        if self.ux_dirty && (self.cleanup_ticks == 0) {
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
            (_, Ticker) => {
                if self.cleanup_ticks > 0 {
                    self.cleanup_ticks -= 1;
                }
            }
            (view, ev) => {
                crate::println!("Unhandled event {:?} in view {:?}", ev, view);
            }
        }
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
    fn run_loop(&mut self) -> ! {
        loop {
            self.process_ux_events();

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
        AppBuilder::new("test_app", "0.0.1", |_app, _msg| Vec::new()).build()
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

    /// Displays a multi-screen review flow composed of label/value pairs followed by a
    /// final confirmation screen. The user can navigate forward and backward through
    /// the content before approving or aborting.
    ///
    /// Arguments:
    /// * `intro_text` - Title or primary text shown on the introductory screen.
    /// * `intro_subtext` - Secondary descriptive text shown under the intro text.
    /// * `pairs` - Slice of tag/value entries to review; order is preserved.
    /// * `final_text` - Text displayed on the final approval screen (e.g. summary).
    /// * `final_button_text` - Label of the confirmation action the user presses to approve.
    /// * `long_press` - When true, the final approval may require a long press gesture instead of a simple confirm.
    ///
    /// Returns `true` if the user confirms/approves on the final screen; `false` if the user aborts (e.g. quits or rejects).
    pub fn review_pairs(
        &mut self,
        intro_text: &str,
        intro_subtext: &str,
        pairs: &[TagValue],
        final_text: &str,
        final_button_text: &str,
        long_press: bool,
    ) -> bool {
        self.set_ux_dirty();
        crate::ux::review_pairs(
            intro_text,
            intro_subtext,
            pairs,
            final_text,
            final_button_text,
            long_press,
        )
    }

    /// Shows a progress indicator with the provided status text.
    ///
    /// Use this while performing an operation that may take noticeable time.
    /// The call returns immediately after the spinner is displayed, and it stays on the screen
    /// until something else is shown to replace it.
    ///
    /// Arguments:
    /// * `text` - Short status message describing the ongoing work.
    pub fn show_spinner(&mut self, text: &str) {
        self.set_ux_dirty();
        crate::ux::show_spinner(text);
    }

    /// Presents a confirmation flow consisting of an informational screen and
    /// explicit confirm/reject actions. The user can navigate between the
    /// confirm and reject choices before deciding.
    ///
    /// Arguments:
    /// * `title` - Heading shown on the information screen.
    /// * `text` - Descriptive text shown under the title.
    /// * `confirm` - Label for the confirm/approve action.
    /// * `reject` - Label for the reject/abort action.
    ///
    /// Returns `true` if the user selects the confirm action; `false` if the user selects reject.
    pub fn show_confirm_reject(
        &mut self,
        title: &str,
        text: &str,
        confirm: &str,
        reject: &str,
    ) -> bool {
        self.set_ux_dirty();
        crate::ux::show_confirm_reject(title, text, confirm, reject)
    }

    /// Shows a temporary informational screen with an icon and message.
    ///
    /// The screen remains visible for a few seconds before automatically returning to the
    /// dashboard, unless superseded by a new UX flow.
    ///
    /// Arguments:
    /// * `icon` - Visual indicator clarifying the nature of the message.
    /// * `text` - Informational text to display to the user.
    ///
    /// This function does not block for user input; it schedules automatic cleanup.
    pub fn show_info(&mut self, icon: crate::ux::Icon, text: &str) {
        self.set_ux_dirty();
        if has_page_api() {
            ux_generated::show_page_info(icon, text);
        } else {
            ux_generated::show_step_info_single(text);
        }
        self.cleanup_ticks = 30; // cleanup after about 3 seconds
    }
}
