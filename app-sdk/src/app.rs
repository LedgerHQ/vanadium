use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use common::ux::TagValue;

/// A Handler is a function that is called when a message is received from the host, and
/// returns the app's response.
pub type Handler = fn(&mut App, &[u8]) -> Vec<u8>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum View {
    None,
    Home,
    HomeInfo,
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

    fn show_home(&mut self) {
        let description = self
            .description
            .as_deref()
            .unwrap_or("Application is ready");

        crate::ux::ux_home(description);
        self.current_view = View::Home;
    }

    fn show_home_info(&mut self) {
        let page_raw = self.home_info_page();
        crate::ux::show_page_raw(page_raw);
        self.current_view = View::HomeInfo;
    }

    /// This function shows the dashboard, then enters the core loop of the app.
    /// It never returns, as it keeps the app running until sdk::exit() is called,
    /// or a fatal error occurs.
    pub fn run(&mut self) -> ! {
        use common::ux::Action::*;
        use common::ux::Event::Action;
        self.show_home();
        loop {
            let ev = crate::ux::get_event();
            match (self.current_view, ev) {
                (View::Home, Action(Quit)) => crate::ecalls::exit(0),
                (View::Home, Action(TopRight)) => self.show_home_info(),
                (View::HomeInfo, Action(Quit)) => self.show_home(),
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

            // TODO: this is not ideal, as:
            // - we should only do this if something was indeed shown during the execution of the command
            // - we shouldn't do it immediately if a confirmation window or notice is being shown after a command
            //   (as we would only go to the dashboard after a timeout).
            // This is temporary until a more proper (stateful) framework is implemented.
            self.show_home();
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
}
