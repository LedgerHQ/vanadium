use alloc::{
    string::{String, ToString},
    vec::Vec,
};

/// A Handler is a function that is called when a message is received from the host, and
/// returns the app's response.
pub type Handler = fn(&mut App, &[u8]) -> Vec<u8>;

/// The App struct represents the context of the application.
pub struct App {
    handler: Handler,
    description: Option<String>,
}

impl App {
    /// Creates a new App instance with the given handler.
    pub fn new(handler: Handler) -> Self {
        Self {
            handler,
            description: None,
        }
    }

    pub fn description(mut self, description: &str) -> Self {
        self.description = Some(description.to_string());
        self
    }

    /// This function shows the dashboard, then enters the core loop of the app.
    /// It never returns, as it keeps the app running until sdk::exit() is called,
    /// or a fatal error occurs.
    pub fn run(&mut self) -> ! {
        let description = self
            .description
            .as_deref()
            .unwrap_or("Application is ready")
            .to_string();

        crate::ux::ux_home(&description);
        loop {
            // TODO: can we handle the error any better?
            //       Aborting in Vanadium might be necessary anyway, if communication breaks.
            let req_msg = crate::comm::receive_message().expect("Communication error");
            let resp_msg = (self.handler)(self, &req_msg);
            crate::comm::send_message(&resp_msg);

            // TODO: this is not ideal, as:
            // - we should only do this if something was indeed shown during the execution of the command
            // - we shouldn't do it immediately if a confirmation window or notice is being shown after a command
            //   (as we would only go to the dashboard after a timeout).
            // This is temporary until a more proper (stateful) framework is implemented.
            crate::ux::ux_home(&description);
        }
    }

    /// This is only useful to produce a valid app instance in tests.
    pub fn singleton() -> Self {
        App::new(|_app, _msg| Vec::new())
    }
}
