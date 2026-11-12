//! The approval screens that the handlers share.
//!
//! With [`AUTO_APPROVE`] (in unit tests, and with the `autoapprove` feature), nothing is shown and
//! every review is approved.

use alloc::{format, string::String};

use sdk::ux::{Icon, TagValue};

/// Whether every review is approved without being shown.
pub const AUTO_APPROVE: bool = cfg!(any(test, feature = "autoapprove"));

/// The text and subtext of the intro of a review, for the title `title` and the subtitle
/// `subtitle`: with the page API, both on one screen, on two lines; otherwise, as the title and
/// the subtitle.
pub fn intro(title: &str, subtitle: &str) -> (String, String) {
    if sdk::ux::has_page_api() {
        (format!("{}\n{}", title, subtitle), String::new())
    } else {
        (title.into(), subtitle.into())
    }
}

/// A review of `pairs` that the user approves or rejects.
pub struct Review<'a> {
    /// The text and subtext of the intro, usually from [`intro`].
    pub intro: (String, String),
    pub pairs: &'a [TagValue],
    /// The text of the last screen, and of its button.
    pub final_text: &'a str,
    pub button_text: &'a str,
    /// Whether the button must be held, rather than pressed.
    pub long_press: bool,
    /// What to show once the user approved the review, if anything.
    pub approved: Option<&'a str>,
    /// What to show once the user rejected the review.
    pub rejected: &'a str,
}

/// Shows `review`, then its outcome. Returns whether the user approved it.
pub async fn review(app: &mut sdk::App, review: Review<'_>) -> bool {
    if AUTO_APPROVE {
        return true;
    }
    let approved = app
        .review_pairs(
            &review.intro.0,
            &review.intro.1,
            review.pairs,
            review.final_text,
            review.button_text,
            review.long_press,
        )
        .await;
    match (approved, review.approved) {
        (true, Some(text)) => app.show_info(Icon::Success, text),
        (true, None) => {}
        (false, _) => app.show_info(Icon::Failure, review.rejected),
    }
    approved
}

/// Asks the user to confirm `text`, under `title`. Returns whether they did.
pub async fn confirm(app: &mut sdk::App, title: &str, text: &str) -> bool {
    if AUTO_APPROVE {
        return true;
    }
    app.show_confirm_reject(title, text, "Continue", "Reject")
        .await
}

/// Shows `text` with `icon`.
pub fn info(app: &mut sdk::App, icon: Icon, text: &str) {
    if !AUTO_APPROVE {
        app.show_info(icon, text);
    }
}
