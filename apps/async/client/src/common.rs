extern crate alloc;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum Command {
    DoWorkSync { n: u32 },
    DoWorkAsync { n: u32 },
}
