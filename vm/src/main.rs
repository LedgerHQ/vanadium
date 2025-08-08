/*****************************************************************************
 *   Ledger App Boilerplate Rust.
 *   (c) 2023 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#![no_std]
#![no_main]

mod aes;
mod app_ui;
mod handlers;
mod hash;
mod io;

#[cfg(feature = "run_tests")]
mod app_tests;

use alloc::{string::ToString, vec, vec::Vec};
use app_ui::menu::ui_menu_main;
use handlers::{
    get_version::handler_get_version, register_vapp::handler_register_vapp,
    start_vapp::handler_start_vapp,
};
use ledger_device_sdk::io::{ApduHeader, Comm, Reply, StatusWords};

extern crate alloc;

use ledger_device_sdk::nbgl::init_comm;

// define print! and println! macros using debug_printf (only for running on Speculos)
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        let mut buf = alloc::string::String::new();
        write!(&mut buf, $($arg)*).unwrap();
        ledger_device_sdk::testing::debug_print(&buf);
    }};
}

#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ({
        $crate::print!("{}\n", format_args!($($arg)*));
    });
}

#[macro_export]
macro_rules! trace {
    ($trace_type:expr, $color:expr, $($arg:tt)*) => {{
        let color_code = if cfg!(feature = "trace_colors") {
            match $color {
                "red" => "\x1b[31m",
                "green" => "\x1b[32m",
                "yellow" => "\x1b[33m",
                "blue" => "\x1b[34m",
                "magenta" => "\x1b[35m",
                "cyan" => "\x1b[36m",
                "white" => "\x1b[37m",
                "light_gray" => "\x1b[90m",
                "light_red" => "\x1b[91m",
                "light_green" => "\x1b[92m",
                "light_yellow" => "\x1b[93m",
                "light_blue" => "\x1b[94m",
                "light_magenta" => "\x1b[95m",
                "light_cyan" => "\x1b[96m",
                "light_white" => "\x1b[97m",
                "" => "",
                _ => panic!("Unrecognized color: {}", $color),
            }
        } else {
            ""
        };
        if color_code.is_empty() {
            $crate::println!("[{}] {}", $trace_type, format_args!($($arg)*));
        } else {
            $crate::println!("{}[{}] {}\x1b[0m", color_code, $trace_type, format_args!($($arg)*));
        }
    }};
}

// Print panic message to the console. Uses the `print!` macro defined above,
// therefore it only works when running on Speculos.
fn handle_panic(info: &core::panic::PanicInfo) -> ! {
    let message = if let Some(location) = info.location() {
        alloc::format!(
            "Panic occurred in file '{}' at line {}: {:?}",
            location.file(),
            location.line(),
            info.message()
                .as_str()
                .unwrap_or(&format_args!("no message").to_string())
        )
    } else {
        alloc::format!(
            "Panic occurred: {}",
            info.message()
                .as_str()
                .unwrap_or(&format_args!("no message").to_string())
        )
    };
    println!("{}", message);

    let mut comm = ledger_device_sdk::io::Comm::new();
    comm.reply(ledger_device_sdk::io::StatusWords::Panic);

    ledger_device_sdk::exit_app(0x01)
}

ledger_device_sdk::set_panic!(handle_panic);

// Application status words.
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppSW {
    Deny = 0x6985,
    IncorrectData = 0x6A80,
    WrongP1P2 = 0x6A86,
    InsNotSupported = 0x6D00,
    ClaNotSupported = 0x6E00,
    SignatureFail = 0xB008,
    KeyDeriveFail = 0xB009,
    VersionParsingFail = 0xB00A,
    InterruptedExecution = 0xEEEE,
    WrongApduLength = StatusWords::BadLen as u16,

    VMRuntimeError = 0xB020,
    VAppPanic = 0xB021,

    Ok = 0x9000,
}

impl From<AppSW> for Reply {
    fn from(sw: AppSW) -> Reply {
        Reply(sw as u16)
    }
}

/// Possible input commands received through APDUs.
#[derive(Debug, Copy, Clone)]
pub enum Instruction {
    GetVersion,
    GetAppName,
    RegisterVApp,
    StartVApp,
    Continue(u8, u8), // client response to a request from the VM
}

impl TryFrom<ApduHeader> for Instruction {
    type Error = AppSW;

    /// APDU parsing logic.
    ///
    /// Parses INS, P1 and P2 bytes to build an [`Instruction`]. P1 and P2 are translated to
    /// strongly typed variables depending on the APDU instruction code. Invalid INS, P1 or P2
    /// values result in errors with a status word, which are automatically sent to the host by the
    /// SDK.
    ///
    /// This design allows a clear separation of the APDU parsing logic and commands handling.
    ///
    /// Note that CLA is not checked here. Instead the method [`Comm::set_expected_cla`] is used in
    /// [`sample_main`] to have this verification automatically performed by the SDK.
    fn try_from(value: ApduHeader) -> Result<Self, Self::Error> {
        match (value.ins, value.p1, value.p2) {
            (0, 0, 0) => Ok(Instruction::GetVersion),
            (1, 0, 0) => Ok(Instruction::GetAppName),
            (2, 0, 0) => Ok(Instruction::RegisterVApp),
            (3, 0, 0) => Ok(Instruction::StartVApp),
            (0..=3, _, _) => Err(AppSW::WrongP1P2),
            (0xff, p1, p2) => Ok(Instruction::Continue(p1, p2)),
            (_, _, _) => Err(AppSW::InsNotSupported),
        }
    }
}

#[cfg(not(feature = "run_tests"))]
#[no_mangle]
extern "C" fn sample_main() {
    // Create the communication manager, and configure it to accept only APDU from the 0xe0 class.
    // If any APDU with a wrong class value is received, comm will respond automatically with
    // BadCla status word.
    let mut comm = Comm::new().set_expected_cla(0xe0);
    init_comm(&mut comm);

    let mut home = ui_menu_main(&mut comm);
    home.show_and_return();

    loop {
        let ins: Instruction = comm.next_command();

        let _status = match handle_apdu(&mut comm, ins) {
            Ok(data) => {
                comm.append(&data);
                comm.reply_ok();
                AppSW::Ok
            }
            Err(sw) => {
                comm.reply(sw.clone());
                sw
            }
        };
        home.show_and_return();
    }
}

#[cfg(feature = "run_tests")]
#[no_mangle]
extern "C" fn sample_main() {
    app_tests::run_tests();
    ledger_device_sdk::exit_app(0x00);
}

fn handle_apdu(comm: &mut Comm, ins: Instruction) -> Result<Vec<u8>, AppSW> {
    match ins {
        Instruction::GetAppName => {
            comm.append(env!("CARGO_PKG_NAME").as_bytes());
            Ok(vec![])
        }
        Instruction::GetVersion => handler_get_version(comm),
        Instruction::RegisterVApp => handler_register_vapp(comm),
        Instruction::StartVApp => handler_start_vapp(comm),
        Instruction::Continue(_, _) => Err(AppSW::InsNotSupported), // 'Continue' command is only allowed when requested by the VM
    }
}
