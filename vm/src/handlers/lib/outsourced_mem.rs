use core::cell::RefCell;

use alloc::rc::Rc;
use common::vm::{Page, PagedMemory};
use ledger_device_sdk::io;

use common::constants::PAGE_SIZE;
use common::client_commands::ClientCommandCode;

use crate::{AppSW, Instruction};


// TODO: temporary implementation that stores a single page, and without page integrity checks
pub struct OutsourcedMemory<'c> {
    comm: Rc<RefCell<&'c mut io::Comm>>,
    idx: Option<u32>,
    page: Page,
    is_readonly: bool
}

impl<'c> OutsourcedMemory<'c> {
    pub fn new(comm: Rc<RefCell<&'c mut io::Comm>>, is_readonly: bool) -> Self {
        Self {
            comm,
            idx: None,
            page: Page { data: [0; PAGE_SIZE] },
            is_readonly
        }
    }

    fn commit_page(&mut self) -> Result<(), &'static str> {
        let Some(idx) = self.idx else {
            panic!("No page to commit");
        };

        let mut comm = self.comm.borrow_mut();

        // First message: communicate the page to commit
        // TODO: should add a byte to identify in which segment does the page belong
        comm.append(&[ClientCommandCode::CommitPage as u8]);
        comm.append(&idx.to_be_bytes());
        comm.reply(AppSW::InterruptedExecution);

        let Instruction::Continue(p1, p2) = comm.next_command() else {
            return Err("INS not supported"); // expected "Continue"
        };

        if (p1, p2) != (0, 0) {
            return Err("Wrong P1/P2");
        }

        // Second message  message: communicate the page content
        comm.append(&[ClientCommandCode::CommitPageContent as u8]);
        comm.append(&self.page.data);

        let Instruction::Continue(p1, p2) = comm.next_command() else {
            return Err("INS not supported"); // expected "Continue"
        };

        if (p1, p2) != (0, 0) {
            return Err("Wrong P1/P2");
        }

        Ok(())
    }
}

impl<'c> PagedMemory for OutsourcedMemory<'c> {
    type PageRef<'a> = &'a mut Page where Self: 'a;

    fn get_page<'a>(&'a mut self, page_index: u32) -> Result<Self::PageRef<'a>, &'static str> {
        if let Some(idx) = &mut self.idx {
            if *idx == page_index {
                return Ok(&mut self.page);
            } else {
                if !self.is_readonly {
                    self.commit_page()?;
                }
            }
        }

        let mut comm = self.comm.borrow_mut();
        comm.append(&[ClientCommandCode::GetPage as u8]);
        comm.append(&page_index.to_be_bytes());
        comm.reply(AppSW::InterruptedExecution);

        let Instruction::Continue(p1, p2) = comm.next_command() else {
            return Err("INS not supported"); // expected "Continue"
        };

        if p2 != 0 {
            return Err("Wrong P2");
        }

        let fetched_data = comm.get_data().map_err(|_| "Wrong APDU length")?;
        if fetched_data.len() != PAGE_SIZE - 1 {
            return Err("Wrong APDU length");
        }
        // overwrite page content
        self.page.data[0..PAGE_SIZE - 1].copy_from_slice(fetched_data);
        self.page.data[PAGE_SIZE - 1] = p1;

        // update index
        self.idx = Some(page_index);

        Ok(&mut self.page)
    }
}
