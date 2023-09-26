use std::{cell::RefCell, error::Error};

thread_local! {
  pub static LAST_ERROR: RefCell<Option<String>> = RefCell::new(None);
}

pub fn update_last_error<E: Error + 'static>(e: E) {
    {
        let mut cause = e.source();
        while let Some(c) = cause {
            println!("cause: {}", c);
            cause = c.source();
        }
    }

    LAST_ERROR.with(|le| *le.borrow_mut() = Some(e.to_string()));
}
