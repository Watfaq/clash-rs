use std::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, Ordering},
};

pub(crate) struct SpinLock {
    locked: AtomicBool,
}

impl SpinLock {
    pub const fn new() -> Self {
        SpinLock {
            locked: AtomicBool::new(false),
        }
    }

    pub fn lock(&self) {
        while self.locked.swap(true, Ordering::Acquire) {
            std::hint::spin_loop();
        }
    }

    pub fn unlock(&self) {
        self.locked.store(false, Ordering::Release);
    }
}

unsafe impl<T: Send> Send for Protected<T> {}
unsafe impl<T: Send> Sync for Protected<T> {}

pub(crate) struct Protected<T> {
    data: UnsafeCell<T>,
    lock: SpinLock,
}
impl<T> Protected<T> {
    pub fn new(data: T) -> Self {
        Protected {
            data: UnsafeCell::new(data),
            lock: SpinLock::new(),
        }
    }

    pub fn with_lock<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut T) -> R,
    {
        self.lock.lock();
        let result = f(unsafe { &mut *self.data.get() });
        // SAFETY: We ensure that the lock is held while accessing `data`.
        self.lock.unlock();
        result
    }
}
