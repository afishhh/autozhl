use std::{alloc::Layout, cell::Cell, ptr::NonNull};

const BLOCK_SIZE: usize = 1024 * 16;

pub struct BlockHeader {
    previous: Option<NonNull<BlockHeader>>,
    current: usize,
}

fn block_layout(size: usize) -> (Layout, usize) {
    Layout::new::<BlockHeader>()
        .extend(Layout::from_size_align(size, 1).unwrap())
        .unwrap()
}

#[derive(Debug)]
pub struct Arena {
    blocks: Cell<Option<NonNull<BlockHeader>>>,
}

impl Arena {
    pub fn new() -> Self {
        Self {
            blocks: Cell::new(None),
        }
    }

    fn allocate_block(&self) -> NonNull<BlockHeader> {
        unsafe {
            let layout = block_layout(BLOCK_SIZE).0;
            let block = std::alloc::alloc(layout) as *mut BlockHeader;
            let ptr = NonNull::new(block).unwrap_or_else(|| std::alloc::handle_alloc_error(layout));
            ptr.write(BlockHeader {
                previous: self.blocks.get(),
                current: 0,
            });
            self.blocks.set(Some(ptr));
            ptr
        }
    }

    pub fn alloc<T: Copy>(&self) -> *mut T {
        let mut block = self.blocks.get().unwrap_or_else(|| self.allocate_block());
        let data_offset = block_layout(BLOCK_SIZE).1;
        loop {
            unsafe {
                let data = (block.as_ptr() as *const u8).add(data_offset);
                let block_mut = block.as_mut();
                let current = data.add(block_mut.current);
                let layout = Layout::new::<T>();
                assert!(layout.size() <= BLOCK_SIZE);
                let aligned = current.add(current.align_offset(layout.align()));

                if aligned > data.add(BLOCK_SIZE - layout.size()) {
                    // don't care, didn't ask
                    #[allow(dropping_references)]
                    drop(block_mut);
                    block = self.allocate_block();
                    continue;
                }

                block_mut.current = aligned.offset_from(current) as usize + layout.size();
                return aligned as *mut T;
            }
        }
    }

    // don't care, didn't ask
    #[allow(clippy::mut_from_ref)]
    pub fn construct<T: Copy>(&self, value: T) -> &mut T {
        let ptr = self.alloc::<T>();
        unsafe {
            ptr.write(value);
        }
        unsafe { &mut *ptr }
    }
}

impl Drop for Arena {
    fn drop(&mut self) {
        let mut next = self.blocks.get();

        unsafe {
            while let Some(current) = next {
                next = current.as_ref().previous;
                std::alloc::dealloc(current.as_ptr() as *mut u8, block_layout(BLOCK_SIZE).0);
            }
        }
    }
}
