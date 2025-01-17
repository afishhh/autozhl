pub trait SliceExt<'a> {
    fn consume_chunk<const N: usize>(&mut self) -> &'a [u8; N];
    fn consume_n(&mut self, n: usize) -> &'a [u8];
    fn consume_first(&mut self) -> u8 {
        self.consume_chunk::<1>()[0]
    }

    fn consume_u16_le(&mut self) -> u16 {
        u16::from_le_bytes(*self.consume_chunk::<2>())
    }

    fn consume_u32_le(&mut self) -> u32 {
        u32::from_le_bytes(*self.consume_chunk::<4>())
    }

    fn consume_u64_le(&mut self) -> u64 {
        u64::from_le_bytes(*self.consume_chunk::<8>())
    }

    fn consume_u32_or_u64_address_le(&mut self, is64: bool) -> usize {
        match is64 {
            true => self.consume_u64_le() as usize,
            false => self.consume_u32_le() as usize,
        }
    }

    unsafe fn consume_struct<T>(&mut self) -> &'a T {
        let bytes = self.consume_n(std::mem::size_of::<T>());
        assert_eq!(bytes.as_ptr().addr() & (std::mem::align_of::<T>() - 1), 0);
        unsafe { &*(bytes.as_ptr() as *const T) }
    }

    unsafe fn consume_n_structs<T>(&mut self, count: usize) -> &'a [T] {
        let bytes = self.consume_n(count * std::mem::size_of::<T>());
        assert_eq!(bytes.as_ptr().addr() & (std::mem::align_of::<T>() - 1), 0);
        assert_eq!(
            std::mem::size_of::<T>() & (std::mem::align_of::<T>() - 1),
            0
        );
        unsafe { std::slice::from_raw_parts(bytes.as_ptr() as *const T, count) }
    }
}

impl<'a> SliceExt<'a> for &'a [u8] {
    fn consume_chunk<const N: usize>(&mut self) -> &'a [u8; N] {
        let Some((d, rest)) = self.split_first_chunk::<N>() else {
            panic!("not enough bytes for chunk of {N} bytes")
        };
        *self = rest;
        d
    }

    fn consume_n(&mut self, n: usize) -> &'a [u8] {
        let (l, rest) = self.split_at(n);
        *self = rest;
        l
    }
}
