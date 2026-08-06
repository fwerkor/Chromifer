#[unsafe(no_mangle)]
pub extern "C" fn chromifer_add(left: i32, right: i32) -> i32 {
    left + right
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn chromifer_buffer_is_valid(
    data: *const u8,
    length: usize,
) -> bool {
    !data.is_null() && length > 0
}
