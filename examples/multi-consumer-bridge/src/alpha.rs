#[cxx::bridge]
mod ffi {
    extern "Rust" {
        fn alpha_value() -> i32;
    }
}

fn alpha_value() -> i32 {
    1
}
