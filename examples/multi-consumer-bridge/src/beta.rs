#[cxx::bridge]
mod ffi {
    extern "Rust" {
        fn beta_value() -> i32;
    }
}

fn beta_value() -> i32 {
    2
}
