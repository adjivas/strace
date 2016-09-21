#[macro_export]
macro_rules! unsafe_try {
    ( $x:expr ) => {{
        match $x {
            -1 => None,
            ret => Some(ret),
        }
    }};
}
