extern crate cc;

fn main() {
    cc::Build::new()
        .file("src/c_until.c")
        .compile("c_until.a");
}