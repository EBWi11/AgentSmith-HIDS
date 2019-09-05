### Agent
* rust-lang project
* use `cargo build --release` build
* please read `src/conf/` code

##### Target 'x86_64-unknown-linux-musl'
* `cargo install cross` && install docker 
* use `src/c_until.c.musl` replace `src/c_until.c`
* `cross build --release --target=x86_64-unknown-linux-musl`