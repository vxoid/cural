# Cural v0.1.0 | Windows process memory model

## Supported OS's
- Windows

## Links
- `docs.rs` - https://docs.rs/cural
- `github` - https://github.com/CURVoid/cural.git

## Changelog
- Init

## Examples
```rust
use cural::Process;
let process = Process::find("process.exe").expect("no such process");
println!("found {}", process);
let modules = process.get_all_modules().expect("cannot get modules");
println!("modules - {:?}", modules);
```