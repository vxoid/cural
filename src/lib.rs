#[cfg(target_os = "windows")]
mod process;
#[cfg(target_os = "windows")]
mod module;

#[cfg(target_os = "windows")]
pub use process::Process;
#[cfg(target_os = "windows")]
pub use module::Module;