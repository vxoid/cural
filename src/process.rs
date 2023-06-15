use std::fmt::Debug;
use std::io;
use std::mem;
use std::ffi;

use windows::Win32::Foundation::BOOL;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::CreateToolhelp32Snapshot;
use windows::Win32::System::Diagnostics::ToolHelp::MODULEENTRY32;
use windows::Win32::System::Diagnostics::ToolHelp::Module32First;
use windows::Win32::System::Diagnostics::ToolHelp::Module32Next;
use windows::Win32::System::Diagnostics::ToolHelp::PROCESSENTRY32;
use windows::Win32::System::Diagnostics::ToolHelp::Process32Next;
use windows::Win32::System::Diagnostics::ToolHelp::TH32CS_SNAPMODULE;
use windows::Win32::System::Diagnostics::ToolHelp::TH32CS_SNAPMODULE32;
use windows::Win32::System::Diagnostics::ToolHelp::TH32CS_SNAPPROCESS;
use windows::Win32::System::Threading::OpenProcess;
use windows::Win32::System::Threading::PROCESS_ALL_ACCESS;

use crate::Module;

/// Struct which represents windows process
/// 
/// # Examples
/// ```
/// use cural::Process;
/// let process = Process::find("process.exe").expect("no such process");
/// println!("found {}", process);
/// ```
#[derive(Clone)]
pub struct Process {
  id: u32,
  name: String,
  handle: HANDLE
}

impl Process {
  /// Gets all processes
  /// 
  /// # Examples
  /// ```
  /// use cural::Process;
  /// let processes = Process::all().expect("Couldn't get any process");
  /// println!("found {:?}", processes);
  /// ```
  pub fn all() -> io::Result<Vec<Self>> {
    let mut result = Vec::new();

    let mut entry = PROCESSENTRY32::default();
    entry.dwSize = mem::size_of::<PROCESSENTRY32>() as u32;

    let snapshot = unsafe {
      CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    }.map_err(|err| io::Error::new(
      io::ErrorKind::Interrupted,
      err
    ))?;

    if snapshot == INVALID_HANDLE_VALUE {
      return Err(io::Error::new(
        io::ErrorKind::Interrupted,
        "Couldn't create snapshot tool"
      ));
    }

    while unsafe { Process32Next(snapshot, &mut entry) } != BOOL(0) {
      let id = entry.th32ProcessID;
      let handle = match unsafe {
        OpenProcess(PROCESS_ALL_ACCESS, false, id)
      } {
        Ok(handle) => handle,
        Err(_) => continue,
      };
      
      if handle.is_invalid() {
        continue;
      }

      let c_name = entry.szExeFile.into_iter()
        .take_while(|byte| byte != &0)
        .map(|byte| byte as char)
        .collect::<String>();

      result.push(Self { id, name: c_name, handle })
    }
    unsafe { CloseHandle(snapshot) };

    Ok(result)
  }

  /// Finds process by name
  /// 
  /// # Examples
  /// ```
  /// use cural::Process;
  /// let process = Process::find("process.exe").expect("no such process");
  /// println!("found {}", process);
  /// ```
  pub fn find(name: &str) -> io::Result<Self> {
    let mut entry = PROCESSENTRY32::default();
    entry.dwSize = mem::size_of::<PROCESSENTRY32>() as u32;

    let snapshot = unsafe {
      CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    }.map_err(|err| io::Error::new(
      io::ErrorKind::Interrupted,
      err
    ))?;

    if snapshot == INVALID_HANDLE_VALUE {
      return Err(io::Error::new(
        io::ErrorKind::Interrupted,
        "Couldn't create snapshot tool"
      ));
    }

    while unsafe { Process32Next(snapshot, &mut entry) } != BOOL(0) {
      let c_name = entry.szExeFile.into_iter()
        .take_while(|byte| byte != &0)
        .map(|byte| byte as char)
        .collect::<String>();

      if name != c_name {
        continue;
      }

      let id = entry.th32ProcessID;
      let handle = unsafe {
        OpenProcess(PROCESS_ALL_ACCESS, false, id)
      }.map_err(|err| io::Error::new(
        io::ErrorKind::Interrupted,
        err
      ))?;
      unsafe { CloseHandle(snapshot) };

      if handle.is_invalid() {
        return Err(io::Error::new(
          io::ErrorKind::InvalidData,
          "got invalid handle while opening process"
        ));
      }

      return Ok(Self { id, name: c_name, handle });
    }

    Err(io::Error::new(
      io::ErrorKind::NotFound,
      format!("no process with name {} found", name)
    ))
  }

  /// Reads from process by address
  /// 
  /// # Examples
  /// ```
  /// use cural::Process;
  /// let process = Process::find("process.exe").expect("no such process");
  /// let some_data = process.read::<i32>(0x0);
  /// ```
  pub fn read<T>(&self, address: usize) -> T {
    let mut buffer = unsafe {
        mem::zeroed::<T>()
    };

    unsafe {
      ReadProcessMemory(
        self.handle,
        address as *const ffi::c_void,
        &mut buffer as *mut T as *mut ffi::c_void,
        mem::size_of::<T>(),
        None
      );
    }

    buffer
  }

  /// Writes to process by address
  /// 
  /// # Examples
  /// ```
  /// use cural::Process;
  /// let process = Process::find("process.exe").expect("no such process");
  /// process.write(123, 0x0);
  /// ```
  pub fn write<T>(&self, value: T, address: usize) {
    unsafe {
      WriteProcessMemory(
        self.handle,
        address as *const ffi::c_void,
        &value as *const T as *const ffi::c_void,
        mem::size_of::<T>(),
        None
      )
    };
  }

  /// Gets module address
  /// 
  /// # Examples
  /// ```
  /// use cural::Process;
  /// let process = Process::find("process.exe").expect("no such process");
  /// let kernel = process.get_module("KERNEL32.DLL").expect("no such dll");
  /// ```
  pub fn get_module(&self, module: &str) -> io::Result<Module> {
    let mut entry = MODULEENTRY32::default();
    entry.dwSize = mem::size_of::<MODULEENTRY32>() as u32;

    let snapshot = unsafe {
      CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, self.id)
    }.map_err(|err| io::Error::new(
      io::ErrorKind::Interrupted,
      err
    ))?;

    if snapshot == INVALID_HANDLE_VALUE {
      return Err(io::Error::new(
        io::ErrorKind::Interrupted,
        "Couldn't create snapshot tool"
      ));
    }

    while unsafe { Module32Next(snapshot, &mut entry) } != BOOL(0) {
      let c_module = entry.szModule.into_iter()
        .take_while(|byte| byte != &0)
        .map(|byte| byte as char)
        .collect::<String>();

      if c_module != module {
        continue;
      }

      unsafe { CloseHandle(snapshot) };

      return Ok(Module { name: c_module, address: entry.modBaseAddr as usize });
    }

    Err(io::Error::new(
      io::ErrorKind::NotFound,
      format!("no module with name {}", module)
    ))
  }

  /// Returns all modules
  /// 
  /// # Examples
  /// ```
  /// use cural::Process;
  /// let process = Process::find("process.exe").expect("no such process");
  /// let modules = process.get_all_modules().expect("error getting modules");
  /// ```
  pub fn get_all_modules(&self) -> io::Result<Vec<Module>> {
    let mut modules = Vec::new();
    let mut entry = MODULEENTRY32::default();
    entry.dwSize = mem::size_of::<MODULEENTRY32>() as u32;

    let snapshot = unsafe {
      CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, self.id)
    }.map_err(|err| io::Error::new(
      io::ErrorKind::Interrupted,
      err
    ))?;

    if snapshot == INVALID_HANDLE_VALUE {
      return Err(io::Error::new(
        io::ErrorKind::Interrupted,
        "Couldn't create snapshot tool"
      ));
    }

    if unsafe { Module32First(snapshot, &mut entry) } == BOOL(0) {
      return Ok(modules);
    }

    loop {
      let c_module = entry.szModule.into_iter()
        .take_while(|byte| byte != &0)
        .map(|byte| byte as char)
        .collect::<String>();

      modules.push(Module { name: c_module, address: entry.modBaseAddr as usize });

      if unsafe { Module32Next(snapshot, &mut entry) } == BOOL(0) {
        break;
      }
    }

    unsafe { CloseHandle(snapshot) };

    Ok(modules)
  }

  /// Returns windows process handle
  pub fn get_handle(&self) -> HANDLE {
    self.handle
  }

  /// Returns name field of process
  pub fn get_name(&self) -> &str {
    &self.name
  }

  /// Returns id field of process
  pub fn get_id(&self) -> &u32 {
    &self.id
  }
}

impl ToString for Process {
    fn to_string(&self) -> String {
      format!("{}({})", self.name, self.id)
    }
}

impl Debug for Process {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_string())
    }
}