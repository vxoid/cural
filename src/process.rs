use std::fmt::Debug;
use std::io;
use std::mem;
use std::ptr;

use winapi::shared::ntdef::HANDLE;
use winapi::um::handleapi::CloseHandle;
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use winapi::um::memoryapi::ReadProcessMemory;
use winapi::um::memoryapi::WriteProcessMemory;
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::tlhelp32::CreateToolhelp32Snapshot;
use winapi::um::tlhelp32::MODULEENTRY32;
use winapi::um::tlhelp32::Module32First;
use winapi::um::tlhelp32::Module32Next;
use winapi::um::tlhelp32::PROCESSENTRY32;
use winapi::um::tlhelp32::Process32Next;
use winapi::um::tlhelp32::TH32CS_SNAPMODULE;
use winapi::um::tlhelp32::TH32CS_SNAPMODULE32;
use winapi::um::tlhelp32::TH32CS_SNAPPROCESS;
use winapi::um::winnt::PROCESS_ALL_ACCESS;
use winapi::um::wow64apiset::IsWow64Process;

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

    let mut entry = unsafe { mem::zeroed::<PROCESSENTRY32>() };
    entry.dwSize = mem::size_of::<PROCESSENTRY32>() as u32;

    let snapshot = unsafe {
      CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    };

    if snapshot == INVALID_HANDLE_VALUE {
      return Err(io::Error::new(
        io::ErrorKind::Interrupted,
        "Couldn't create snapshot tool"
      ));
    }

    while unsafe { Process32Next(snapshot, &mut entry) } != 0 {
      let id = entry.th32ProcessID;
      let handle = unsafe {
        OpenProcess(PROCESS_ALL_ACCESS, 0, id)
      };

      if handle == INVALID_HANDLE_VALUE {
        continue;
      }

      let c_name = entry.szExeFile.into_iter()
        .take_while(|byte| byte != &0)
        .map(|byte| byte as u8 as char)
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
    let all = Process::all()?;

    for process in all {
      if &process.name == name {
        return Ok(process);
      }
    }

    Err(io::Error::new(
      io::ErrorKind::NotFound,
      format!("no process found with name {}", name)
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
        address as *const _,
        &mut buffer as *mut T as *mut _,
        mem::size_of::<T>(),
        ptr::null_mut()
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
        address as *mut _,
        &value as *const T as *const _,
        mem::size_of::<T>(),
        ptr::null_mut()
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
    let all = self.get_all_modules()?;

    for module in all {
      return Ok(module);
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

    let mut entry = unsafe { mem::zeroed::<MODULEENTRY32>() };
    entry.dwSize = mem::size_of::<MODULEENTRY32>() as u32;

    let snapshot = unsafe {
      CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, self.id)
    };

    if snapshot == INVALID_HANDLE_VALUE {
      return Err(io::Error::new(
        io::ErrorKind::Interrupted,
        "Couldn't create snapshot tool"
      ));
    }

    if unsafe { Module32First(snapshot, &mut entry) } == 0 {
      return Ok(modules);
    }

    loop {
      let c_module = entry.szModule.into_iter()
        .take_while(|byte| byte != &0)
        .map(|byte| byte as u8 as char)
        .collect::<String>();

      modules.push(Module { name: c_module, address: entry.modBaseAddr as usize });

      if unsafe { Module32Next(snapshot, &mut entry) } == 0 {
        break;
      }
    }

    unsafe { CloseHandle(snapshot) };

    Ok(modules)
  }

  /// Returns is process x64 or no
  pub fn is_x64(&self) -> io::Result<bool> {
    let mut is_x64 = 0;
    
    if unsafe { IsWow64Process(self.handle, &mut is_x64) } != 1 {
      return Err(io::Error::last_os_error());
    }

    return Ok(is_x64 != 1);
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