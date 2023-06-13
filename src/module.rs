use std::fmt::Debug;

pub struct Module {
  pub(crate) name: String,
  pub(crate) address: usize
}

impl Module {
    /// Returns address
    pub fn get_address(&self) -> &usize {
      &self.address
    }

    /// Returns name
    pub fn get_name(&self) -> &str {
      &self.name
    }
}

impl ToString for Module {
  fn to_string(&self) -> String {
    self.name.clone()
  }
}

impl Debug for Module {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_string())
    }
}