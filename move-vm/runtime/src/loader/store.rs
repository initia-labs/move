use std::{collections::HashMap, sync::Arc};

use move_binary_format::{errors::PartialVMResult, file_format::CompiledScript, CompiledModule};
use move_core_types::language_storage::ModuleId;
use move_vm_types::loaded_data::runtime_types::Checksum;

use crate::session_cache::SessionCache;

pub trait SessionStorage {
    fn deserialize_script(&self, script_blob: &[u8]) -> PartialVMResult<Arc<CompiledScript>>;
    fn load_checksum(&self, module_id: &ModuleId) -> PartialVMResult<Checksum>;
    fn load_module(&self, module_id: &ModuleId) -> PartialVMResult<(usize, Checksum, Arc<CompiledModule>)>;
}

pub(crate) struct SessionStorageForVerify<'r> {
    session_cache: &'r SessionCache<'r>,
    checksums: &'r HashMap<ModuleId, Checksum>,
}

impl<'r> SessionStorageForVerify<'r> {
    pub(crate) fn new(
        session_cache: &'r SessionCache,
        checksums: &'r HashMap<ModuleId, Checksum>,
    ) -> Self {
        Self {
            session_cache,
            checksums,
        }
    }
}

impl<'r> SessionStorage for SessionStorageForVerify<'r> {
    fn load_checksum(&self, module_id: &ModuleId) -> PartialVMResult<Checksum> {
        if let Some(checksum) = self.checksums.get(module_id) {
            return Ok(*checksum);
        }

        self.session_cache.load_checksum(module_id)
    }
    
    fn deserialize_script(&self, script_blob: &[u8]) -> PartialVMResult<Arc<CompiledScript>> {
        self.session_cache.deserialize_script(script_blob)
    }
    
    fn load_module(&self, module_id: &ModuleId) -> PartialVMResult<(usize, Checksum, Arc<CompiledModule>)> {
        self.session_cache.load_module(module_id)
    }
}
