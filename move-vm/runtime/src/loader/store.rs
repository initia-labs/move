use std::collections::HashMap;

use bytes::Bytes;
use move_binary_format::errors::PartialVMResult;
use move_core_types::language_storage::ModuleId;
use move_vm_types::loaded_data::runtime_types::Checksum;

use crate::session_cache::SessionCache;

pub trait ModuleStorage {
    fn load_module(&self, module_id: &ModuleId) -> PartialVMResult<Bytes>;
}

pub trait ChecksumStorage {
    fn load_checksum(&self, module_id: &ModuleId) -> PartialVMResult<Checksum>;
}

pub(crate) struct ChecksumStorageForVerify<'r> {
    checksum_cache: &'r SessionCache<'r>,
    checksums: &'r HashMap<ModuleId, Checksum>,
}

impl<'r> ChecksumStorageForVerify<'r> {
    pub(crate) fn new(
        checksum_cache: &'r SessionCache,
        checksums: &'r HashMap<ModuleId, Checksum>,
    ) -> Self {
        Self {
            checksum_cache,
            checksums,
        }
    }
}
impl<'r> ChecksumStorage for ChecksumStorageForVerify<'r> {
    fn load_checksum(&self, module_id: &ModuleId) -> PartialVMResult<Checksum> {
        if let Some(checksum) = self.checksums.get(module_id) {
            return Ok(*checksum);
        }

        self.checksum_cache.load_checksum(module_id)
    }
}
