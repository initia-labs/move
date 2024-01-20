use std::collections::HashMap;

use bytes::Bytes;
use move_binary_format::errors::PartialVMResult;
use move_core_types::language_storage::ModuleId;
use move_vm_types::loaded_data::runtime_types::Checksum;

use crate::data_cache::TransactionDataCache;

pub trait ModuleStorage {
    fn load_module(&self, module_id: &ModuleId) -> PartialVMResult<Bytes>;
    fn load_checksum(&self, module_id: &ModuleId) -> PartialVMResult<[u8; 32]>;
}

pub(crate) struct ModuleStorageForVerify<'r> {
    data_cache: &'r TransactionDataCache<'r>,
    checksums: HashMap<ModuleId, Checksum>,
}

impl<'r> ModuleStorageForVerify<'r> {
    pub(crate) fn new(
        data_cache: &'r TransactionDataCache,
        checksums: HashMap<ModuleId, Checksum>,
    ) -> Self {
        Self {
            data_cache,
            checksums,
        }
    }
}

impl<'r> ModuleStorage for ModuleStorageForVerify<'r> {
    fn load_module(&self, module_id: &ModuleId) -> PartialVMResult<Bytes> {
        self.data_cache.load_module(module_id)
    }

    fn load_checksum(&self, module_id: &ModuleId) -> PartialVMResult<[u8; 32]> {
        if let Some(checksum) = self.checksums.get(module_id) {
            return Ok(*checksum);
        }

        self.data_cache.load_checksum(module_id)
    }
}
