use std::collections::HashMap;

use bytes::Bytes;
use move_binary_format::errors::PartialVMResult;
use move_core_types::language_storage::ModuleId;
use move_vm_types::loaded_data::runtime_types::Checksum;

use crate::checksum_cache::TransactionChecksumCache;

pub trait ModuleStorage {
    fn load_module(&self, module_id: &ModuleId) -> PartialVMResult<Bytes>;
}

pub trait ChecksumStorage {
    fn load_checksum(&self, module_id: &ModuleId) -> PartialVMResult<[u8; 32]>;
}

pub(crate) struct ChecksumStorageForVerify<'r> {
    checksum_cache: &'r TransactionChecksumCache<'r>,
    checksums: &'r HashMap<ModuleId, Checksum>,
}

impl<'r> ChecksumStorageForVerify<'r> {
    pub(crate) fn new(
        checksum_cache: &'r TransactionChecksumCache,
        checksums: &'r HashMap<ModuleId, Checksum>,
    ) -> Self {
        Self {
            checksum_cache,
            checksums,
        }
    }
}
impl<'r> ChecksumStorage for ChecksumStorageForVerify<'r> {
    fn load_checksum(&self, module_id: &ModuleId) -> PartialVMResult<[u8; 32]> {
        if let Some(checksum) = self.checksums.get(module_id) {
            return Ok(*checksum);
        }

        self.checksum_cache.load_checksum(module_id)
    }
}
