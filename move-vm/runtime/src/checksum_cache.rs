// Copyright (c) The Diem Core Contributors
// Copyright (c) The Move Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::loader::ChecksumStorage;
use move_binary_format::errors::*;
use move_core_types::{language_storage::ModuleId, resolver::MoveResolver, vm_status::StatusCode};
use move_vm_types::loaded_data::runtime_types::Checksum;
use parking_lot::RwLock;
use std::collections::btree_map::BTreeMap;

/// Transaction checksum cache. Keep updates within a transaction so 
/// they can all be fetched at loader execution.
pub struct TransactionChecksumCache<'r> {
    remote: &'r dyn MoveResolver<PartialVMError>,

    // we don't need lock because it is created per session,
    // but use lock to avoid make load_checksum as mutable.
    checksums: RwLock<BTreeMap<ModuleId, Checksum>>,
}

impl<'r> ChecksumStorage for TransactionChecksumCache<'r> {
    fn load_checksum(&self, module_id: &ModuleId) -> PartialVMResult<[u8; 32]> {
        if let Some(checksum) = self.checksums.read().get(module_id) {
            return Ok(*checksum);
        }

        match self.remote.get_checksum(module_id)? {
            Some(checksum) => {
                // update checksum
                self.checksums.write().insert(module_id.clone(), checksum);

                Ok(checksum)
            }
            None => Err(
                PartialVMError::new(StatusCode::LINKER_ERROR).with_message(format!(
                    "Linker Error: Cannot find {:?} in data cache",
                    module_id
                )),
            ),
        }
    }
}

impl<'r> TransactionChecksumCache<'r> {
    /// Create a `TransactionChecksumCache` with a `RemoteCache` that provides access to data
    /// not updated in the transaction.
    pub fn new(remote: &'r impl MoveResolver<PartialVMError>) -> Self {
        TransactionChecksumCache {
            remote,
            checksums: RwLock::new(BTreeMap::new()),
        }
    }

    pub(crate) fn update_checksum(&mut self, module_id: &ModuleId, checksum: [u8; 32]) {
        self.checksums.write().insert(module_id.clone(), checksum);
    }
}
