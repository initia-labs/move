// Copyright (c) The Diem Core Contributors
// Copyright (c) The Move Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::loader::{ChecksumStorage, ModuleStorage};

use bytes::Bytes;
use move_binary_format::errors::*;
use move_core_types::{language_storage::ModuleId, resolver::MoveResolver, vm_status::StatusCode};
use move_vm_types::loaded_data::runtime_types::Checksum;
use parking_lot::RwLock;
use std::collections::btree_map::BTreeMap;

/// Transaction checksum cache. Keep updates within a transaction so
/// they can all be fetched at loader execution.
pub struct SessionCache<'r> {
    remote: &'r dyn MoveResolver<PartialVMError>,

    // we don't need lock because it is created per session,
    // but use lock to avoid make load_checksum as mutable.
    checksums: RwLock<BTreeMap<ModuleId, Checksum>>,

    // we don't need lock because it is created per session,
    // but use lock to avoid make load_checksum as mutable.
    modules: RwLock<BTreeMap<ModuleId, Bytes>>,
}

impl<'r> ChecksumStorage for SessionCache<'r> {
    fn load_checksum(&self, module_id: &ModuleId) -> PartialVMResult<Checksum> {
        if let Some(checksum) = self.checksums.read().get(module_id) {
            return Ok(*checksum);
        }

        match self.remote.get_checksum(module_id)? {
            Some(checksum) => {
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

impl<'r> ModuleStorage for SessionCache<'r> {
    fn load_module(&self, module_id: &ModuleId) -> PartialVMResult<Bytes> {
        self.load_module(module_id)
    }
}

impl<'r> SessionCache<'r> {
    /// Create a `SessionCache` with a `RemoteCache` that provides access to data
    /// not updated in the transaction.
    pub fn new(remote: &'r impl MoveResolver<PartialVMError>) -> Self {
        SessionCache {
            remote,
            checksums: RwLock::new(BTreeMap::new()),
            modules: RwLock::new(BTreeMap::new()),
        }
    }

    pub(crate) fn record_publish(
        &mut self,
        module_id: &ModuleId,
        module_bytes: Bytes,
        checksum: Checksum,
    ) {
        self.modules.write().insert(module_id.clone(), module_bytes);
        self.checksums.write().insert(module_id.clone(), checksum);
    }

    pub(crate) fn exists_module(&self, module_id: &ModuleId) -> VMResult<bool> {
        if self.modules.read().get(module_id).is_some() {
            return Ok(true);
        }

        if let Some(blob) = self
            .remote
            .get_module(module_id)
            .map_err(|e| e.finish(Location::Undefined))?
        {
            self.modules.write().insert(module_id.clone(), blob);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub(crate) fn load_module(&self, module_id: &ModuleId) -> PartialVMResult<Bytes> {
        if let Some(blob) = self.modules.read().get(module_id) {
            return Ok(blob.clone());
        }

        match self.remote.get_module(module_id)? {
            Some(blob) => {
                self.modules.write().insert(module_id.clone(), blob.clone());
                Ok(blob)
            }
            None => Err(
                PartialVMError::new(StatusCode::LINKER_ERROR).with_message(format!(
                    "Linker Error: Cannot find {:?} in data cache",
                    module_id
                )),
            ),
        }
    }

    pub fn load_module_from_cache(&self, module_id: &ModuleId) -> Option<Bytes> {
        self.modules.read().get(module_id).cloned()
    }

    pub fn load_checksum_from_cache(&self, module_id: &ModuleId) -> Option<Checksum> {
        self.checksums.read().get(module_id).cloned()
    }
}
