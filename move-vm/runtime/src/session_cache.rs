// Copyright (c) The Diem Core Contributors
// Copyright (c) The Move Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::loader::SessionStorage;

use bytes::Bytes;
use move_binary_format::{
    deserializer::DeserializerConfig, errors::*, file_format::CompiledScript, CompiledModule,
};
use move_core_types::{language_storage::ModuleId, resolver::MoveResolver, vm_status::StatusCode};
use move_vm_types::loaded_data::runtime_types::Checksum;
use parking_lot::RwLock;
use sha3::{Digest, Sha3_256};
use std::{collections::btree_map::BTreeMap, sync::Arc};

/// Transaction checksum cache. Keep updates within a transaction so
/// they can all be fetched at loader execution.
pub struct SessionCache<'r> {
    remote: &'r dyn MoveResolver<PartialVMError>,
    deserializer_config: DeserializerConfig,

    // we don't need lock because it is created per session,
    // but use lock to avoid make load_checksum as mutable.
    checksums: RwLock<BTreeMap<ModuleId, Checksum>>,

    // we don't need lock because it is created per session,
    // but use lock to avoid make load_checksum as mutable.
    modules: RwLock<BTreeMap<ModuleId, (usize, Checksum, Arc<CompiledModule>)>>,

    // we don't need lock because it is created per session,
    // but use lock to avoid make load_checksum as mutable.
    scripts: RwLock<BTreeMap<Checksum, Arc<CompiledScript>>>,
}

impl<'r> SessionStorage for SessionCache<'r> {
    fn load_checksum(&self, module_id: &ModuleId) -> PartialVMResult<Checksum> {
        if let Some(checksum) = self.checksums.read().get(module_id) {
            return Ok(*checksum);
        }

        match self.remote.get_checksum(module_id)? {
            Some(checksum) => {
                self.checksums.write().insert(module_id.clone(), checksum);
                Ok(checksum)
            },
            None => Err(
                PartialVMError::new(StatusCode::LINKER_ERROR).with_message(format!(
                    "Linker Error: Cannot find {:?} in data cache",
                    module_id
                )),
            ),
        }
    }

    fn load_module(
        &self,
        module_id: &ModuleId,
    ) -> PartialVMResult<(usize, Checksum, Arc<CompiledModule>)> {
        self.load_module(module_id)
    }

    fn deserialize_script(&self, script_blob: &[u8]) -> PartialVMResult<Arc<CompiledScript>> {
        let checksum: Checksum = checksum(script_blob);

        if let Some(script) = self.scripts.read().get(&checksum) {
            return Ok(script.clone());
        }

        let script =
            CompiledScript::deserialize_with_config(script_blob, &self.deserializer_config)
                .map_err(|err| {
                    let msg = format!("[VM] deserializer for script returned error: {:?}", err);
                    PartialVMError::new(StatusCode::CODE_DESERIALIZATION_ERROR).with_message(msg)
                })?;

        let arc_script = Arc::new(script);
        self.scripts.write().insert(checksum, arc_script.clone());

        Ok(arc_script)
    }
}

impl<'r> SessionCache<'r> {
    /// Create a `SessionCache` with a `RemoteCache` that provides access to data
    /// not updated in the transaction.
    pub fn new(
        remote: &'r impl MoveResolver<PartialVMError>,
        deserializer_config: DeserializerConfig,
    ) -> Self {
        SessionCache {
            remote,
            deserializer_config,
            checksums: RwLock::new(BTreeMap::new()),
            modules: RwLock::new(BTreeMap::new()),
            scripts: RwLock::new(BTreeMap::new()),
        }
    }

    pub(crate) fn record_publish(
        &mut self,
        module_id: &ModuleId,
        module_blob: Bytes,
        checksum: Checksum,
    ) -> PartialVMResult<()> {
        let module = self.deserialize_module(&module_blob)?;
        let arc_module = Arc::new(module);
        self.modules.write().insert(
            module_id.clone(),
            (module_blob.len(), checksum.clone(), arc_module),
        );
        self.checksums.write().insert(module_id.clone(), checksum);

        Ok(())
    }

    pub(crate) fn exists_module(&self, module_id: &ModuleId) -> PartialVMResult<bool> {
        if self.modules.read().get(module_id).is_some() {
            return Ok(true);
        }

        if let Some(module_blob) = self.remote.get_module(module_id)? {
            let module = self.deserialize_module(&module_blob)?;
            let arc_module = Arc::new(module);
            self.modules.write().insert(
                module_id.clone(),
                (module_blob.len(), checksum(&module_blob), arc_module),
            );

            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub(crate) fn load_module(
        &self,
        module_id: &ModuleId,
    ) -> PartialVMResult<(usize, Checksum, Arc<CompiledModule>)> {
        if let Some(arc_module) = self.modules.read().get(module_id) {
            return Ok(arc_module.clone());
        }

        match self.remote.get_module(module_id)? {
            Some(module_blob) => {
                let checksum = checksum(&module_blob);
                let module = self.deserialize_module(&module_blob)?;
                let arc_module = Arc::new(module);
                self.modules.write().insert(
                    module_id.clone(),
                    (module_blob.len(), checksum.clone(), arc_module.clone()),
                );

                Ok((module_blob.len(), checksum, arc_module))
            },
            None => Err(
                PartialVMError::new(StatusCode::LINKER_ERROR).with_message(format!(
                    "Linker Error: Cannot find {:?} in data cache",
                    module_id
                )),
            ),
        }
    }

    pub fn load_module_from_cache(&self, module_id: &ModuleId) -> Option<Arc<CompiledModule>> {
        self.modules
            .read()
            .get(module_id)
            .map(|(_, _, module)| module.clone())
    }

    pub fn load_checksum_from_cache(&self, module_id: &ModuleId) -> Option<Checksum> {
        self.checksums.read().get(module_id).cloned()
    }

    fn deserialize_module(&self, module_blob: &Bytes) -> PartialVMResult<CompiledModule> {
        CompiledModule::deserialize_with_config(&module_blob, &self.deserializer_config).map_err(
            |err| {
                let msg = format!("Deserialization error: {:?}", err);
                PartialVMError::new(StatusCode::CODE_DESERIALIZATION_ERROR).with_message(msg)
            },
        )
    }
}

fn checksum(blob: &[u8]) -> Checksum {
    let mut sha3_256 = Sha3_256::new();
    sha3_256.update(blob);
    sha3_256.finalize().into()
}
