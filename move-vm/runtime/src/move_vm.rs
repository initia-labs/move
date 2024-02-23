// Copyright (c) The Diem Core Contributors
// Copyright (c) The Move Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    config::VMConfig, data_cache::TransactionDataCache, native_extensions::NativeContextExtensions,
    native_functions::NativeFunction, runtime::VMRuntime, session::Session,
    session_cache::SessionCache,
};
use move_binary_format::errors::{Location, PartialVMError, VMResult};
use move_core_types::{
    account_address::AccountAddress, identifier::Identifier, language_storage::TypeTag,
    resolver::MoveResolver, value::MoveTypeLayout,
};

pub struct MoveVM {
    pub(crate) runtime: VMRuntime,
}

impl MoveVM {
    pub fn new(
        natives: impl IntoIterator<Item = (AccountAddress, Identifier, Identifier, NativeFunction)>,
    ) -> VMResult<Self> {
        Self::new_with_config(natives, VMConfig::default())
    }

    pub fn new_with_config(
        natives: impl IntoIterator<Item = (AccountAddress, Identifier, Identifier, NativeFunction)>,
        vm_config: VMConfig,
    ) -> VMResult<Self> {
        Ok(Self {
            runtime: VMRuntime::new(natives, vm_config)
                .map_err(|err| err.finish(Location::Undefined))?,
        })
    }

    /// Create a new Session backed by the given storage.
    ///
    /// Right now it is the caller's responsibility to ensure cache coherence of the Move VM Loader
    ///   - When a module gets published in a Move VM Session, and then gets used by another
    ///     transaction, it will be loaded into the code cache and stay there even if the resulted
    ///     effects do not get committed back to the storage when the Session ends.
    ///   - As a result, if one wants to have multiple sessions at a time, one needs to make sure
    ///     none of them will try to publish a module. In other words, if there is a module publishing
    ///     Session it must be the only Session existing.
    ///   - In general, a new Move VM needs to be created whenever the storage gets modified by an
    ///     outer environment, or otherwise the states may be out of sync. There are a few exceptional
    ///     cases where this may not be necessary, with the most notable one being the common module
    ///     publishing flow: you can keep using the same Move VM if you publish some modules in a Session
    ///     and apply the effects to the storage when the Session ends.
    pub fn new_session<'r>(
        &self,
        remote: &'r impl MoveResolver<PartialVMError>,
    ) -> Session<'r, '_> {
        self.new_session_with_extensions(remote, NativeContextExtensions::default())
    }

    /// Create a new session, as in `new_session`, but provide native context extensions.
    pub fn new_session_with_extensions<'r>(
        &self,
        remote: &'r impl MoveResolver<PartialVMError>,
        native_extensions: NativeContextExtensions<'r>,
    ) -> Session<'r, '_> {
        Session {
            runtime: &self.runtime,
            data_cache: TransactionDataCache::new(remote),
            session_cache: SessionCache::new(remote),
            native_extensions,
        }
    }

    pub fn get_fully_annotated_type_layout(
        &self,
        session_cache: &SessionCache,
        type_tag: &TypeTag,
    ) -> VMResult<MoveTypeLayout> {
        self.runtime
            .loader
            .get_fully_annotated_type_layout(type_tag, session_cache, session_cache)
    }

    pub fn flush_unused_module_cache(&self) {
        self.runtime.flush_unused_module_cache()
    }

    pub fn flush_unused_script_cache(&self) {
        self.runtime.flush_unused_script_cache()
    }
}
