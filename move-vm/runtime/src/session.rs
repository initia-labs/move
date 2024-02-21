// Copyright (c) The Diem Core Contributors
// Copyright (c) The Move Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    config::VMConfig,
    data_cache::TransactionDataCache,
    loader::{LoadedFunction, Loader},
    move_vm::MoveVM,
    native_extensions::NativeContextExtensions,
    session_cache::SessionCache,
};
use bytes::Bytes;
use move_binary_format::{
    compatibility::Compatibility,
    errors::*,
    file_format::{AbilitySet, LocalIndex},
    CompiledModule,
};
use move_core_types::{
    account_address::AccountAddress,
    effects::{ChangeSet, Changes},
    gas_algebra::NumBytes,
    identifier::IdentStr,
    language_storage::{ModuleId, TypeTag},
    metadata::Metadata,
    value::MoveTypeLayout,
};
use move_vm_types::{
    gas::GasMeter,
    loaded_data::runtime_types::{Checksum, StructIdentifier, StructType, Type},
    values::{GlobalValue, Value},
};
use std::{borrow::Borrow, sync::Arc};

pub struct Session<'r, 'l> {
    pub(crate) move_vm: &'l MoveVM,
    pub(crate) data_cache: TransactionDataCache<'r>,
    pub(crate) session_cache: SessionCache<'r>,
    pub(crate) native_extensions: NativeContextExtensions<'r>,
}

/// Serialized return values from function/script execution
/// Simple struct is designed just to convey meaning behind serialized values
#[derive(Debug)]
pub struct SerializedReturnValues {
    /// The value of any arguments that were mutably borrowed.
    /// Non-mut borrowed values are not included
    pub mutable_reference_outputs: Vec<(LocalIndex, Vec<u8>, MoveTypeLayout)>,
    /// The return values from the function
    pub return_values: Vec<(Vec<u8>, MoveTypeLayout)>,
}

impl<'r, 'l> Session<'r, 'l> {
    /// Execute a Move function with the given arguments. This is mainly designed for an external
    /// environment to invoke system logic written in Move.
    ///
    /// NOTE: There are NO checks on the `args` except that they can deserialize into the provided
    /// types.
    /// The ability to deserialize `args` into arbitrary types is *very* powerful, e.g. it can
    /// used to manufacture `signer`'s or `Coin`'s from raw bytes. It is the responsibility of the
    /// caller (e.g. adapter) to ensure that this power is used responsibly/securely for its
    /// use-case.
    ///
    /// The caller MUST ensure
    ///   - All types and modules referred to by the type arguments exist.
    ///   - The signature is valid for the rules of the adapter
    ///
    /// The Move VM MUST return an invariant violation if the caller fails to follow any of the
    /// rules above.
    ///
    /// The VM will check that the function is marked as an 'entry' function.
    ///
    /// Currently if any other error occurs during execution, the Move VM will simply propagate that
    /// error back to the outer environment without handling/translating it. This behavior may be
    /// revised in the future.
    ///
    /// In case an invariant violation occurs, the whole Session should be considered corrupted and
    /// one shall not proceed with effect generation.
    pub fn execute_entry_function(
        &mut self,
        loader: &Loader,
        module: &ModuleId,
        function_name: &IdentStr,
        ty_args: Vec<TypeTag>,
        args: Vec<impl Borrow<[u8]>>,
        gas_meter: &mut impl GasMeter,
    ) -> VMResult<SerializedReturnValues> {
        let bypass_declared_entry_check = false;
        self.move_vm.runtime.execute_function(
            module,
            function_name,
            ty_args,
            args,
            loader,
            &mut self.data_cache,
            &self.session_cache,
            gas_meter,
            &mut self.native_extensions,
            bypass_declared_entry_check,
        )
    }

    /// Similar to execute_entry_function, but it bypasses visibility checks
    pub fn execute_function_bypass_visibility(
        &mut self,
        loader: &Loader,
        module: &ModuleId,
        function_name: &IdentStr,
        ty_args: Vec<TypeTag>,
        args: Vec<impl Borrow<[u8]>>,
        gas_meter: &mut impl GasMeter,
    ) -> VMResult<SerializedReturnValues> {
        let bypass_declared_entry_check = true;
        self.move_vm.runtime.execute_function(
            module,
            function_name,
            ty_args,
            args,
            loader,
            &mut self.data_cache,
            &self.session_cache,
            gas_meter,
            &mut self.native_extensions,
            bypass_declared_entry_check,
        )
    }

    pub fn execute_instantiated_function(
        &mut self,
        loader: &Loader,
        func: LoadedFunction,
        instantiation: LoadedFunctionInstantiation,
        args: Vec<impl Borrow<[u8]>>,
        gas_meter: &mut impl GasMeter,
    ) -> VMResult<SerializedReturnValues> {
        self.move_vm.runtime.execute_function_instantiation(
            func,
            instantiation,
            args,
            loader,
            &mut self.data_cache,
            &self.session_cache,
            gas_meter,
            &mut self.native_extensions,
            true,
        )
    }

    /// Execute a transaction script.
    ///
    /// The Move VM MUST return a user error (in other words, an error that's not an invariant
    /// violation) if
    ///   - The script fails to deserialize or verify. Not all expressible signatures are valid.
    ///     See `move_bytecode_verifier::script_signature` for the rules.
    ///   - Type arguments refer to a non-existent type.
    ///   - Arguments (senders included) fail to deserialize or fail to match the signature of the
    ///     script function.
    ///
    /// If any other error occurs during execution, the Move VM MUST propagate that error back to
    /// the caller.
    /// Besides, no user input should cause the Move VM to return an invariant violation.
    ///
    /// In case an invariant violation occurs, the whole Session should be considered corrupted and
    /// one shall not proceed with effect generation.
    pub fn execute_script(
        &mut self,
        loader: &Loader,
        script: impl Borrow<[u8]>,
        ty_args: Vec<TypeTag>,
        args: Vec<impl Borrow<[u8]>>,
        gas_meter: &mut impl GasMeter,
    ) -> VMResult<SerializedReturnValues> {
        self.move_vm.runtime.execute_script(
            script,
            ty_args,
            args,
            loader,
            &mut self.data_cache,
            &self.session_cache,
            gas_meter,
            &mut self.native_extensions,
        )
    }

    /// Publish the given module.
    ///
    /// The Move VM MUST return a user error, i.e., an error that's not an invariant violation, if
    ///   - The module fails to deserialize or verify.
    ///   - The sender address does not match that of the module.
    ///   - (Republishing-only) the module to be updated is not backward compatible with the old module.
    ///   - (Republishing-only) the module to be updated introduces cyclic dependencies.
    ///
    /// The Move VM should not be able to produce other user errors.
    /// Besides, no user input should cause the Move VM to return an invariant violation.
    ///
    /// In case an invariant violation occurs, the whole Session should be considered corrupted and
    /// one shall not proceed with effect generation.
    pub fn publish_module(
        &mut self,
        loader: &Loader,
        module: Vec<u8>,
        sender: AccountAddress,
        gas_meter: &mut impl GasMeter,
    ) -> VMResult<()> {
        self.publish_module_bundle(loader, vec![module], sender, gas_meter)
    }

    /// Publish a series of modules.
    ///
    /// The Move VM MUST return a user error, i.e., an error that's not an invariant violation, if
    /// any module fails to deserialize or verify (see the full list of  failing conditions in the
    /// `publish_module` API). The publishing of the module series is an all-or-nothing action:
    /// either all modules are published to the data store or none is.
    ///
    /// Similar to the `publish_module` API, the Move VM should not be able to produce other user
    /// errors. Besides, no user input should cause the Move VM to return an invariant violation.
    ///
    /// In case an invariant violation occurs, the whole Session should be considered corrupted and
    /// one shall not proceed with effect generation.
    ///
    /// This operation performs compatibility checks if a module is replaced. See also
    /// `move_binary_format::compatibility`.
    pub fn publish_module_bundle(
        &mut self,
        loader: &Loader,
        modules: Vec<Vec<u8>>,
        sender: AccountAddress,
        gas_meter: &mut impl GasMeter,
    ) -> VMResult<()> {
        self.move_vm.runtime.publish_module_bundle(
            modules,
            sender,
            loader,
            &mut self.data_cache,
            &mut self.session_cache,
            gas_meter,
            Compatibility::full_check(),
        )
    }

    /// Same like `publish_module_bundle` but with a custom compatibility check.
    pub fn publish_module_bundle_with_compat_config(
        &mut self,
        loader: &Loader,
        modules: Vec<Vec<u8>>,
        sender: AccountAddress,
        gas_meter: &mut impl GasMeter,
        compat_config: Compatibility,
    ) -> VMResult<()> {
        self.move_vm.runtime.publish_module_bundle(
            modules,
            sender,
            loader,
            &mut self.data_cache,
            &mut self.session_cache,
            gas_meter,
            compat_config,
        )
    }

    pub fn publish_module_bundle_relax_compatibility(
        &mut self,
        loader: &Loader,
        modules: Vec<Vec<u8>>,
        sender: AccountAddress,
        gas_meter: &mut impl GasMeter,
    ) -> VMResult<()> {
        self.move_vm.runtime.publish_module_bundle(
            modules,
            sender,
            loader,
            &mut self.data_cache,
            &mut self.session_cache,
            gas_meter,
            Compatibility::no_check(),
        )
    }

    pub fn num_mutated_accounts(&self, sender: &AccountAddress) -> u64 {
        self.data_cache.num_mutated_accounts(sender)
    }

    /// Finish up the session and produce the side effects.
    ///
    /// This function should always succeed with no user errors returned, barring invariant violations.
    ///
    /// This MUST NOT be called if there is a previous invocation that failed with an invariant violation.
    pub fn finish(self, loader: &Loader) -> VMResult<ChangeSet> {
        self.data_cache
            .into_effects(loader, &self.session_cache)
            .map_err(|e| e.finish(Location::Undefined))
    }

    pub fn finish_with_custom_effects<Resource>(
        self,
        loader: &Loader,
        resource_converter: &dyn Fn(Value, MoveTypeLayout, bool) -> PartialVMResult<Resource>,
    ) -> VMResult<Changes<Bytes, Checksum, Resource>> {
        self.data_cache
            .into_custom_effects(resource_converter, loader, &self.session_cache)
            .map_err(|e| e.finish(Location::Undefined))
    }

    /// Same like `finish`, but also extracts the native context extensions from the session.
    pub fn finish_with_extensions(
        self,
        loader: &Loader,
    ) -> VMResult<(ChangeSet, NativeContextExtensions<'r>)> {
        let Session {
            data_cache,
            native_extensions,
            ..
        } = self;
        let change_set = data_cache
            .into_effects(loader, &self.session_cache)
            .map_err(|e| e.finish(Location::Undefined))?;
        Ok((change_set, native_extensions))
    }

    #[allow(clippy::type_complexity)]
    pub fn finish_with_extensions_with_custom_effects<Resource>(
        self,
        loader: &Loader,
        resource_converter: &dyn Fn(Value, MoveTypeLayout, bool) -> PartialVMResult<Resource>,
    ) -> VMResult<(
        Changes<Bytes, Checksum, Resource>,
        NativeContextExtensions<'r>,
    )> {
        let Session {
            data_cache,
            native_extensions,
            ..
        } = self;
        let change_set = data_cache
            .into_custom_effects(resource_converter, loader, &self.session_cache)
            .map_err(|e| e.finish(Location::Undefined))?;
        Ok((change_set, native_extensions))
    }

    pub fn finish_with_extensions_with_session_cache(
        self,
        loader: &Loader,
    ) -> VMResult<(ChangeSet, SessionCache<'r>, NativeContextExtensions<'r>)> {
        let Session {
            data_cache,
            session_cache,
            native_extensions,
            ..
        } = self;
        let change_set = data_cache
            .into_effects(loader, &session_cache)
            .map_err(|e| e.finish(Location::Undefined))?;
        Ok((change_set, session_cache, native_extensions))
    }

    /// Try to load a resource from remote storage and create a corresponding GlobalValue
    /// that is owned by the data store.
    pub fn load_resource(
        &mut self,
        loader: &Loader,
        addr: AccountAddress,
        ty: &Type,
    ) -> PartialVMResult<(&mut GlobalValue, Option<NumBytes>)> {
        self.data_cache
            .load_resource(loader, &self.session_cache, addr, ty)
    }

    /// Get the serialized format of a `CompiledModule` given a `ModuleId`.
    pub fn load_module_bytes(&self, module_id: &ModuleId) -> VMResult<Bytes> {
        self.session_cache
            .load_module(module_id)
            .map_err(|e| e.finish(Location::Undefined))
    }

    /// Check if this module exists.
    pub fn exists_module(&self, module_id: &ModuleId) -> VMResult<bool> {
        self.session_cache.exists_module(module_id)
    }

    /// Load a script and all of its types into cache
    pub fn load_script(
        &self,
        loader: &Loader,
        script: impl Borrow<[u8]>,
        ty_args: Vec<TypeTag>,
    ) -> VMResult<LoadedFunctionInstantiation> {
        let (_, instantiation) = loader.load_script(
            script.borrow(),
            &ty_args,
            &self.session_cache,
            &self.session_cache,
        )?;
        Ok(instantiation)
    }

    /// Load a module, a function, and all of its types into cache
    pub fn load_function_with_type_arg_inference(
        &self,
        loader: &Loader,
        module_id: &ModuleId,
        function_name: &IdentStr,
        expected_return_type: &Type,
    ) -> VMResult<(LoadedFunction, LoadedFunctionInstantiation)> {
        let (func, instantiation) = loader.load_function_with_type_arg_inference(
            module_id,
            function_name,
            expected_return_type,
            &self.session_cache,
            &self.session_cache,
        )?;
        Ok((func, instantiation))
    }

    /// Load a module, a function, and all of its types into cache
    pub fn load_function(
        &self,
        loader: &Loader,
        module_id: &ModuleId,
        function_name: &IdentStr,
        type_arguments: &[TypeTag],
    ) -> VMResult<LoadedFunctionInstantiation> {
        let (_, _, instantiation) = loader.load_function(
            module_id,
            function_name,
            type_arguments,
            &self.session_cache,
            &self.session_cache,
        )?;
        Ok(instantiation)
    }

    pub fn load_type(&self, loader: &Loader, type_tag: &TypeTag) -> VMResult<Type> {
        loader.load_type(type_tag, &self.session_cache, &self.session_cache)
    }

    pub fn get_type_layout(&self, loader: &Loader, type_tag: &TypeTag) -> VMResult<MoveTypeLayout> {
        loader.get_type_layout(type_tag, &self.session_cache, &self.session_cache)
    }

    pub fn get_type_tag(&self, loader: &Loader, ty: &Type) -> VMResult<TypeTag> {
        loader
            .type_to_type_tag(ty, &self.session_cache)
            .map_err(|e| e.finish(Location::Undefined))
    }

    /// Gets the abilities for this type, at it's particular instantiation
    pub fn get_type_abilities(&self, ty: &Type) -> VMResult<AbilitySet> {
        ty.abilities().map_err(|e| e.finish(Location::Undefined))
    }

    /// Gets the underlying native extensions.
    pub fn get_native_extensions(&mut self) -> &mut NativeContextExtensions<'r> {
        &mut self.native_extensions
    }

    pub fn get_move_vm(&self) -> &'l MoveVM {
        self.move_vm
    }

    pub fn get_vm_config(&self, loader: &'l Loader) -> &'l VMConfig {
        &loader.vm_config
    }

    pub fn get_struct_type(
        &self,
        loader: &Loader,
        id: &StructIdentifier,
    ) -> Option<Arc<StructType>> {
        loader
            .get_struct_type_by_identifier(id, &self.session_cache)
            .ok()
    }

    /// Load a module into VM's code cache
    pub fn load_module(
        &self,
        loader: &Loader,
        module_id: &ModuleId,
    ) -> VMResult<Arc<CompiledModule>> {
        loader
            .load_module(module_id, &self.session_cache, &self.session_cache)
            .map(|arc_module| arc_module.arc_module())
    }

    /// Attempts to discover metadata in a given module with given key. Availability
    /// of this data may depend on multiple aspects. In general, no hard assumptions of
    /// availability should be made, but typically, one can expect that
    /// the modules which have been involved in the execution of the last session are available.
    ///
    /// This is called by an adapter to extract, for example, debug information out of
    /// the metadata section of the code for post mortem analysis. Notice that because
    /// of ownership of the underlying binary representation of modules hidden behind an rwlock,
    /// this actually has to hand back a copy of the associated metadata, so metadata should
    /// be organized keeping this in mind.
    ///
    /// TODO: in the new loader architecture, as the loader is visible to the adapter, one would
    ///   call this directly via the loader instead of the VM.
    pub fn with_module_metadata<T, F>(
        &self,
        loader: &Loader,
        module_id: &ModuleId,
        f: F,
    ) -> PartialVMResult<Option<T>>
    where
        F: FnOnce(&[Metadata]) -> Option<T>,
    {
        Ok(loader
            .get_module(module_id, &self.session_cache)?
            .and_then(|v| f(&v.compiled_module().metadata)))
    }
}

pub struct LoadedFunctionInstantiation {
    pub type_arguments: Vec<Type>,
    pub parameters: Vec<Type>,
    pub return_: Vec<Type>,
}
