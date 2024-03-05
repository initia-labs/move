// Copyright (c) The Diem Core Contributors
// Copyright (c) The Move Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    config::VMConfig,
    data_cache::TransactionDataCache,
    interpreter::Interpreter,
    loader::{Function, LoadedFunction, Loader, SessionStorageForVerify},
    native_extensions::NativeContextExtensions,
    native_functions::{NativeFunction, NativeFunctions},
    session::{LoadedFunctionInstantiation, SerializedReturnValues, Session},
    session_cache::SessionCache,
};
use bytes::Bytes;
use move_binary_format::{
    access::ModuleAccess,
    compatibility::Compatibility,
    errors::{verification_error, Location, PartialVMError, PartialVMResult, VMResult},
    file_format::LocalIndex,
    normalized, CompiledModule, IndexKind,
};
use move_bytecode_verifier::script_signature;
use move_core_types::{
    account_address::AccountAddress,
    identifier::{IdentStr, Identifier},
    language_storage::{ModuleId, TypeTag},
    metadata::Metadata,
    resolver::MoveResolver,
    value::MoveTypeLayout,
    vm_status::StatusCode,
};
use move_vm_types::{
    gas::GasMeter,
    loaded_data::runtime_types::{Checksum, Type},
    values::{Locals, Reference, VMValueCast, Value},
};
use sha3::{Digest, Sha3_256};
use std::{
    borrow::Borrow,
    collections::{BTreeSet, HashMap},
    sync::Arc,
};

/// An instantiation of the MoveVM.
pub struct VMRuntime {
    pub(crate) loader: Loader,
}

impl VMRuntime {
    pub fn new(
        natives: impl IntoIterator<Item = (AccountAddress, Identifier, Identifier, NativeFunction)>,
        vm_config: VMConfig,
    ) -> PartialVMResult<Self> {
        Ok(VMRuntime {
            loader: Loader::new(NativeFunctions::new(natives)?, vm_config),
        })
    }

    /// Create a new Session backed by the given storage.
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
            runtime: &self,
            data_cache: TransactionDataCache::new(remote),
            session_cache: SessionCache::new(
                remote,
                self.loader.vm_config.deserializer_config.clone(),
            ),
            native_extensions,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn publish_module_bundle(
        &self,
        modules: Vec<Vec<u8>>,
        sender: AccountAddress,
        data_store: &mut TransactionDataCache,
        session_cache: &mut SessionCache,
        _gas_meter: &mut impl GasMeter,
        compat: Compatibility,
    ) -> VMResult<()> {
        // make checksum records for the publishing modules
        let mut checksums: HashMap<ModuleId, Checksum> = HashMap::new();

        // deserialize the modules. Perform bounds check. After this indexes can be
        // used with the `[]` operator
        let compiled_modules = match modules
            .iter()
            .map(|blob| {
                let mut sha3_256 = Sha3_256::new();
                sha3_256.update(blob);
                let checksum: Checksum = sha3_256.finalize().into();

                CompiledModule::deserialize_with_config(
                    blob,
                    &self.loader.vm_config().deserializer_config,
                )
                .map(|m| {
                    checksums.insert(m.self_id(), checksum);

                    m
                })
            })
            .collect::<PartialVMResult<Vec<_>>>()
        {
            Ok(modules) => modules,
            Err(err) => {
                return Err(err
                    .append_message_with_separator(
                        '\n',
                        "[VM] module deserialization failed".to_string(),
                    )
                    .finish(Location::Undefined));
            },
        };

        // Make sure all modules' self addresses matches the transaction sender. The self address is
        // where the module will actually be published. If we did not check this, the sender could
        // publish a module under anyone's account.
        for module in &compiled_modules {
            if module.address() != &sender {
                return Err(verification_error(
                    StatusCode::MODULE_ADDRESS_DOES_NOT_MATCH_SENDER,
                    IndexKind::AddressIdentifier,
                    module.self_handle_idx().0,
                )
                .finish(Location::Undefined));
            }
        }

        // Collect ids for modules that are published together
        let mut bundle_unverified = BTreeSet::new();

        // For now, we assume that all modules can be republished, as long as the new module is
        // backward compatible with the old module.
        //
        // TODO: in the future, we may want to add restrictions on module republishing, possibly by
        // changing the bytecode format to include an `is_upgradable` flag in the CompiledModule.
        for module in &compiled_modules {
            let module_id = module.self_id();

            if session_cache
                .exists_module(&module_id)
                .map_err(|e| e.finish(Location::Module(module_id.clone())))?
                && compat.need_check_compat()
            {
                let old_module_ref = self.loader.load_module(&module_id, session_cache)?;
                let old_module = old_module_ref.compiled_module();
                let old_m = normalized::Module::new(old_module);
                let new_m = normalized::Module::new(module);
                compat
                    .check(&old_m, &new_m)
                    .map_err(|e| e.finish(Location::Undefined))?;
            }
            if !bundle_unverified.insert(module_id) {
                return Err(PartialVMError::new(StatusCode::DUPLICATE_MODULE_NAME)
                    .finish(Location::Undefined));
            }
        }

        // Perform bytecode and loading verification. Modules must be sorted in topological order.
        self.loader.verify_module_bundle_for_publication(
            &compiled_modules,
            &SessionStorageForVerify::new(session_cache, &checksums),
        )?;

        // NOTE: we want to (informally) argue that all modules pass the linking check before being
        // published to the data store.
        //
        // The linking check consists of two checks actually
        // - dependencies::verify_module(module, all_imm_deps)
        // - cyclic_dependencies::verify_module(module, fn_imm_deps, fn_imm_friends)
        //
        // [Claim 1]
        // We show that the `dependencies::verify_module` check is always satisfied whenever a
        // module M is published or updated and the `all_imm_deps` contains the actual modules
        // required by M.
        //
        // Suppose M depends on D, and we now consider the following scenarios:
        // 1) D does not appear in the bundle together with M
        // -- In this case, D must be either in the code cache or in the data store which can be
        //    loaded into the code cache (and pass all checks on D).
        //    - If D is missing, the linking will fail and return an error.
        //    - If D exists, D will be added to the `all_imm_deps` arg when checking M.
        //
        // 2) D appears in the bundle *before* M
        // -- In this case, regardless of whether D is in code cache or not, D will be put into the
        //    `bundle_verified` argument and modules in `bundle_verified` will be prioritized before
        //    returning a module in code cache.
        //
        // 3) D appears in the bundle *after* M
        // -- This technically should be discouraged but this is user input so we cannot have this
        //    assumption here. But nevertheless, we can still make the claim 1 even in this case.
        //    When M is verified, flow 1) is effectively activated, which means:
        //    - If the code cache or the data store does not contain a D' which has the same name
        //      with D, then the linking will fail and return an error.
        //    - If D' exists, and M links against D', then when verifying D in a later time point,
        //      a compatibility check will be invoked to ensure that D is compatible with D',
        //      meaning, whichever module that links against D' will have to link against D as well.
        //
        // [Claim 2]
        // We show that the `cyclic_dependencies::verify_module` check is always satisfied whenever
        // a module M is published or updated and the dep/friend modules returned by the transitive
        // dependency closure functions are valid.
        //
        // Currently, the code is written in a way that, from the view point of the
        // `cyclic_dependencies::verify_module` check, modules checked prior to module M in the same
        // bundle looks as if they have already been published and loaded to the code cache.
        //
        // Therefore, if M forms a cyclic dependency with module A in the same bundle that is
        // checked prior to M, such an error will be detected. However, if M forms a cyclic
        // dependency with a module X that appears in the same bundle *after* M. The cyclic
        // dependency can only be caught when X is verified.
        //
        // In summary: the code is written in a way that, certain checks are skipped while checking
        // each individual module in the bundle in order. But if every module in the bundle pass
        // all the checks, then the whole bundle can be published/upgraded together. Otherwise,
        // none of the module can be published/updated.

        // All modules verified, publish them to data cache
        for (module, blob) in compiled_modules.into_iter().zip(modules.into_iter()) {
            let module_id = module.self_id();
            let checksum = checksums.remove(&module_id).unwrap();
            let is_republishing = session_cache
                .exists_module(&module_id)
                .map_err(|e| e.finish(Location::Module(module_id.clone())))?;

            let module_bytes: Bytes = blob.into();
            session_cache
                .record_publish(&module_id, module_bytes.clone(), checksum)
                .map_err(|e| e.finish(Location::Module(module_id.clone())))?;
            data_store.publish_module(&module_id, module_bytes, is_republishing)?;
        }
        Ok(())
    }

    fn deserialize_arg(
        &self,
        checksum_store: &SessionCache,
        ty: &Type,
        arg: impl Borrow<[u8]>,
    ) -> PartialVMResult<Value> {
        let (layout, has_identifier_mappings) = match self
            .loader
            .type_to_type_layout_with_identifier_mappings(ty, checksum_store)
        {
            Ok(layout) => layout,
            Err(_err) => {
                return Err(PartialVMError::new(
                    StatusCode::INVALID_PARAM_TYPE_FOR_DESERIALIZATION,
                )
                .with_message("[VM] failed to get layout from type".to_string()));
            },
        };

        let deserialization_error = || -> PartialVMError {
            PartialVMError::new(StatusCode::FAILED_TO_DESERIALIZE_ARGUMENT)
                .with_message("[VM] failed to deserialize argument".to_string())
        };

        // Make sure we do not construct values which might have identifiers
        // inside. This should be guaranteed by transaction argument validation
        // but because it does not use layouts we double-check here.
        if has_identifier_mappings {
            return Err(deserialization_error());
        }

        match Value::simple_deserialize(arg.borrow(), &layout) {
            Some(val) => Ok(val),
            None => Err(deserialization_error()),
        }
    }

    fn deserialize_args(
        &self,
        checksum_store: &SessionCache,
        arg_tys: Vec<Type>,
        serialized_args: Vec<impl Borrow<[u8]>>,
    ) -> PartialVMResult<(Locals, Vec<Value>)> {
        if arg_tys.len() != serialized_args.len() {
            return Err(
                PartialVMError::new(StatusCode::NUMBER_OF_ARGUMENTS_MISMATCH).with_message(
                    format!(
                        "argument length mismatch: expected {} got {}",
                        arg_tys.len(),
                        serialized_args.len()
                    ),
                ),
            );
        }

        // Create a list of dummy locals. Each value stored will be used be borrowed and passed
        // by reference to the invoked function
        let mut dummy_locals = Locals::new(arg_tys.len());
        // Arguments for the invoked function. These can be owned values or references
        let deserialized_args = arg_tys
            .into_iter()
            .zip(serialized_args)
            .enumerate()
            .map(|(idx, (arg_ty, arg_bytes))| match &arg_ty {
                Type::MutableReference(inner_t) | Type::Reference(inner_t) => {
                    dummy_locals.store_loc(
                        idx,
                        self.deserialize_arg(checksum_store, inner_t, arg_bytes)?,
                        self.loader
                            .vm_config()
                            .enable_invariant_violation_check_in_swap_loc,
                    )?;
                    dummy_locals.borrow_loc(idx)
                },
                _ => self.deserialize_arg(checksum_store, &arg_ty, arg_bytes),
            })
            .collect::<PartialVMResult<Vec<_>>>()?;
        Ok((dummy_locals, deserialized_args))
    }

    fn serialize_return_value(
        &self,
        checksum_store: &SessionCache,
        ty: &Type,
        value: Value,
    ) -> PartialVMResult<(Vec<u8>, MoveTypeLayout)> {
        let (ty, value) = match ty {
            Type::Reference(inner) | Type::MutableReference(inner) => {
                let ref_value: Reference = value.cast().map_err(|_err| {
                    PartialVMError::new(StatusCode::INTERNAL_TYPE_ERROR).with_message(
                        "non reference value given for a reference typed return value".to_string(),
                    )
                })?;
                let inner_value = ref_value.read_ref()?;
                (&**inner, inner_value)
            },
            _ => (ty, value),
        };

        let (layout, has_identifier_mappings) = self
            .loader
            .type_to_type_layout_with_identifier_mappings(ty, checksum_store)
            .map_err(|_err| {
                PartialVMError::new(StatusCode::VERIFICATION_ERROR).with_message(
                    "entry point functions cannot have non-serializable return types".to_string(),
                )
            })?;
        let serialization_error = || -> PartialVMError {
            PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
                .with_message("failed to serialize return values".to_string())
        };

        // Disallow native values to escape through return values of a function.
        if has_identifier_mappings {
            return Err(serialization_error());
        }

        let bytes = value
            .simple_serialize(&layout)
            .ok_or_else(serialization_error)?;

        // INITIA CUSTOM
        // for serialization
        let layout_for_return = self
            .loader
            .type_to_fully_annotated_layout(ty, checksum_store)
            .map_err(|_err| {
                PartialVMError::new(StatusCode::VERIFICATION_ERROR).with_message(
                    "entry point functions cannot have non-serializable return types".to_string(),
                )
            })?;

        Ok((bytes, layout_for_return))
    }

    fn serialize_return_values(
        &self,
        checksum_store: &SessionCache,
        return_types: &[Type],
        return_values: Vec<Value>,
    ) -> PartialVMResult<Vec<(Vec<u8>, MoveTypeLayout)>> {
        if return_types.len() != return_values.len() {
            return Err(
                PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR).with_message(
                    format!(
                        "declared {} return types, but got {} return values",
                        return_types.len(),
                        return_values.len()
                    ),
                ),
            );
        }

        return_types
            .iter()
            .zip(return_values)
            .map(|(ty, value)| self.serialize_return_value(checksum_store, ty, value))
            .collect()
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::needless_collect)]
    fn execute_function_impl(
        &self,
        func: Arc<Function>,
        ty_args: Vec<Type>,
        param_types: Vec<Type>,
        return_types: Vec<Type>,
        serialized_args: Vec<impl Borrow<[u8]>>,
        data_store: &mut TransactionDataCache,
        checksum_store: &SessionCache,
        gas_meter: &mut impl GasMeter,
        extensions: &mut NativeContextExtensions,
    ) -> VMResult<SerializedReturnValues> {
        let arg_types = param_types
            .into_iter()
            .map(|ty| ty.subst(&ty_args))
            .collect::<PartialVMResult<Vec<_>>>()
            .map_err(|err| err.finish(Location::Undefined))?;
        let mut_ref_args = arg_types
            .iter()
            .enumerate()
            .filter_map(|(idx, ty)| match ty {
                Type::MutableReference(inner) => Some((idx, inner.clone())),
                _ => None,
            })
            .collect::<Vec<_>>();
        let (mut dummy_locals, deserialized_args) = self
            .deserialize_args(checksum_store, arg_types, serialized_args)
            .map_err(|e| e.finish(Location::Undefined))?;
        let return_types = return_types
            .into_iter()
            .map(|ty| ty.subst(&ty_args))
            .collect::<PartialVMResult<Vec<_>>>()
            .map_err(|err| err.finish(Location::Undefined))?;

        let return_values = Interpreter::entrypoint(
            func,
            ty_args,
            deserialized_args,
            data_store,
            checksum_store,
            gas_meter,
            extensions,
            &self.loader,
        )?;

        let serialized_return_values = self
            .serialize_return_values(checksum_store, &return_types, return_values)
            .map_err(|e| e.finish(Location::Undefined))?;
        let serialized_mut_ref_outputs = mut_ref_args
            .into_iter()
            .map(|(idx, ty)| {
                // serialize return values first in the case that a value points into this local
                let local_val = dummy_locals.move_loc(
                    idx,
                    self.loader
                        .vm_config()
                        .enable_invariant_violation_check_in_swap_loc,
                )?;
                let (bytes, layout) =
                    self.serialize_return_value(checksum_store, &ty, local_val)?;
                Ok((idx as LocalIndex, bytes, layout))
            })
            .collect::<PartialVMResult<_>>()
            .map_err(|e| e.finish(Location::Undefined))?;

        // locals should not be dropped until all return values are serialized
        std::mem::drop(dummy_locals);

        Ok(SerializedReturnValues {
            mutable_reference_outputs: serialized_mut_ref_outputs,
            return_values: serialized_return_values,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn execute_function(
        &self,
        module: &ModuleId,
        function_name: &IdentStr,
        ty_args: Vec<TypeTag>,
        serialized_args: Vec<impl Borrow<[u8]>>,
        data_store: &mut TransactionDataCache,
        session_cache: &SessionCache,
        gas_meter: &mut impl GasMeter,
        extensions: &mut NativeContextExtensions,
        bypass_declared_entry_check: bool,
    ) -> VMResult<SerializedReturnValues> {
        // load the function
        let (module, function, instantiation) =
            self.loader
                .load_function(module, function_name, &ty_args, session_cache)?;

        self.execute_function_instantiation(
            LoadedFunction { module, function },
            instantiation,
            serialized_args,
            data_store,
            session_cache,
            gas_meter,
            extensions,
            bypass_declared_entry_check,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn execute_function_instantiation(
        &self,
        func: LoadedFunction,
        function_instantiation: LoadedFunctionInstantiation,
        serialized_args: Vec<impl Borrow<[u8]>>,

        data_store: &mut TransactionDataCache,
        checksum_store: &SessionCache,
        gas_meter: &mut impl GasMeter,
        extensions: &mut NativeContextExtensions,
        bypass_declared_entry_check: bool,
    ) -> VMResult<SerializedReturnValues> {
        // load the function
        let LoadedFunctionInstantiation {
            type_arguments,
            parameters,
            return_,
        } = function_instantiation;

        use move_binary_format::{binary_views::BinaryIndexedView, file_format::SignatureIndex};
        fn check_is_entry(
            _resolver: &BinaryIndexedView,
            is_entry: bool,
            _parameters_idx: SignatureIndex,
            _return_idx: Option<SignatureIndex>,
        ) -> PartialVMResult<()> {
            if is_entry {
                Ok(())
            } else {
                Err(PartialVMError::new(
                    StatusCode::EXECUTE_ENTRY_FUNCTION_CALLED_ON_NON_ENTRY_FUNCTION,
                ))
            }
        }
        let additional_signature_checks = if bypass_declared_entry_check {
            move_bytecode_verifier::no_additional_script_signature_checks
        } else {
            check_is_entry
        };

        let LoadedFunction { module, function } = func;

        script_signature::verify_module_function_signature_by_name(
            module.compiled_module(),
            IdentStr::new(function.as_ref().name()).expect(""),
            additional_signature_checks,
        )?;

        // execute the function
        self.execute_function_impl(
            function,
            type_arguments,
            parameters,
            return_,
            serialized_args,
            data_store,
            checksum_store,
            gas_meter,
            extensions,
        )
    }

    #[allow(clippy::too_many_arguments)]
    // See Session::execute_script for what contracts to follow.
    pub(crate) fn execute_script(
        &self,
        script: impl Borrow<[u8]>,
        ty_args: Vec<TypeTag>,
        serialized_args: Vec<impl Borrow<[u8]>>,
        data_store: &mut TransactionDataCache,
        session_cache: &SessionCache,
        gas_meter: &mut impl GasMeter,
        extensions: &mut NativeContextExtensions,
    ) -> VMResult<SerializedReturnValues> {
        // load the script, perform verification
        let (
            func,
            LoadedFunctionInstantiation {
                type_arguments,
                parameters,
                return_,
            },
        ) = self
            .loader
            .load_script(script.borrow(), &ty_args, session_cache)?;
        // execute the function
        self.execute_function_impl(
            func,
            type_arguments,
            parameters,
            return_,
            serialized_args,
            data_store,
            session_cache,
            gas_meter,
            extensions,
        )
    }

    pub fn get_fully_annotated_type_layout(
        &self,
        session_cache: &SessionCache,
        type_tag: &TypeTag,
    ) -> VMResult<MoveTypeLayout> {
        self.loader
            .get_fully_annotated_type_layout(type_tag, session_cache)
    }

    pub fn flush_unused_module_cache(&self) {
        self.loader.flush_unused_module_cache()
    }

    pub fn flush_unused_script_cache(&self) {
        self.loader.flush_unused_script_cache()
    }

    pub fn with_module_metadata<T, F>(
        &self,
        session_cache: &SessionCache,
        module_id: &ModuleId,
        f: F,
    ) -> PartialVMResult<Option<T>>
    where
        F: FnOnce(&[Metadata]) -> Option<T>,
    {
        Ok(self
            .loader
            .get_module(module_id, session_cache)?
            .and_then(|v| f(&v.compiled_module().metadata)))
    }
}
