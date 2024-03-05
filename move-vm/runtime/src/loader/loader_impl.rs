use std::{
    collections::{btree_map, BTreeMap, BTreeSet},
    num::NonZeroUsize,
    sync::Arc,
};

use lazy_static::lazy_static;
use move_binary_format::{
    access::{ModuleAccess, ScriptAccess},
    errors::{verification_error, Location, PartialVMError, PartialVMResult, VMResult},
    file_format::{
        AbilitySet, CompiledScript, StructFieldInformation, TableIndex, TypeParameterIndex,
    },
    CompiledModule, IndexKind,
};
use move_bytecode_verifier::{cyclic_dependencies, dependencies};
use move_core_types::{
    account_address::AccountAddress,
    gas_algebra::NumBytes,
    ident_str,
    identifier::IdentStr,
    language_storage::{ModuleId, StructTag, TypeTag},
    value::{IdentifierMappingKind, MoveFieldLayout, MoveStructLayout, MoveTypeLayout},
    vm_status::StatusCode,
};
use move_vm_types::{
    gas::GasMeter,
    loaded_data::runtime_types::{
        AbilityInfo, Checksum, DepthFormula, StructIdentifier, StructType, Type,
    },
};
use parking_lot::{Mutex, RwLock};
use sha3::{Digest, Sha3_256};
use typed_arena::Arena;

use crate::{
    config::VMConfig, logging::expect_no_verification_errors, module_traversal::TraversalContext,
    native_functions::NativeFunctions, session::LoadedFunctionInstantiation,
};

use super::{
    cache::{CacheHitRecords, ModuleCache, ScriptCache, StructLayoutInfoCacheItem, TypeCache},
    function::{Function, FunctionHandle, LoadedFunction},
    module::Module,
    script::Script,
    SessionStorage,
};

// Max number of modules that can skip re-verification.
const VERIFIED_CACHE_SIZE: usize = 100_000;

// Cache for already verified modules
lazy_static! {
    static ref VERIFIED_MODULES: Mutex<lru::LruCache<[u8; 32], ()>> = Mutex::new(
        lru::LruCache::new(NonZeroUsize::new(VERIFIED_CACHE_SIZE).unwrap())
    );
}

// A Loader is responsible to load scripts and modules and holds the cache of all loaded
// entities. Each cache is protected by a `RwLock`. Operation in the Loader must be thread safe
// (operating on values on the stack) and when cache needs updating the mutex must be taken.
// The `pub(crate)` API is what a Loader offers to the runtime.
pub struct Loader {
    module_cache: RwLock<ModuleCache>,
    script_cache: RwLock<ScriptCache>,
    type_cache: RwLock<TypeCache>,

    module_cache_hits: RwLock<CacheHitRecords>,
    script_cache_hits: RwLock<CacheHitRecords>,

    removed_modules: RwLock<Vec<Checksum>>,
    removed_scripts: RwLock<Vec<Checksum>>,

    natives: NativeFunctions,
    pub(crate) vm_config: VMConfig,
}

impl Loader {
    pub(crate) fn new(natives: NativeFunctions, vm_config: VMConfig) -> Self {
        Self {
            module_cache: RwLock::new(ModuleCache::new()),
            script_cache: RwLock::new(ScriptCache::new()),
            type_cache: RwLock::new(TypeCache::new()),
            module_cache_hits: RwLock::new(CacheHitRecords::new(vm_config.module_cache_capacity)),
            script_cache_hits: RwLock::new(CacheHitRecords::new(vm_config.script_cache_capacity)),
            removed_modules: RwLock::new(Vec::new()),
            removed_scripts: RwLock::new(Vec::new()),
            natives,
            vm_config,
        }
    }

    pub(crate) fn vm_config(&self) -> &VMConfig {
        &self.vm_config
    }

    //
    // Script verification and loading
    //

    // Scripts are verified and dependencies are loaded.
    // Effectively that means modules are cached from leaf to root in the dependency DAG.
    // If a dependency error is found, loading stops and the error is returned.
    // However all modules cached up to that point stay loaded.

    // Entry point for script execution (`MoveVM::execute_script`).
    // Verifies the script if it is not in the cache of scripts loaded.
    // Type parameters are checked as well after every type is loaded.
    pub(crate) fn load_script(
        &self,
        script_blob: &[u8],
        ty_args: &[TypeTag],
        session_storage: &dyn SessionStorage,
    ) -> VMResult<(Arc<Function>, LoadedFunctionInstantiation)> {
        // retrieve or load the script
        let mut sha3_256 = Sha3_256::new();
        sha3_256.update(script_blob);
        let checksum: Checksum = sha3_256.finalize().into();

        let mut locked_script_cache = self.script_cache.write();
        let (main, parameters, return_) = match locked_script_cache.get_main(&checksum) {
            Some(cached) => {
                self.script_cache_hits.write().record_hit(&checksum);

                cached
            },
            None => {
                let ver_script =
                    self.deserialize_and_verify_script(script_blob, session_storage)?;
                let script = Script::new(
                    ver_script,
                    &checksum,
                    &self.module_cache.read(),
                    session_storage,
                )
                .map_err(|e| e.finish(Location::Script))?;

                // insert script to cache
                let cached = locked_script_cache.insert(checksum, script);

                // create cache hits entry
                if let Some(removed) = self.module_cache_hits.write().create(checksum) {
                    self.removed_scripts.write().push(removed);
                }

                cached
            },
        };

        // explicitly drop
        drop(locked_script_cache);

        // verify type arguments
        let mut type_arguments = vec![];
        for ty in ty_args {
            type_arguments.push(self.load_type(ty, session_storage)?);
        }

        if self.vm_config.type_size_limit
            && type_arguments
                .iter()
                .map(|loaded_ty| self.count_type_nodes(loaded_ty))
                .sum::<u64>()
                > MAX_TYPE_INSTANTIATION_NODES
        {
            return Err(
                PartialVMError::new(StatusCode::TOO_MANY_TYPE_NODES).finish(Location::Script)
            );
        };

        self.verify_ty_args(main.type_parameters(), &type_arguments)
            .map_err(|e| e.finish(Location::Script))?;
        let instantiation = LoadedFunctionInstantiation {
            type_arguments,
            parameters,
            return_,
        };
        Ok((main, instantiation))
    }

    // The process of deserialization and verification is not and it must not be under lock.
    // So when publishing modules through the dependency DAG it may happen that a different
    // thread had loaded the module after this process fetched it from storage.
    // Caching will take care of that by asking for each dependency module again under lock.
    fn deserialize_and_verify_script(
        &self,
        script: &[u8],
        session_storage: &dyn SessionStorage,
    ) -> VMResult<CompiledScript> {
        let script = match CompiledScript::deserialize_with_config(
            script,
            &self.vm_config.deserializer_config,
        ) {
            Ok(script) => script,
            Err(err) => {
                let msg = format!("[VM] deserializer for script returned error: {:?}", err);
                return Err(PartialVMError::new(StatusCode::CODE_DESERIALIZATION_ERROR)
                    .with_message(msg)
                    .finish(Location::Script));
            },
        };

        match self.verify_script(&script) {
            Ok(_) => {
                // verify dependencies
                let loaded_deps = script
                    .immediate_dependencies()
                    .into_iter()
                    .map(|module_id| self.load_module(&module_id, session_storage))
                    .collect::<VMResult<_>>()?;
                self.verify_script_dependencies(&script, loaded_deps)?;
                Ok(script)
            },
            Err(err) => Err(err),
        }
    }

    // Script verification steps.
    // See `verify_module()` for module verification steps.
    fn verify_script(&self, script: &CompiledScript) -> VMResult<()> {
        fail::fail_point!("verifier-failpoint-3", |_| { Ok(()) });

        move_bytecode_verifier::verify_script_with_config(&self.vm_config.verifier, script)
    }

    fn verify_script_dependencies(
        &self,
        script: &CompiledScript,
        dependencies: Vec<Arc<Module>>,
    ) -> VMResult<()> {
        let mut deps = vec![];
        for dep in &dependencies {
            deps.push(dep.compiled_module());
        }
        dependencies::verify_script(script, deps)
    }

    //
    // Module verification and loading
    //

    fn load_compiled_module(
        &self,
        id: &ModuleId,
        session_storage: &dyn SessionStorage,
        allow_loading_failure: bool,
    ) -> VMResult<(usize, Checksum, Arc<CompiledModule>)> {
        // if the module is already in the code cache, load the cached version
        let checksum = session_storage
            .load_checksum(id)
            .map_err(|e| e.finish(Location::Module(id.clone())))?;

        if let Some(cached) = self.module_cache.read().get(&checksum) {
            self.module_cache_hits.write().record_hit(&checksum);
            return Ok((cached.size, checksum, cached.module.clone()));
        }

        match session_storage.load_module(id) {
            Ok(data) => Ok(data),
            Err(err) if err.major_status() == StatusCode::CODE_DESERIALIZATION_ERROR => Err(
                expect_no_verification_errors(err.finish(Location::Module(id.clone()))),
            ),
            Err(err) if allow_loading_failure => Err(err.finish(Location::Undefined)),
            Err(err) => Err(expect_no_verification_errors(
                err.finish(Location::Undefined),
            )),
        }
    }

    #[allow(clippy::type_complexity)]
    // Loading verifies the module if it was never loaded.
    fn load_function_without_type_args(
        &self,
        module_id: &ModuleId,
        function_name: &IdentStr,
        session_storage: &dyn SessionStorage,
    ) -> VMResult<(Arc<Module>, Arc<Function>, Vec<Type>, Vec<Type>)> {
        let module = self.load_module(module_id, session_storage)?;
        let func = module
            .resolve_function_by_name(function_name)
            .map_err(|e| e.finish(Location::Undefined))?;
        let parameters = func.parameter_types().to_vec();
        let return_ = func.return_types().to_vec();

        Ok((module, func, parameters, return_))
    }

    // Matches the actual returned type to the expected type, binding any type args to the
    // necessary type as stored in the map. The expected type must be a concrete type (no TyParam).
    // Returns true if a successful match is made.
    fn match_return_type<'a>(
        returned: &Type,
        expected: &'a Type,
        map: &mut BTreeMap<u16, &'a Type>,
    ) -> bool {
        match (returned, expected) {
            // The important case, deduce the type params
            (Type::TyParam(idx), _) => match map.entry(*idx) {
                btree_map::Entry::Vacant(vacant_entry) => {
                    vacant_entry.insert(expected);
                    true
                },
                btree_map::Entry::Occupied(occupied_entry) => *occupied_entry.get() == expected,
            },
            // Recursive types we need to recurse the matching types
            (Type::Reference(ret_inner), Type::Reference(expected_inner))
            | (Type::MutableReference(ret_inner), Type::MutableReference(expected_inner)) => {
                Self::match_return_type(ret_inner, expected_inner, map)
            },
            (Type::Vector(ret_inner), Type::Vector(expected_inner)) => {
                Self::match_return_type(ret_inner, expected_inner, map)
            },
            // Abilities should not contribute to the equality check as they just serve for caching computations.
            // For structs the both need to be the same struct.
            (
                Type::Struct { id: ret_id, .. },
                Type::Struct {
                    id: expected_id, ..
                },
            ) => *ret_id == *expected_id,
            // For struct instantiations we need to additionally match all type arguments
            (
                Type::StructInstantiation {
                    id: ret_id,
                    ty_args: ret_fields,
                    ..
                },
                Type::StructInstantiation {
                    id: expected_id,
                    ty_args: expected_fields,
                    ..
                },
            ) => {
                *ret_id == *expected_id
                    && ret_fields.len() == expected_fields.len()
                    && ret_fields
                        .iter()
                        .zip(expected_fields.iter())
                        .all(|types| Self::match_return_type(types.0, types.1, map))
            },
            // For primitive types we need to assure the types match
            (Type::U8, Type::U8)
            | (Type::U16, Type::U16)
            | (Type::U32, Type::U32)
            | (Type::U64, Type::U64)
            | (Type::U128, Type::U128)
            | (Type::U256, Type::U256)
            | (Type::Bool, Type::Bool)
            | (Type::Address, Type::Address)
            | (Type::Signer, Type::Signer) => true,
            // Otherwise the types do not match and we can't match return type to the expected type.
            // Note we don't use the _ pattern but spell out all cases, so that the compiler will
            // bark when a case is missed upon future updates to the types.
            (Type::U8, _)
            | (Type::U16, _)
            | (Type::U32, _)
            | (Type::U64, _)
            | (Type::U128, _)
            | (Type::U256, _)
            | (Type::Bool, _)
            | (Type::Address, _)
            | (Type::Signer, _)
            | (Type::Struct { .. }, _)
            | (Type::StructInstantiation { .. }, _)
            | (Type::Vector(_), _)
            | (Type::MutableReference(_), _)
            | (Type::Reference(_), _) => false,
        }
    }

    // Loading verifies the module if it was never loaded.
    // Type parameters are inferred from the expected return type. Returns an error if it's not
    // possible to infer the type parameters or return type cannot be matched.
    // The type parameters are verified with capabilities.
    pub(crate) fn load_function_with_type_arg_inference(
        &self,
        module_id: &ModuleId,
        function_name: &IdentStr,
        expected_return_type: &Type,
        session_storage: &dyn SessionStorage,
    ) -> VMResult<(LoadedFunction, LoadedFunctionInstantiation)> {
        let (module, func, parameters, return_vec) =
            self.load_function_without_type_args(module_id, function_name, session_storage)?;

        if return_vec.len() != 1 {
            // For functions that are marked constructor this should not happen.
            return Err(PartialVMError::new(StatusCode::ABORTED).finish(Location::Undefined));
        }
        let return_type = &return_vec[0];

        let mut map = BTreeMap::new();
        if !Self::match_return_type(return_type, expected_return_type, &mut map) {
            // For functions that are marked constructor this should not happen.
            return Err(
                PartialVMError::new(StatusCode::INVALID_MAIN_FUNCTION_SIGNATURE)
                    .finish(Location::Undefined),
            );
        }

        // Construct the type arguments from the match
        let mut type_arguments = vec![];
        let type_param_len = func.type_parameters().len();
        for i in 0..type_param_len {
            if let Option::Some(t) = map.get(&(i as u16)) {
                type_arguments.push((*t).clone());
            } else {
                // Unknown type argument we are not able to infer the type arguments.
                // For functions that are marked constructor this should not happen.
                return Err(
                    PartialVMError::new(StatusCode::INVALID_MAIN_FUNCTION_SIGNATURE)
                        .finish(Location::Undefined),
                );
            }
        }

        // verify type arguments for capability constraints
        self.verify_ty_args(func.type_parameters(), &type_arguments)
            .map_err(|e| e.finish(Location::Module(module_id.clone())))?;

        let loaded = LoadedFunctionInstantiation {
            type_arguments,
            parameters,
            return_: return_vec,
        };
        Ok((
            LoadedFunction {
                module,
                function: func,
            },
            loaded,
        ))
    }

    // Entry point for function execution (`MoveVM::execute_function`).
    // Loading verifies the module if it was never loaded.
    // Type parameters are checked as well after every type is loaded.
    pub(crate) fn load_function(
        &self,
        module_id: &ModuleId,
        function_name: &IdentStr,
        ty_args: &[TypeTag],
        session_storage: &dyn SessionStorage,
    ) -> VMResult<(Arc<Module>, Arc<Function>, LoadedFunctionInstantiation)> {
        let (module, func, parameters, return_) =
            self.load_function_without_type_args(module_id, function_name, session_storage)?;

        let type_arguments = ty_args
            .iter()
            .map(|ty| self.load_type(ty, session_storage))
            .collect::<VMResult<Vec<_>>>()
            .map_err(|mut err| {
                // User provided type arguement failed to load. Set extra sub status to distinguish from internal type loading error.
                if StatusCode::TYPE_RESOLUTION_FAILURE == err.major_status() {
                    err.set_sub_status(move_core_types::vm_status::sub_status::type_resolution_failure::EUSER_TYPE_LOADING_FAILURE);
                }
                err
            })?;

        // verify type arguments
        self.verify_ty_args(func.type_parameters(), &type_arguments)
            .map_err(|e| e.finish(Location::Module(module_id.clone())))?;

        let loaded = LoadedFunctionInstantiation {
            type_arguments,
            parameters,
            return_,
        };
        Ok((module, func, loaded))
    }

    // Entry point for module publishing (`MoveVM::publish_module_bundle`).
    //
    // All modules in the bundle to be published must be loadable. This function performs all
    // verification steps to load these modules without actually loading them into the code cache.
    pub(crate) fn verify_module_bundle_for_publication(
        &self,
        modules: &[CompiledModule],
        session_storage: &dyn SessionStorage,
    ) -> VMResult<()> {
        fail::fail_point!("verifier-failpoint-1", |_| { Ok(()) });

        let mut bundle_unverified: BTreeSet<_> = modules.iter().map(|m| m.self_id()).collect();
        let mut bundle_verified = BTreeMap::new();
        for module in modules {
            let module_id = module.self_id();
            bundle_unverified.remove(&module_id);

            self.verify_module_for_publication(
                module,
                &bundle_verified,
                &bundle_unverified,
                session_storage,
            )?;
            bundle_verified.insert(module_id.clone(), module.clone());
        }
        Ok(())
    }

    // A module to be published must be loadable.
    //
    // This step performs all verification steps to load the module without loading it.
    // The module is not added to the code cache. It is simply published to the data cache.
    // See `verify_script()` for script verification steps.
    //
    // If a module `M` is published together with a bundle of modules (i.e., a vector of modules),
    // - the `bundle_verified` argument tracks the modules that have already been verified in the
    //   bundle. Basically, this represents the modules appears before `M` in the bundle vector.
    // - the `bundle_unverified` argument tracks the modules that have not been verified when `M`
    //   is being verified, i.e., the modules appears after `M` in the bundle vector.
    fn verify_module_for_publication(
        &self,
        module: &CompiledModule,
        bundle_verified: &BTreeMap<ModuleId, CompiledModule>,
        bundle_unverified: &BTreeSet<ModuleId>,
        session_storage: &dyn SessionStorage,
    ) -> VMResult<()> {
        // Performs all verification steps to load the module without loading it, i.e., the new
        // module will NOT show up in `module_cache`. In the module republishing case, it means
        // that the old module is still in the `module_cache`, unless a new Loader is created,
        // which means that a new MoveVM instance needs to be created.
        move_bytecode_verifier::verify_module_with_config(&self.vm_config.verifier, module)?;
        self.check_natives(module)?;

        let mut visited = BTreeSet::new();
        let mut friends_discovered = BTreeSet::new();
        visited.insert(module.self_id());
        friends_discovered.extend(module.immediate_friends());

        // downward exploration of the module's dependency graph. Since we know nothing about this
        // target module, we don't know what the module may specify as its dependencies and hence,
        // we allow the loading of dependencies and the subsequent linking to fail.
        self.load_and_verify_dependencies(
            module,
            bundle_verified,
            session_storage,
            &mut visited,
            &mut friends_discovered,
            /* allow_dependency_loading_failure */ true,
            /* dependencies_depth */ 0,
        )?;

        // upward exploration of the modules's dependency graph. Similar to dependency loading, as
        // we know nothing about this target module, we don't know what the module may specify as
        // its friends and hence, we allow the loading of friends to fail.
        self.load_and_verify_friends(
            friends_discovered,
            bundle_verified,
            bundle_unverified,
            session_storage,
            /* allow_friend_loading_failure */ true,
            /* dependencies_depth */ 0,
        )?;

        // make sure there is no cyclic dependency
        self.verify_module_cyclic_relations(
            session_storage,
            module,
            bundle_verified,
            bundle_unverified,
        )
    }

    fn verify_module_cyclic_relations(
        &self,
        session_storage: &dyn SessionStorage,
        module: &CompiledModule,
        bundle_verified: &BTreeMap<ModuleId, CompiledModule>,
        bundle_unverified: &BTreeSet<ModuleId>,
    ) -> VMResult<()> {
        let locked_module_cache = self.module_cache.read();
        cyclic_dependencies::verify_module(
            module,
            |module_id| {
                match bundle_verified.get(module_id) {
                    Some(m) => Some(m.immediate_dependencies()),
                    None => {
                        let checksum = session_storage.load_checksum(module_id)?;
                        locked_module_cache
                            .get(&checksum)
                            .map(|m| m.compiled_module().immediate_dependencies())
                    },
                }
                .ok_or_else(|| PartialVMError::new(StatusCode::MISSING_DEPENDENCY))
            },
            |module_id| {
                if bundle_unverified.contains(module_id) {
                    // If the module under verification declares a friend which is also in the
                    // bundle (and positioned after this module in the bundle), we defer the cyclic
                    // relation checking when we verify that module.
                    Ok(vec![])
                } else {
                    // Otherwise, we get all the information we need to verify whether this module
                    // creates a cyclic relation.
                    match bundle_verified.get(module_id) {
                        Some(m) => Some(m.immediate_friends()),
                        None => {
                            let checksum = session_storage.load_checksum(module_id)?;
                            locked_module_cache
                                .get(&checksum)
                                .map(|m| m.compiled_module().immediate_friends())
                        },
                    }
                    .ok_or_else(|| PartialVMError::new(StatusCode::MISSING_DEPENDENCY))
                }
            },
        )
    }

    fn check_natives(&self, module: &CompiledModule) -> VMResult<()> {
        fn check_natives_impl(_loader: &Loader, module: &CompiledModule) -> PartialVMResult<()> {
            // TODO: fix check and error code if we leave something around for native structs.
            // For now this generates the only error test cases care about...
            for (idx, struct_def) in module.struct_defs().iter().enumerate() {
                if struct_def.field_information == StructFieldInformation::Native {
                    return Err(verification_error(
                        StatusCode::MISSING_DEPENDENCY,
                        IndexKind::FunctionHandle,
                        idx as TableIndex,
                    ));
                }
            }
            Ok(())
        }
        check_natives_impl(self, module).map_err(|e| e.finish(Location::Module(module.self_id())))
    }

    //
    // Helpers for loading and verification
    //

    pub(crate) fn load_type(
        &self,
        type_tag: &TypeTag,
        session_storage: &dyn SessionStorage,
    ) -> VMResult<Type> {
        Ok(match type_tag {
            TypeTag::Bool => Type::Bool,
            TypeTag::U8 => Type::U8,
            TypeTag::U16 => Type::U16,
            TypeTag::U32 => Type::U32,
            TypeTag::U64 => Type::U64,
            TypeTag::U128 => Type::U128,
            TypeTag::U256 => Type::U256,
            TypeTag::Address => Type::Address,
            TypeTag::Signer => Type::Signer,
            TypeTag::Vector(tt) => {
                Type::Vector(triomphe::Arc::new(self.load_type(tt, session_storage)?))
            },
            TypeTag::Struct(struct_tag) => {
                let module_id = ModuleId::new(struct_tag.address, struct_tag.module.clone());
                let module = self.load_module(&module_id, session_storage)?;
                let struct_type = module
                    .get_struct_type_by_identifier(&struct_tag.name)
                    .map_err(|e| e.finish(Location::Undefined))?;
                if struct_type.type_parameters.is_empty() && struct_tag.type_params.is_empty() {
                    Type::Struct {
                        id: struct_type.id.clone(),
                        ability: AbilityInfo::struct_(struct_type.abilities),
                    }
                } else {
                    let mut type_params = vec![];
                    for ty_param in &struct_tag.type_params {
                        type_params.push(self.load_type(ty_param, session_storage)?);
                    }
                    self.verify_ty_args(struct_type.type_param_constraints(), &type_params)
                        .map_err(|e| e.finish(Location::Undefined))?;
                    Type::StructInstantiation {
                        id: struct_type.id.clone(),
                        ty_args: triomphe::Arc::new(type_params),
                        ability: AbilityInfo::generic_struct(
                            struct_type.abilities,
                            struct_type.phantom_ty_args_mask.clone(),
                        ),
                    }
                }
            },
        })
    }

    // The interface for module loading. Aligned with `load_type` and `load_function`, this function
    // verifies that the module is OK instead of expect it.
    pub(crate) fn load_module(
        &self,
        id: &ModuleId,
        session_storage: &dyn SessionStorage,
    ) -> VMResult<Arc<Module>> {
        self.load_module_internal(id, &BTreeMap::new(), &BTreeSet::new(), session_storage)
    }

    // The interface to cleanup the unused modules from the cache.
    pub fn flush_unused_module_cache(&self) {
        // flush operation holds all loader locks, so good to avoid frequent flushing.
        if self.removed_modules.read().len() < self.vm_config.module_cache_capacity / 10 {
            return;
        }

        let mut type_cache = self.type_cache.write();
        let mut module_cache = self.module_cache.write();
        let mut removed_modules = self.removed_modules.write();
        let module_cache_hits = self.module_cache_hits.read();

        for checksum in removed_modules.iter() {
            if module_cache_hits.peek(checksum) {
                continue;
            }

            type_cache.remove_type_cache(checksum);
            module_cache.remove(checksum);
        }

        removed_modules.clear();
    }

    // The interface to cleanup the unused modules from the cache.
    pub fn flush_unused_script_cache(&self) {
        // flush operation holds all loader locks, so good to avoid frequent flushing.
        if self.removed_scripts.read().len() < self.vm_config.script_cache_capacity / 10 {
            return;
        }

        let mut script_cache = self.script_cache.write();
        let mut removed_scripts = self.removed_scripts.write();
        let script_cache_hits = self.script_cache_hits.read();

        for checksum in removed_scripts.iter() {
            if script_cache_hits.peek(checksum) {
                continue;
            }

            script_cache.remove(checksum);
        }

        removed_scripts.clear();
    }

    // Load the transitive closure of the target module first, and then verify that the modules in
    // the closure do not have cyclic dependencies.
    fn load_module_internal(
        &self,
        id: &ModuleId,
        bundle_verified: &BTreeMap<ModuleId, CompiledModule>,
        bundle_unverified: &BTreeSet<ModuleId>,
        session_storage: &dyn SessionStorage,
    ) -> VMResult<Arc<Module>> {
        // if the module is already in the code cache, load the cached version
        let checksum = session_storage
            .load_checksum(id)
            .map_err(|e| e.finish(Location::Undefined))?;

        if let Some(cached) = self.module_cache.read().get(&checksum) {
            self.module_cache_hits.write().record_hit(&checksum);
            return Ok(cached);
        }

        // create cache hits entry
        if let Some(removed) = self.module_cache_hits.write().create(checksum) {
            self.removed_modules.write().push(removed);
        }

        // otherwise, load the transitive closure of the target module
        let module_ref = self.load_and_verify_module_and_dependencies_and_friends(
            id,
            bundle_verified,
            bundle_unverified,
            session_storage,
            /* allow_module_loading_failure */ true,
            /* dependencies_depth */ 0,
        )?;

        // verify that the transitive closure does not have cycles
        self.verify_module_cyclic_relations(
            session_storage,
            module_ref.compiled_module(),
            bundle_verified,
            bundle_unverified,
        )
        .map_err(expect_no_verification_errors)?;
        Ok(module_ref)
    }

    // Load, deserialize, and check the module with the bytecode verifier, without linking
    fn load_and_verify_module(
        &self,
        id: &ModuleId,
        session_storage: &dyn SessionStorage,
        allow_loading_failure: bool,
    ) -> VMResult<(usize, Arc<CompiledModule>)> {
        let (size, checksum, module) =
            self.load_compiled_module(id, session_storage, allow_loading_failure)?;

        fail::fail_point!("verifier-failpoint-2", |_| { Ok((size, module.clone())) });

        if self.vm_config.paranoid_type_checks && &module.self_id() != id {
            return Err(
                PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
                    .with_message("Module self id mismatch with storage".to_string())
                    .finish(Location::Module(id.clone())),
            );
        }

        if VERIFIED_MODULES.lock().get(&checksum).is_none() {
            move_bytecode_verifier::verify_module_with_config(&self.vm_config.verifier, &module)
                .map_err(expect_no_verification_errors)?;

            VERIFIED_MODULES.lock().put(checksum, ());
        }

        self.check_natives(&module)
            .map_err(expect_no_verification_errors)?;
        Ok((size, module))
    }

    #[allow(clippy::too_many_arguments)]
    // Everything in `load_and_verify_module` and also recursively load and verify all the
    // dependencies of the target module.
    fn load_and_verify_module_and_dependencies(
        &self,
        id: &ModuleId,
        bundle_verified: &BTreeMap<ModuleId, CompiledModule>,
        session_storage: &dyn SessionStorage,
        visited: &mut BTreeSet<ModuleId>,
        friends_discovered: &mut BTreeSet<ModuleId>,
        allow_module_loading_failure: bool,
        dependencies_depth: usize,
    ) -> VMResult<Arc<Module>> {
        // dependency loading does not permit cycles
        if visited.contains(id) {
            return Err(PartialVMError::new(StatusCode::CYCLIC_MODULE_DEPENDENCY)
                .finish(Location::Undefined));
        }

        // module self-check
        let (size, module) =
            self.load_and_verify_module(id, session_storage, allow_module_loading_failure)?;
        visited.insert(id.clone());
        friends_discovered.extend(module.immediate_friends());

        // downward exploration of the module's dependency graph. For a module that is loaded from
        // the session_storage, we should never allow its dependencies to fail to load.
        self.load_and_verify_dependencies(
            &module,
            bundle_verified,
            session_storage,
            visited,
            friends_discovered,
            /* allow_dependency_loading_failure */ false,
            dependencies_depth,
        )?;

        // if linking goes well, insert the module to the code cache
        let mut locked_module_cache = self.module_cache.write();
        let module = Module::new(
            &self.natives,
            size,
            module,
            &locked_module_cache,
            session_storage,
        )
        .map_err(|e| e.finish(Location::Undefined))?;

        let checksum = module.checksum;
        let module_ref = locked_module_cache.insert(checksum, module);

        // create type cache for module
        self.type_cache.write().create_type_cache(checksum);

        drop(locked_module_cache); // explicit unlock

        Ok(module_ref)
    }

    #[allow(clippy::too_many_arguments)]
    // downward exploration of the module's dependency graph
    fn load_and_verify_dependencies(
        &self,
        module: &CompiledModule,
        bundle_verified: &BTreeMap<ModuleId, CompiledModule>,
        session_storage: &dyn SessionStorage,
        visited: &mut BTreeSet<ModuleId>,
        friends_discovered: &mut BTreeSet<ModuleId>,
        allow_dependency_loading_failure: bool,
        dependencies_depth: usize,
    ) -> VMResult<()> {
        if let Some(max_dependency_depth) = self.vm_config.verifier.max_dependency_depth {
            if dependencies_depth > max_dependency_depth {
                return Err(
                    PartialVMError::new(StatusCode::MAX_DEPENDENCY_DEPTH_REACHED)
                        .finish(Location::Undefined),
                );
            }
        }
        // all immediate dependencies of the module being verified should be in one of the locations
        // - the verified portion of the bundle (e.g., verified before this module)
        // - the code cache (i.e., loaded already)
        // - the data store (i.e., not loaded to code cache yet)
        let mut bundle_deps = vec![];
        let mut cached_deps = vec![];
        for module_id in module.immediate_dependencies() {
            if let Some(cached) = bundle_verified.get(&module_id) {
                bundle_deps.push(cached);
            } else {
                let checksum = session_storage.load_checksum(&module_id).map_err(|e| {
                    if allow_dependency_loading_failure {
                        e.finish(Location::Undefined)
                    } else {
                        expect_no_verification_errors(e.finish(Location::Undefined))
                    }
                })?;

                let locked_cache = self.module_cache.read();
                let loaded = match locked_cache.get(&checksum) {
                    None => {
                        drop(locked_cache); // explicit unlock
                        self.load_and_verify_module_and_dependencies(
                            &module_id,
                            bundle_verified,
                            session_storage,
                            visited,
                            friends_discovered,
                            allow_dependency_loading_failure,
                            dependencies_depth + 1,
                        )?
                    },
                    Some(cached) => cached,
                };
                cached_deps.push(loaded);
            }
        }

        // once all dependencies are loaded, do the linking check
        let all_imm_deps = bundle_deps
            .into_iter()
            .chain(cached_deps.iter().map(|m| m.compiled_module()));

        fail::fail_point!("verifier-failpoint-4", |_| { Ok(()) });

        let result = dependencies::verify_module(module, all_imm_deps);

        // if dependencies loading is not allowed to fail, the linking should not fail as well
        if allow_dependency_loading_failure {
            result
        } else {
            result.map_err(expect_no_verification_errors)
        }
    }

    #[allow(clippy::too_many_arguments)]
    // Everything in `load_and_verify_module_and_dependencies` and also recursively load and verify
    // all the friends modules of the newly loaded modules, until the friends frontier covers the
    // whole closure.
    fn load_and_verify_module_and_dependencies_and_friends(
        &self,
        id: &ModuleId,
        bundle_verified: &BTreeMap<ModuleId, CompiledModule>,
        bundle_unverified: &BTreeSet<ModuleId>,
        session_storage: &dyn SessionStorage,
        allow_module_loading_failure: bool,
        dependencies_depth: usize,
    ) -> VMResult<Arc<Module>> {
        // load the closure of the module in terms of dependency relation
        let mut visited = BTreeSet::new();
        let mut friends_discovered = BTreeSet::new();
        let module_ref = self.load_and_verify_module_and_dependencies(
            id,
            bundle_verified,
            session_storage,
            &mut visited,
            &mut friends_discovered,
            allow_module_loading_failure,
            0,
        )?;

        // upward exploration of the module's friendship graph and expand the friendship frontier.
        // For a module that is loaded from the session_storage, we should never allow that its friends
        // fail to load.
        self.load_and_verify_friends(
            friends_discovered,
            bundle_verified,
            bundle_unverified,
            session_storage,
            /* allow_friend_loading_failure */ false,
            dependencies_depth,
        )?;
        Ok(module_ref)
    }

    #[allow(clippy::too_many_arguments)]
    // upward exploration of the module's dependency graph
    fn load_and_verify_friends(
        &self,
        friends_discovered: BTreeSet<ModuleId>,
        bundle_verified: &BTreeMap<ModuleId, CompiledModule>,
        bundle_unverified: &BTreeSet<ModuleId>,
        session_storage: &dyn SessionStorage,
        allow_friend_loading_failure: bool,
        dependencies_depth: usize,
    ) -> VMResult<()> {
        if let Some(max_dependency_depth) = self.vm_config.verifier.max_dependency_depth {
            if dependencies_depth > max_dependency_depth {
                return Err(
                    PartialVMError::new(StatusCode::MAX_DEPENDENCY_DEPTH_REACHED)
                        .finish(Location::Undefined),
                );
            }
        }
        // for each new module discovered in the frontier, load them fully and expand the frontier.
        // apply three filters to the new friend modules discovered
        // - `!locked_cache.has_module(mid)`
        //   If we friend a module that is already in the code cache, then we know that the
        //   transitive closure of that module is loaded into the cache already, skip the loading
        // - `!bundle_verified.contains_key(mid)`
        //   In the case of publishing a bundle, we don't actually put the published module into
        //   code cache. This `bundle_verified` cache is a temporary extension of the code cache
        //   in the bundle publication scenario. If a module is already verified, we don't need to
        //   re-load it again.
        // - `!bundle_unverified.contains(mid)
        //   If the module under verification declares a friend which is also in the bundle (and
        //   positioned after this module in the bundle), we defer the loading of that module when
        //   it is the module's turn in the bundle.
        let locked_module_cache = self.module_cache.read();
        let new_imm_friends: Vec<_> = friends_discovered
            .into_iter()
            .map(|mid| {
                session_storage
                    .load_checksum(&mid)
                    .map(|checksum| (mid.clone(), checksum))
                    .map_err(|e| {
                        if allow_friend_loading_failure {
                            e.finish(Location::Undefined)
                        } else {
                            expect_no_verification_errors(e.finish(Location::Undefined))
                        }
                    })
            })
            .collect::<VMResult<Vec<(ModuleId, Checksum)>>>()?
            .into_iter()
            .filter(|(mid, checksum)| {
                !locked_module_cache.has(checksum)
                    && !bundle_verified.contains_key(mid)
                    && !bundle_unverified.contains(mid)
            })
            .collect();
        drop(locked_module_cache); // explicit unlock

        for (module_id, _) in new_imm_friends {
            self.load_and_verify_module_and_dependencies_and_friends(
                &module_id,
                bundle_verified,
                bundle_unverified,
                session_storage,
                allow_friend_loading_failure,
                dependencies_depth + 1,
            )?;
        }
        Ok(())
    }

    // Return an instantiated type given a generic and an instantiation.
    // Stopgap to avoid a recursion that is either taking too long or using too
    // much memory
    pub(crate) fn subst(&self, ty: &Type, ty_args: &[Type]) -> PartialVMResult<Type> {
        // Before instantiating the type, count the # of nodes of all type arguments plus
        // existing type instantiation.
        // If that number is larger than MAX_TYPE_INSTANTIATION_NODES, refuse to construct this type.
        // This prevents constructing larger and lager types via struct instantiation.
        match ty {
            Type::MutableReference(_) | Type::Reference(_) | Type::Vector(_) => {
                if self.vm_config.type_size_limit
                    && self.count_type_nodes(ty) > MAX_TYPE_INSTANTIATION_NODES
                {
                    return Err(PartialVMError::new(StatusCode::TOO_MANY_TYPE_NODES));
                }
            },
            Type::StructInstantiation {
                ty_args: struct_inst,
                ..
            } => {
                let mut sum_nodes = 1u64;
                for ty in ty_args.iter().chain(struct_inst.iter()) {
                    sum_nodes = sum_nodes.saturating_add(self.count_type_nodes(ty));
                    if sum_nodes > MAX_TYPE_INSTANTIATION_NODES {
                        return Err(PartialVMError::new(StatusCode::TOO_MANY_TYPE_NODES));
                    }
                }
            },
            Type::Address
            | Type::Bool
            | Type::Signer
            | Type::Struct { .. }
            | Type::TyParam(_)
            | Type::U8
            | Type::U16
            | Type::U32
            | Type::U64
            | Type::U128
            | Type::U256 => (),
        };
        ty.subst(ty_args)
    }

    // Verify the kind (constraints) of an instantiation.
    // Both function and script invocation use this function to verify correctness
    // of type arguments provided
    fn verify_ty_args<'a, I>(&self, constraints: I, ty_args: &[Type]) -> PartialVMResult<()>
    where
        I: IntoIterator<Item = &'a AbilitySet>,
        I::IntoIter: ExactSizeIterator,
    {
        let constraints = constraints.into_iter();
        if constraints.len() != ty_args.len() {
            return Err(PartialVMError::new(
                StatusCode::NUMBER_OF_TYPE_ARGUMENTS_MISMATCH,
            ));
        }
        for (ty, expected_k) in ty_args.iter().zip(constraints) {
            if !expected_k.is_subset(ty.abilities()?) {
                return Err(PartialVMError::new(StatusCode::CONSTRAINT_NOT_SATISFIED));
            }
        }
        Ok(())
    }

    //
    // Internal helpers
    //

    pub(crate) fn function_at(
        &self,
        handle: &FunctionHandle,
        session_storage: &dyn SessionStorage,
    ) -> PartialVMResult<Arc<Function>> {
        match handle {
            FunctionHandle::Local(func) => Ok(func.clone()),
            FunctionHandle::Remote { module_id, name } => {
                self.get_module(module_id, session_storage)?
                    .and_then(|module| {
                        let idx = module.function_map.get(name)?;
                        module.function_defs.get(*idx).cloned()
                    })
                    .ok_or_else(|| {
                        PartialVMError::new(StatusCode::TYPE_RESOLUTION_FAILURE).with_message(
                            format!("Failed to resolve function: {:?}::{:?}", module_id, name),
                        )
                    })
            },
        }
    }

    pub(crate) fn get_module(
        &self,
        id: &ModuleId,
        session_storage: &dyn SessionStorage,
    ) -> PartialVMResult<Option<Arc<Module>>> {
        let checksum = session_storage.load_checksum(id)?;
        Ok(self.module_cache.read().get(&checksum))
    }

    pub(crate) fn get_script(&self, checksum: &Checksum) -> Arc<Script> {
        self.script_cache
            .read()
            .get(checksum)
            .expect("Script hash on Function must exist")
    }

    pub(crate) fn get_struct_type_by_identifier(
        &self,
        id: &StructIdentifier,
        session_storage: &dyn SessionStorage,
    ) -> PartialVMResult<Arc<StructType>> {
        let checksum = session_storage.load_checksum(&id.module_id)?;
        let module = self.module_cache.read().get(&checksum).ok_or_else(|| {
            PartialVMError::new(StatusCode::LINKER_ERROR)
                .with_message(format!("Cannot find {:?} in cache", checksum))
        })?;

        module.get_struct_type_by_identifier(&id.name)
    }

    /// Traverses the whole transitive closure of dependencies, starting from the specified
    /// modules and performs gas metering.
    ///
    /// The traversal follows a depth-first order, with the module itself being visited first,
    /// followed by its dependencies, and finally its friends.
    /// DO NOT CHANGE THE ORDER unless you have a good reason, or otherwise this could introduce
    /// a breaking change to the gas semantics.
    ///
    /// This will result in the shallow-loading of the modules -- they will be read from the
    /// storage as bytes and then deserialized, but NOT converted into the runtime representation.
    ///
    /// It should also be noted that this is implemented in a way that avoids the cloning of
    /// `ModuleId`, a.k.a. heap allocations, as much as possible, which is critical for
    /// performance.
    ///
    /// TODO: Revisit the order of traversal. Consider switching to alphabetical order.
    pub(crate) fn check_dependencies_and_charge_gas<'a, I>(
        &self,
        session_storage: &dyn SessionStorage,
        gas_meter: &mut impl GasMeter,
        visited: &mut BTreeMap<(&'a AccountAddress, &'a IdentStr), ()>,
        referenced_modules: &'a Arena<Arc<CompiledModule>>,
        ids: I,
    ) -> VMResult<()>
    where
        I: IntoIterator<Item = (&'a AccountAddress, &'a IdentStr)>,
        I::IntoIter: DoubleEndedIterator,
    {
        // Initialize the work list (stack) and the map of visited modules.
        //
        // TODO: Determine the reserved capacity based on the max number of dependencies allowed.
        let mut stack = Vec::with_capacity(512);

        for (addr, name) in ids.into_iter().rev() {
            // TODO: Allow the check of special addresses to be customized.
            if !addr.is_special() && visited.insert((addr, name), ()).is_none() {
                stack.push((addr, name, true));
            }
        }

        while let Some((addr, name, allow_loading_failure)) = stack.pop() {
            // Load and deserialize the module only if it has not been cached by the loader.
            // Otherwise this will cause a significant regression in performance.
            let module_id = ModuleId::new(*addr, name.to_owned());
            let (size, _, module) =
                self.load_compiled_module(&module_id, session_storage, allow_loading_failure)?;

            // Extend the lifetime of the module to the remainder of the function body
            // by storing it in an arena.
            //
            // This is needed because we need to store references derived from it in the
            // work list.
            let module = referenced_modules.alloc(module);

            gas_meter
                .charge_dependency(false, addr, name, NumBytes::new(size as u64))
                .map_err(|err| {
                    err.finish(Location::Module(ModuleId::new(*addr, name.to_owned())))
                })?;

            // Explore all dependencies and friends that have been visited yet.
            for (addr, name) in module
                .immediate_dependencies_iter()
                .chain(module.immediate_friends_iter())
                .rev()
            {
                // TODO: Allow the check of special addresses to be customized.
                if !addr.is_special() && visited.insert((addr, name), ()).is_none() {
                    stack.push((addr, name, false));
                }
            }
        }

        Ok(())
    }

    /// Similar to `check_dependencies_and_charge_gas`, except that this does not recurse
    /// into transitive dependencies and allows non-existent modules.
    pub(crate) fn check_dependencies_and_charge_gas_non_recursive_optional<'a, I>(
        &self,
        session_storage: &dyn SessionStorage,
        gas_meter: &mut impl GasMeter,
        visited: &mut BTreeMap<(&'a AccountAddress, &'a IdentStr), ()>,
        ids: I,
    ) -> VMResult<()>
    where
        I: IntoIterator<Item = (&'a AccountAddress, &'a IdentStr)>,
    {
        for (addr, name) in ids.into_iter() {
            // TODO: Allow the check of special addresses to be customized.
            if !addr.is_special() && visited.insert((addr, name), ()).is_some() {
                continue;
            }

            // Load and deserialize the module only if it has not been cached by the loader.
            // Otherwise this will cause a significant regression in performance.
            let module_id = ModuleId::new(*addr, name.to_owned());
            let size = match self.load_compiled_module(&module_id, session_storage, true) {
                Ok((size, _, _)) => size,
                Err(err) if err.major_status() == StatusCode::LINKER_ERROR => continue,
                Err(err) => return Err(err),
            };

            gas_meter
                .charge_dependency(false, addr, name, NumBytes::new(size as u64))
                .map_err(|err| {
                    err.finish(Location::Module(ModuleId::new(*addr, name.to_owned())))
                })?;
        }

        Ok(())
    }

    pub(crate) fn check_script_dependencies_and_check_gas(
        &self,
        session_storage: &dyn SessionStorage,
        gas_meter: &mut impl GasMeter,
        traversal_context: &mut TraversalContext,
        script_blob: &[u8],
    ) -> VMResult<()> {
        let script = session_storage
            .deserialize_script(script_blob)
            .map_err(|e| e.finish(Location::Script))?;
        let script = traversal_context.referenced_scripts.alloc(script);

        // TODO(Gas): Should we charge dependency gas for the script itself?
        self.check_dependencies_and_charge_gas(
            session_storage,
            gas_meter,
            &mut traversal_context.visited,
            traversal_context.referenced_modules,
            script.immediate_dependencies_iter(),
        )?;

        Ok(())
    }
}

/// Maximal depth of a value in terms of type depth.
pub(crate) const VALUE_DEPTH_MAX: u64 = 128;

/// Maximal nodes which are allowed when converting to layout. This includes the the types of
/// fields for struct types.
pub(crate) const MAX_TYPE_TO_LAYOUT_NODES: u64 = 256;

/// Maximal nodes which are all allowed when instantiating a generic type. This does not include
/// field types of structs.
pub(crate) const MAX_TYPE_INSTANTIATION_NODES: u64 = 128;

struct PseudoGasContext {
    max_cost: u64,
    cost: u64,
    cost_base: u64,
    cost_per_byte: u64,
}

impl PseudoGasContext {
    fn charge(&mut self, amount: u64) -> PartialVMResult<()> {
        self.cost += amount;
        if self.cost > self.max_cost {
            Err(PartialVMError::new(StatusCode::TYPE_TAG_LIMIT_EXCEEDED)
                .with_message(format!("Max type limit {} exceeded", self.max_cost)))
        } else {
            Ok(())
        }
    }
}

impl Loader {
    fn struct_name_to_type_tag(
        &self,
        id: &StructIdentifier,
        ty_args: &[Type],
        gas_context: &mut PseudoGasContext,
        session_storage: &dyn SessionStorage,
    ) -> PartialVMResult<StructTag> {
        let checksum = session_storage.load_checksum(&id.module_id)?;
        let locked_type_cache = self.type_cache.read();
        let types = locked_type_cache.get_types(&checksum).ok_or_else(|| {
            PartialVMError::new(StatusCode::LINKER_ERROR)
                .with_message(format!("Cannot find {:?} in cache", checksum))
        })?;

        if let Some(struct_map) = types.structs.get(&id.name) {
            if let Some(struct_info) = struct_map.get(ty_args) {
                if let Some((struct_tag, gas)) = &struct_info.struct_tag {
                    gas_context.charge(*gas)?;
                    return Ok(struct_tag.clone());
                }
            }
        }

        // explicitly drop
        drop(locked_type_cache);

        let cur_cost = gas_context.cost;

        let ty_arg_tags = ty_args
            .iter()
            .map(|ty| self.type_to_type_tag_impl(ty, gas_context, session_storage))
            .collect::<PartialVMResult<Vec<_>>>()?;
        let struct_tag = StructTag {
            address: *id.module_id.address(),
            module: id.module_id.name().to_owned(),
            name: id.name.clone(),
            type_params: ty_arg_tags,
        };

        let size =
            (struct_tag.address.len() + struct_tag.module.len() + struct_tag.name.len()) as u64;
        gas_context.charge(size * gas_context.cost_per_byte)?;

        self.type_cache
            .write()
            .insert_type(&checksum, id, ty_args)?
            .struct_tag = Some((struct_tag.clone(), gas_context.cost - cur_cost));

        Ok(struct_tag)
    }

    fn type_to_type_tag_impl(
        &self,
        ty: &Type,
        gas_context: &mut PseudoGasContext,
        session_storage: &dyn SessionStorage,
    ) -> PartialVMResult<TypeTag> {
        gas_context.charge(gas_context.cost_base)?;
        Ok(match ty {
            Type::Bool => TypeTag::Bool,
            Type::U8 => TypeTag::U8,
            Type::U16 => TypeTag::U16,
            Type::U32 => TypeTag::U32,
            Type::U64 => TypeTag::U64,
            Type::U128 => TypeTag::U128,
            Type::U256 => TypeTag::U256,
            Type::Address => TypeTag::Address,
            Type::Signer => TypeTag::Signer,
            Type::Vector(ty) => {
                TypeTag::Vector(Box::new(self.type_to_type_tag(ty, session_storage)?))
            },
            Type::Struct { id, .. } => TypeTag::Struct(Box::new(self.struct_name_to_type_tag(
                id,
                &[],
                gas_context,
                session_storage,
            )?)),
            Type::StructInstantiation { id, ty_args, .. } => TypeTag::Struct(Box::new(
                self.struct_name_to_type_tag(id, ty_args, gas_context, session_storage)?,
            )),
            Type::Reference(_) | Type::MutableReference(_) | Type::TyParam(_) => {
                return Err(
                    PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
                        .with_message(format!("no type tag for {:?}", ty)),
                );
            },
        })
    }

    pub(crate) fn count_type_nodes(&self, ty: &Type) -> u64 {
        let mut todo = vec![ty];
        let mut result = 0;
        while let Some(ty) = todo.pop() {
            match ty {
                Type::Vector(ty) => {
                    result += 1;
                    todo.push(ty);
                },
                Type::Reference(ty) | Type::MutableReference(ty) => {
                    result += 1;
                    todo.push(ty);
                },
                Type::StructInstantiation { ty_args, .. } => {
                    result += 1;
                    todo.extend(ty_args.iter())
                },
                _ => {
                    result += 1;
                },
            }
        }
        result
    }

    fn struct_name_to_type_layout(
        &self,
        id: &StructIdentifier,
        ty_args: &[Type],
        count: &mut u64,
        depth: u64,
        session_storage: &dyn SessionStorage,
    ) -> PartialVMResult<(MoveTypeLayout, bool)> {
        let checksum = session_storage.load_checksum(&id.module_id)?;
        let locked_type_cache = self.type_cache.read();
        let types = locked_type_cache.get_types(&checksum).ok_or_else(|| {
            PartialVMError::new(StatusCode::LINKER_ERROR)
                .with_message(format!("Cannot find {:?} in cache", checksum))
        })?;

        if let Some(struct_map) = types.structs.get(&id.name) {
            if let Some(struct_info) = struct_map.get(ty_args) {
                if let Some(struct_layout_info) = &struct_info.struct_layout_info {
                    *count += struct_layout_info.node_count;
                    return Ok((
                        struct_layout_info.struct_layout.clone(),
                        struct_layout_info.has_identifier_mappings,
                    ));
                }
            }
        }

        // explicitly drop
        drop(locked_type_cache);

        let count_before = *count;
        let struct_type = self.get_struct_type_by_identifier(id, session_storage)?;

        // Some types can have fields which are lifted at serialization or deserialization
        // times. Right now these are Aggregator and AggregatorSnapshot.
        let maybe_mapping = self.get_identifier_mapping_kind(id);

        let field_tys = struct_type
            .fields
            .iter()
            .map(|ty| self.subst(ty, ty_args))
            .collect::<PartialVMResult<Vec<_>>>()?;
        let (mut field_layouts, field_has_identifier_mappings): (Vec<MoveTypeLayout>, Vec<bool>) =
            field_tys
                .iter()
                .map(|ty| self.type_to_type_layout_impl(ty, count, depth + 1, session_storage))
                .collect::<PartialVMResult<Vec<_>>>()?
                .into_iter()
                .unzip();

        let has_identifier_mappings =
            maybe_mapping.is_some() || field_has_identifier_mappings.into_iter().any(|b| b);

        let field_node_count = *count - count_before;
        let struct_layout = if Some(IdentifierMappingKind::DerivedString) == maybe_mapping {
            // For DerivedString, the whole object should be lifted.
            MoveTypeLayout::Native(
                IdentifierMappingKind::DerivedString,
                Box::new(MoveTypeLayout::Struct(MoveStructLayout::new(field_layouts))),
            )
        } else {
            // For aggregators / snapshots, the first field should be lifted.
            if let Some(kind) = &maybe_mapping {
                if let Some(l) = field_layouts.first_mut() {
                    *l = MoveTypeLayout::Native(kind.clone(), Box::new(l.clone()));
                }
            }
            MoveTypeLayout::Struct(MoveStructLayout::new(field_layouts))
        };

        let mut locked_type_cache: parking_lot::lock_api::RwLockWriteGuard<
            '_,
            parking_lot::RawRwLock,
            TypeCache,
        > = self.type_cache.write();
        let info = locked_type_cache.insert_type(&checksum, id, ty_args)?;
        info.struct_layout_info = Some(StructLayoutInfoCacheItem {
            struct_layout: struct_layout.clone(),
            node_count: field_node_count,
            has_identifier_mappings,
        });

        Ok((struct_layout, has_identifier_mappings))
    }

    // TODO[agg_v2](cleanup):
    // Currently aggregator checks are hardcoded and leaking to loader.
    // It seems that this is only because there is no support for native
    // types.
    // Let's think how we can do this nicer.
    fn get_identifier_mapping_kind(&self, id: &StructIdentifier) -> Option<IdentifierMappingKind> {
        if !self.vm_config.aggregator_v2_type_tagging {
            return None;
        }

        let ident_str_to_kind = |ident_str: &IdentStr| -> Option<IdentifierMappingKind> {
            if ident_str.eq(ident_str!("Aggregator")) {
                Some(IdentifierMappingKind::Aggregator)
            } else if ident_str.eq(ident_str!("AggregatorSnapshot")) {
                Some(IdentifierMappingKind::Snapshot)
            } else if ident_str.eq(ident_str!("DerivedStringSnapshot")) {
                Some(IdentifierMappingKind::DerivedString)
            } else {
                None
            }
        };

        (id.module_id.address().eq(&AccountAddress::ONE)
            && id.module_id.name().eq(ident_str!("aggregator_v2")))
        .then_some(ident_str_to_kind(id.name.as_ident_str()))
        .flatten()
    }

    fn type_to_type_layout_impl(
        &self,
        ty: &Type,
        count: &mut u64,
        depth: u64,
        session_storage: &dyn SessionStorage,
    ) -> PartialVMResult<(MoveTypeLayout, bool)> {
        if *count > MAX_TYPE_TO_LAYOUT_NODES {
            return Err(PartialVMError::new(StatusCode::TOO_MANY_TYPE_NODES));
        }
        if depth > VALUE_DEPTH_MAX {
            return Err(PartialVMError::new(StatusCode::VM_MAX_VALUE_DEPTH_REACHED));
        }
        Ok(match ty {
            Type::Bool => {
                *count += 1;
                (MoveTypeLayout::Bool, false)
            },
            Type::U8 => {
                *count += 1;
                (MoveTypeLayout::U8, false)
            },
            Type::U16 => {
                *count += 1;
                (MoveTypeLayout::U16, false)
            },
            Type::U32 => {
                *count += 1;
                (MoveTypeLayout::U32, false)
            },
            Type::U64 => {
                *count += 1;
                (MoveTypeLayout::U64, false)
            },
            Type::U128 => {
                *count += 1;
                (MoveTypeLayout::U128, false)
            },
            Type::U256 => {
                *count += 1;
                (MoveTypeLayout::U256, false)
            },
            Type::Address => {
                *count += 1;
                (MoveTypeLayout::Address, false)
            },
            Type::Signer => {
                *count += 1;
                (MoveTypeLayout::Signer, false)
            },
            Type::Vector(ty) => {
                *count += 1;
                let (layout, has_identifier_mappings) =
                    self.type_to_type_layout_impl(ty, count, depth + 1, session_storage)?;
                (
                    MoveTypeLayout::Vector(Box::new(layout)),
                    has_identifier_mappings,
                )
            },
            Type::Struct { id, .. } => {
                *count += 1;
                // Note depth is increased inside struct_name_to_type_layout instead.
                let (layout, has_identifier_mappings) =
                    self.struct_name_to_type_layout(id, &[], count, depth, session_storage)?;
                (layout, has_identifier_mappings)
            },
            Type::StructInstantiation { id, ty_args, .. } => {
                *count += 1;
                // Note depth is incread inside struct_name_to_type_layout instead.
                let (layout, has_identifier_mappings) =
                    self.struct_name_to_type_layout(id, ty_args, count, depth, session_storage)?;
                (layout, has_identifier_mappings)
            },
            Type::Reference(_) | Type::MutableReference(_) | Type::TyParam(_) => {
                return Err(
                    PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
                        .with_message(format!("no type layout for {:?}", ty)),
                );
            },
        })
    }

    fn struct_name_to_fully_annotated_layout(
        &self,
        id: &StructIdentifier,
        ty_args: &[Type],
        count: &mut u64,
        depth: u64,
        session_storage: &dyn SessionStorage,
    ) -> PartialVMResult<MoveTypeLayout> {
        let checksum = session_storage.load_checksum(&id.module_id)?;
        let locked_type_cache = self.type_cache.read();
        let types = locked_type_cache.get_types(&checksum).ok_or_else(|| {
            PartialVMError::new(StatusCode::LINKER_ERROR)
                .with_message(format!("Cannot find {:?} in cache", checksum))
        })?;

        if let Some(struct_map) = types.structs.get(&id.name) {
            if let Some(struct_info) = struct_map.get(ty_args) {
                if let Some(annotated_node_count) = &struct_info.annotated_node_count {
                    *count += *annotated_node_count
                }
                if let Some(layout) = &struct_info.annotated_struct_layout {
                    return Ok(layout.clone());
                }
            }
        }

        // explicitly drop
        drop(locked_type_cache);

        let struct_type = self.get_struct_type_by_identifier(id, session_storage)?;
        if struct_type.fields.len() != struct_type.field_names.len() {
            return Err(
                PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR).with_message(
                    "Field types did not match the length of field names in loaded struct"
                        .to_owned(),
                ),
            );
        }

        let count_before = *count;
        let mut gas_context = PseudoGasContext {
            cost: 0,
            max_cost: self.vm_config.type_max_cost,
            cost_base: self.vm_config.type_base_cost,
            cost_per_byte: self.vm_config.type_byte_cost,
        };

        let struct_tag =
            self.struct_name_to_type_tag(id, ty_args, &mut gas_context, session_storage)?;
        let field_layouts = struct_type
            .field_names
            .iter()
            .zip(&struct_type.fields)
            .map(|(n, ty)| {
                let ty = self.subst(ty, ty_args)?;
                let l = self.type_to_fully_annotated_layout_impl(
                    &ty,
                    count,
                    depth + 1,
                    session_storage,
                )?;
                Ok(MoveFieldLayout::new(n.clone(), l))
            })
            .collect::<PartialVMResult<Vec<_>>>()?;
        let struct_layout =
            MoveTypeLayout::Struct(MoveStructLayout::with_types(struct_tag, field_layouts));
        let field_node_count = *count - count_before;

        let mut locked_type_cache = self.type_cache.write();
        let info = locked_type_cache.insert_type(&checksum, id, ty_args)?;
        info.annotated_struct_layout = Some(struct_layout.clone());
        info.annotated_node_count = Some(field_node_count);

        Ok(struct_layout)
    }

    fn type_to_fully_annotated_layout_impl(
        &self,
        ty: &Type,
        count: &mut u64,
        depth: u64,
        session_storage: &dyn SessionStorage,
    ) -> PartialVMResult<MoveTypeLayout> {
        if *count > MAX_TYPE_TO_LAYOUT_NODES {
            return Err(PartialVMError::new(StatusCode::TOO_MANY_TYPE_NODES));
        }
        if depth > VALUE_DEPTH_MAX {
            return Err(PartialVMError::new(StatusCode::VM_MAX_VALUE_DEPTH_REACHED));
        }
        Ok(match ty {
            Type::Bool => MoveTypeLayout::Bool,
            Type::U8 => MoveTypeLayout::U8,
            Type::U16 => MoveTypeLayout::U16,
            Type::U32 => MoveTypeLayout::U32,
            Type::U64 => MoveTypeLayout::U64,
            Type::U128 => MoveTypeLayout::U128,
            Type::U256 => MoveTypeLayout::U256,
            Type::Address => MoveTypeLayout::Address,
            Type::Signer => MoveTypeLayout::Signer,
            Type::Vector(ty) => MoveTypeLayout::Vector(Box::new(
                self.type_to_fully_annotated_layout_impl(ty, count, depth + 1, session_storage)?,
            )),
            Type::Struct { id, .. } => {
                self.struct_name_to_fully_annotated_layout(id, &[], count, depth, session_storage)?
            },
            Type::StructInstantiation { id, ty_args, .. } => self
                .struct_name_to_fully_annotated_layout(
                    id,
                    ty_args,
                    count,
                    depth,
                    session_storage,
                )?,
            Type::Reference(_) | Type::MutableReference(_) | Type::TyParam(_) => {
                return Err(
                    PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
                        .with_message(format!("no type layout for {:?}", ty)),
                );
            },
        })
    }

    pub(crate) fn calculate_depth_of_struct(
        &self,
        id: &StructIdentifier,
        session_storage: &dyn SessionStorage,
    ) -> PartialVMResult<DepthFormula> {
        let checksum = session_storage.load_checksum(&id.module_id)?;
        let locked_type_cache = self.type_cache.read();
        let types = locked_type_cache.get_types(&checksum).ok_or_else(|| {
            PartialVMError::new(StatusCode::LINKER_ERROR)
                .with_message(format!("Cannot find {:?} in cache", checksum))
        })?;
        if let Some(depth_formula) = types.depth_formula.get(&id.name) {
            return Ok(depth_formula.clone());
        }

        // explicitly drop
        drop(locked_type_cache);

        let struct_type = self.get_struct_type_by_identifier(id, session_storage)?;

        let formulas = struct_type
            .fields
            .iter()
            .map(|field_type| self.calculate_depth_of_type(field_type, session_storage))
            .collect::<PartialVMResult<Vec<_>>>()?;
        let formula = DepthFormula::normalize(formulas);
        let prev = self
            .type_cache
            .write()
            .insert_depth_formula(&checksum, id, formula.clone())?;

        if prev.is_some() {
            return Err(
                PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
                    .with_message("Recursive type?".to_owned()),
            );
        }
        Ok(formula)
    }

    fn calculate_depth_of_type(
        &self,
        ty: &Type,
        session_storage: &dyn SessionStorage,
    ) -> PartialVMResult<DepthFormula> {
        Ok(match ty {
            Type::Bool
            | Type::U8
            | Type::U64
            | Type::U128
            | Type::Address
            | Type::Signer
            | Type::U16
            | Type::U32
            | Type::U256 => DepthFormula::constant(1),
            Type::Vector(ty) => {
                let mut inner = self.calculate_depth_of_type(ty, session_storage)?;
                inner.scale(1);
                inner
            },
            Type::Reference(ty) | Type::MutableReference(ty) => {
                let mut inner = self.calculate_depth_of_type(ty, session_storage)?;
                inner.scale(1);
                inner
            },
            Type::TyParam(ty_idx) => DepthFormula::type_parameter(*ty_idx),
            Type::Struct { id, .. } => {
                let mut struct_formula = self.calculate_depth_of_struct(id, session_storage)?;
                debug_assert!(struct_formula.terms.is_empty());
                struct_formula.scale(1);
                struct_formula
            },
            Type::StructInstantiation { id, ty_args, .. } => {
                let ty_arg_map = ty_args
                    .iter()
                    .enumerate()
                    .map(|(idx, ty)| {
                        let var = idx as TypeParameterIndex;
                        Ok((var, self.calculate_depth_of_type(ty, session_storage)?))
                    })
                    .collect::<PartialVMResult<BTreeMap<_, _>>>()?;
                let struct_formula = self.calculate_depth_of_struct(id, session_storage)?;
                let mut subst_struct_formula = struct_formula.subst(ty_arg_map)?;
                subst_struct_formula.scale(1);
                subst_struct_formula
            },
        })
    }

    pub(crate) fn type_to_type_tag(
        &self,
        ty: &Type,
        session_storage: &dyn SessionStorage,
    ) -> PartialVMResult<TypeTag> {
        let mut gas_context = PseudoGasContext {
            cost: 0,
            max_cost: self.vm_config.type_max_cost,
            cost_base: self.vm_config.type_base_cost,
            cost_per_byte: self.vm_config.type_byte_cost,
        };
        self.type_to_type_tag_impl(ty, &mut gas_context, session_storage)
    }

    pub(crate) fn type_to_type_layout_with_identifier_mappings(
        &self,
        ty: &Type,
        session_storage: &dyn SessionStorage,
    ) -> PartialVMResult<(MoveTypeLayout, bool)> {
        let mut count = 0;
        self.type_to_type_layout_impl(ty, &mut count, 1, session_storage)
    }

    pub(crate) fn type_to_type_layout(
        &self,
        ty: &Type,
        session_storage: &dyn SessionStorage,
    ) -> PartialVMResult<MoveTypeLayout> {
        let mut count = 0;
        let (layout, _has_identifier_mappings) =
            self.type_to_type_layout_impl(ty, &mut count, 1, session_storage)?;
        Ok(layout)
    }

    pub(crate) fn type_to_fully_annotated_layout(
        &self,
        ty: &Type,
        session_storage: &dyn SessionStorage,
    ) -> PartialVMResult<MoveTypeLayout> {
        let mut count = 0;
        self.type_to_fully_annotated_layout_impl(ty, &mut count, 1, session_storage)
    }
}

// Public APIs for external uses.
impl Loader {
    pub fn get_type_layout(
        &self,
        type_tag: &TypeTag,
        session_storage: &dyn SessionStorage,
    ) -> VMResult<MoveTypeLayout> {
        let ty = self.load_type(type_tag, session_storage)?;
        self.type_to_type_layout(&ty, session_storage)
            .map_err(|e| e.finish(Location::Undefined))
    }

    pub fn get_fully_annotated_type_layout(
        &self,
        type_tag: &TypeTag,
        session_storage: &dyn SessionStorage,
    ) -> VMResult<MoveTypeLayout> {
        let ty = self.load_type(type_tag, session_storage)?;
        self.type_to_fully_annotated_layout(&ty, session_storage)
            .map_err(|e| e.finish(Location::Undefined))
    }
}
