use std::{collections::BTreeMap, sync::Arc};

use move_binary_format::{
    access::ScriptAccess,
    binary_views::BinaryIndexedView,
    errors::{PartialVMError, PartialVMResult},
    file_format::{Bytecode, CompiledScript, FunctionDefinitionIndex, Signature, SignatureIndex},
};
use move_core_types::{identifier::Identifier, language_storage::ModuleId, vm_status::StatusCode};
use move_vm_types::loaded_data::{
    runtime_access_specifier::AccessSpecifier,
    runtime_types::{Checksum, StructIdentifier, Type},
};

use super::{
    cache::ModuleCache,
    function::{Function, FunctionHandle, FunctionInstantiation, Scope},
    type_loader::intern_type,
    SessionStorage,
};

// A Script is very similar to a `CompiledScript` but data is "transformed" to a representation
// more appropriate to execution.
// When code executes, indexes in instructions are resolved against runtime structures
// (rather then "compiled") to make available data needed for execution
// #[derive(Debug)]
#[derive(Clone)]
pub(crate) struct Script {
    // primitive pools
    pub(crate) script: CompiledScript,

    // functions as indexes into the Loader function list
    function_refs: Vec<FunctionHandle>,
    // materialized instantiations, whether partial or not
    function_instantiations: Vec<FunctionInstantiation>,

    // entry point
    main: Arc<Function>,

    // parameters of main
    pub(crate) parameter_tys: Vec<Type>,

    // return values
    pub(crate) return_tys: Vec<Type>,

    // a map of single-token signature indices to type
    single_signature_token_map: BTreeMap<SignatureIndex, Type>,
}

impl Script {
    pub(crate) fn new(
        script: CompiledScript,
        script_hash: &Checksum,
        module_cache: &ModuleCache,
        session_storage: &dyn SessionStorage,
    ) -> PartialVMResult<Self> {
        let mut struct_names = vec![];
        for struct_handle in script.struct_handles() {
            let struct_name = script.identifier_at(struct_handle.name);
            let module_handle = script.module_handle_at(struct_handle.module);
            let module_id = script.module_id_for_handle(module_handle);

            let id = StructIdentifier {
                module_id: module_id.clone(),
                name: struct_name.to_owned(),
            };

            let checksum = session_storage.load_checksum(&module_id)?;
            module_cache
                .get_struct_type_by_identifier(&checksum, &id)?
                .check_compatibility(struct_handle)?;

            struct_names.push(id);
        }

        let mut function_refs = vec![];
        for func_handle in script.function_handles().iter() {
            let func_name = script.identifier_at(func_handle.name);
            let module_handle = script.module_handle_at(func_handle.module);
            let module_id = ModuleId::new(
                *script.address_identifier_at(module_handle.address),
                script.identifier_at(module_handle.name).to_owned(),
            );
            function_refs.push(FunctionHandle::Remote {
                module_id,
                name: func_name.to_owned(),
            });
        }

        let mut function_instantiations = vec![];
        for func_inst in script.function_instantiations() {
            let handle = function_refs[func_inst.handle.0 as usize].clone();
            let mut instantiation = vec![];
            for ty in &script.signature_at(func_inst.type_parameters).0 {
                instantiation.push(intern_type(
                    BinaryIndexedView::Script(&script),
                    ty,
                    &struct_names,
                )?);
            }
            function_instantiations.push(FunctionInstantiation {
                handle,
                instantiation,
            });
        }

        let scope = Scope::Script(*script_hash);

        let code: Vec<Bytecode> = script.code.code.clone();
        let parameters = script.signature_at(script.parameters).clone();

        let parameter_tys = parameters
            .0
            .iter()
            .map(|tok| intern_type(BinaryIndexedView::Script(&script), tok, &struct_names))
            .collect::<PartialVMResult<Vec<_>>>()?;
        let locals = Signature(
            parameters
                .0
                .iter()
                .chain(script.signature_at(script.code.locals).0.iter())
                .cloned()
                .collect(),
        );
        let local_tys = locals
            .0
            .iter()
            .map(|tok| intern_type(BinaryIndexedView::Script(&script), tok, &struct_names))
            .collect::<PartialVMResult<Vec<_>>>()?;
        let return_ = Signature(vec![]);
        let return_tys = return_
            .0
            .iter()
            .map(|tok| intern_type(BinaryIndexedView::Script(&script), tok, &struct_names))
            .collect::<PartialVMResult<Vec<_>>>()?;
        let type_parameters = script.type_parameters.clone();
        // TODO: main does not have a name. Revisit.
        let name = Identifier::new("main").unwrap();
        let (native, def_is_native) = (None, false); // Script entries cannot be native
        let main: Arc<Function> = Arc::new(Function {
            file_format_version: script.version(),
            index: FunctionDefinitionIndex(0),
            code,
            type_parameters,
            native,
            def_is_native,
            def_is_friend_or_private: false,
            scope,
            name,
            return_types: return_tys.clone(),
            local_types: local_tys,
            parameter_types: parameter_tys.clone(),
            access_specifier: AccessSpecifier::Any,
        });

        let mut single_signature_token_map = BTreeMap::new();
        for bc in &script.code.code {
            match bc {
                Bytecode::VecPack(si, _)
                | Bytecode::VecLen(si)
                | Bytecode::VecImmBorrow(si)
                | Bytecode::VecMutBorrow(si)
                | Bytecode::VecPushBack(si)
                | Bytecode::VecPopBack(si)
                | Bytecode::VecUnpack(si, _)
                | Bytecode::VecSwap(si) => {
                    if !single_signature_token_map.contains_key(si) {
                        let ty = match script.signature_at(*si).0.first() {
                            None => {
                                return Err(PartialVMError::new(
                                    StatusCode::VERIFIER_INVARIANT_VIOLATION,
                                )
                                .with_message(
                                    "the type argument for vector-related bytecode \
                                                expects one and only one signature token"
                                        .to_owned(),
                                ));
                            },
                            Some(sig_token) => sig_token,
                        };
                        single_signature_token_map.insert(
                            *si,
                            intern_type(BinaryIndexedView::Script(&script), ty, &struct_names)?,
                        );
                    }
                },
                _ => {},
            }
        }

        Ok(Self {
            script,
            function_refs,
            function_instantiations,
            main,
            parameter_tys,
            return_tys,
            single_signature_token_map,
        })
    }

    pub(crate) fn entry_point(&self) -> Arc<Function> {
        self.main.clone()
    }

    pub(crate) fn function_at(&self, idx: u16) -> &FunctionHandle {
        &self.function_refs[idx as usize]
    }

    pub(crate) fn function_instantiation_at(&self, idx: u16) -> &FunctionInstantiation {
        &self.function_instantiations[idx as usize]
    }

    pub(crate) fn single_type_at(&self, idx: SignatureIndex) -> &Type {
        self.single_signature_token_map.get(&idx).unwrap()
    }
}
