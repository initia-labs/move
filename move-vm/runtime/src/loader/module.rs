use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

use move_binary_format::{
    access::ModuleAccess,
    binary_views::BinaryIndexedView,
    errors::{PartialVMError, PartialVMResult},
    file_format::{
        Bytecode, FieldHandleIndex, FieldInstantiationIndex, FunctionDefinitionIndex,
        SignatureIndex, StructDefinition, StructDefinitionIndex, StructFieldInformation,
        TableIndex,
    },
    CompiledModule,
};
use move_core_types::{
    identifier::{IdentStr, Identifier},
    language_storage::ModuleId,
    vm_status::StatusCode,
};
use move_vm_types::loaded_data::runtime_types::{StructIdentifier, StructType, Type};

use crate::native_functions::NativeFunctions;

use super::{
    cache::ModuleCache,
    function::{Function, FunctionHandle, FunctionInstantiation},
    store::ModuleStorage,
    type_loader::intern_type,
};

// A Module is very similar to a binary Module but data is "transformed" to a representation
// more appropriate to execution.
// When code executes indexes in instructions are resolved against those runtime structure
// so that any data needed for execution is immediately available
#[derive(Clone, Debug)]
pub(crate) struct Module {
    pub(crate) id: ModuleId,
    pub(crate) checksum: [u8; 32],

    // primitive pools
    pub(crate) module: Arc<CompiledModule>,

    //
    // types as indexes into the Loader type list
    //
    pub(crate) structs: Vec<StructDef>,
    // materialized instantiations, whether partial or not
    pub(crate) struct_instantiations: Vec<StructInstantiation>,

    // functions as indexes into the Loader function list
    // That is effectively an indirection over the ref table:
    // the instruction carries an index into this table which contains the index into the
    // glabal table of functions. No instantiation of generic functions is saved into
    // the global table.
    pub(crate) function_refs: Vec<FunctionHandle>,
    pub(crate) function_defs: Vec<Arc<Function>>,
    // materialized instantiations, whether partial or not
    pub(crate) function_instantiations: Vec<FunctionInstantiation>,

    // fields as a pair of index, first to the type, second to the field position in that type
    pub(crate) field_handles: Vec<FieldHandle>,
    // materialized instantiations, whether partial or not
    pub(crate) field_instantiations: Vec<FieldInstantiation>,

    // function name to index into the Loader function list.
    // This allows a direct access from function name to `Function`
    pub(crate) function_map: HashMap<Identifier, usize>,
    // struct name to index into the module's type list
    // This allows a direct access from struct name to `Struct`
    pub(crate) struct_map: HashMap<Identifier, usize>,

    // a map of single-token signature indices to type.
    // Single-token signatures are usually indexed by the `SignatureIndex` in bytecode. For example,
    // `VecMutBorrow(SignatureIndex)`, the `SignatureIndex` maps to a single `SignatureToken`, and
    // hence, a single type.
    pub(crate) single_signature_token_map: BTreeMap<SignatureIndex, Type>,
}

#[derive(Clone, Debug)]
pub(crate) struct StructDef {
    // struct field count
    pub(crate) field_count: u16,
    pub(crate) definition_struct_type: Arc<StructType>,
}

#[derive(Clone, Debug)]
pub(crate) struct StructInstantiation {
    // struct field count
    pub(crate) field_count: u16,
    pub(crate) definition_struct_type: Arc<StructType>,
    pub(crate) instantiation: Vec<Type>,
}

// A field handle. The offset is the only used information when operating on a field
#[derive(Clone, Debug)]
pub(crate) struct FieldHandle {
    pub(crate) offset: usize,
    pub(crate) definition_struct_type: Arc<StructType>,
}

// A field instantiation. The offset is the only used information when operating on a field
#[derive(Clone, Debug)]
pub(crate) struct FieldInstantiation {
    pub(crate) offset: usize,
    pub(crate) definition_struct_type: Arc<StructType>,
    pub(crate) instantiation: Vec<Type>,
}

impl Module {
    pub(crate) fn new(
        natives: &NativeFunctions,
        module: CompiledModule,
        module_cache: &ModuleCache,
        module_storage: &dyn ModuleStorage,
    ) -> PartialVMResult<Self> {
        let id = module.self_id();
        let checksum = module_storage.load_checksum(&id)?;

        let mut structs = vec![];
        let mut struct_instantiations = vec![];
        let mut function_refs = vec![];
        let mut function_defs = vec![];
        let mut function_instantiations = vec![];
        let mut field_handles = vec![];
        let mut field_instantiations: Vec<FieldInstantiation> = vec![];
        let mut function_map = HashMap::new();
        let mut struct_map = HashMap::new();
        let mut single_signature_token_map = BTreeMap::new();
        let mut signature_table = vec![];

        let mut create = || {
            let mut struct_ids = vec![];
            // validate the correctness of struct handle references.
            for struct_handle in module.struct_handles() {
                let struct_name = module.identifier_at(struct_handle.name);
                let module_handle = module.module_handle_at(struct_handle.module);
                let module_id = module.module_id_for_handle(module_handle);

                let mut id = StructIdentifier {
                    module_id: module_id.clone(),
                    checksum,
                    name: struct_name.to_owned(),
                };

                if module_handle != module.self_handle() {
                    id.checksum = module_storage.load_checksum(&module_id)?;
                    module_cache
                        .get_struct_type_by_identifier(&id)?
                        .check_compatibility(struct_handle)?;
                }

                struct_ids.push(id);
            }

            // Build signature table
            for signatures in module.signatures() {
                signature_table.push(
                    signatures
                        .0
                        .iter()
                        .map(|sig| {
                            intern_type(BinaryIndexedView::Module(&module), sig, &struct_ids)
                        })
                        .collect::<PartialVMResult<Vec<_>>>()?,
                )
            }

            for (idx, struct_def) in module.struct_defs().iter().enumerate() {
                let definition_struct_type =
                    Arc::new(make_struct_type(&module, struct_def, &struct_ids)?);
                structs.push(StructDef {
                    field_count: definition_struct_type.fields.len() as u16,
                    definition_struct_type,
                });
                let name =
                    module.identifier_at(module.struct_handle_at(struct_def.struct_handle).name);
                struct_map.insert(name.to_owned(), idx);
            }

            for struct_inst in module.struct_instantiations() {
                let def = struct_inst.def.0 as usize;
                let struct_def = &structs[def];
                let field_count = struct_def.field_count;
                struct_instantiations.push(StructInstantiation {
                    field_count,
                    instantiation: signature_table[struct_inst.type_parameters.0 as usize].clone(),
                    definition_struct_type: struct_def.definition_struct_type.clone(),
                });
            }

            for (idx, func) in module.function_defs().iter().enumerate() {
                let findex = FunctionDefinitionIndex(idx as TableIndex);
                let function = match Function::new(
                    natives,
                    findex,
                    &module,
                    module_storage,
                    signature_table.as_slice(),
                ) {
                    Ok(f) => f,
                    Err(e) => return Err(e),
                };

                function_map.insert(function.name.to_owned(), idx);
                function_defs.push(Arc::new(function));

                if let Some(code_unit) = &func.code {
                    for bc in &code_unit.code {
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
                                    let ty = match module.signature_at(*si).0.get(0) {
                                        None => {
                                            return Err(PartialVMError::new(
                                                StatusCode::VERIFIER_INVARIANT_VIOLATION,
                                            )
                                            .with_message(
                                                "the type argument for vector-related bytecode \
                                                expects one and only one signature token"
                                                    .to_owned(),
                                            ));
                                        }
                                        Some(sig_token) => sig_token,
                                    };
                                    single_signature_token_map.insert(
                                        *si,
                                        intern_type(
                                            BinaryIndexedView::Module(&module),
                                            ty,
                                            &struct_ids,
                                        )?,
                                    );
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }

            for func_handle in module.function_handles() {
                let func_name = module.identifier_at(func_handle.name);
                let module_handle = module.module_handle_at(func_handle.module);
                let module_id = module.module_id_for_handle(module_handle);
                let func_handle = if module_id == id {
                    FunctionHandle::Local(
                        function_defs[*function_map.get(func_name).ok_or_else(|| {
                            PartialVMError::new(StatusCode::TYPE_RESOLUTION_FAILURE).with_message(
                                "Cannot find function in publishing module".to_string(),
                            )
                        })?]
                        .clone(),
                    )
                } else {
                    FunctionHandle::Remote {
                        module: module_storage.load_checksum(&module_id)?,
                        name: func_name.to_owned(),
                    }
                };
                function_refs.push(func_handle);
            }

            for func_inst in module.function_instantiations() {
                let handle = function_refs[func_inst.handle.0 as usize].clone();
                function_instantiations.push(FunctionInstantiation {
                    handle,
                    instantiation: signature_table[func_inst.type_parameters.0 as usize].clone(),
                });
            }

            for func_handle in module.field_handles() {
                let def_idx = func_handle.owner;
                let definition_struct_type =
                    structs[def_idx.0 as usize].definition_struct_type.clone();
                let offset = func_handle.field as usize;
                field_handles.push(FieldHandle {
                    offset,
                    definition_struct_type,
                });
            }

            for field_inst in module.field_instantiations() {
                let fh_idx = field_inst.handle;
                let offset = field_handles[fh_idx.0 as usize].offset;
                let owner_struct_def = &structs[module.field_handle_at(fh_idx).owner.0 as usize];
                field_instantiations.push(FieldInstantiation {
                    offset,
                    instantiation: signature_table[field_inst.type_parameters.0 as usize].clone(),
                    definition_struct_type: owner_struct_def.definition_struct_type.clone(),
                });
            }

            Ok(())
        };

        match create() {
            Ok(_) => Ok(Self {
                id,
                checksum,
                module: Arc::new(module),
                structs,
                struct_instantiations,
                function_refs,
                function_defs,
                function_instantiations,
                field_handles,
                field_instantiations,
                function_map,
                struct_map,
                single_signature_token_map,
            }),
            Err(err) => Err(err),
        }
    }

    pub(crate) fn struct_at(&self, idx: StructDefinitionIndex) -> Arc<StructType> {
        self.structs[idx.0 as usize].definition_struct_type.clone()
    }

    pub(crate) fn struct_instantiation_at(&self, idx: u16) -> &StructInstantiation {
        &self.struct_instantiations[idx as usize]
    }

    pub(crate) fn function_at(&self, idx: u16) -> &FunctionHandle {
        &self.function_refs[idx as usize]
    }

    pub(crate) fn function_instantiation_at(&self, idx: u16) -> &FunctionInstantiation {
        &self.function_instantiations[idx as usize]
    }

    pub(crate) fn field_count(&self, idx: u16) -> u16 {
        self.structs[idx as usize].field_count
    }

    pub(crate) fn field_instantiation_count(&self, idx: u16) -> u16 {
        self.struct_instantiations[idx as usize].field_count
    }

    pub(crate) fn compiled_module(&self) -> &CompiledModule {
        &self.module
    }

    pub(crate) fn arc_module(&self) -> Arc<CompiledModule> {
        self.module.clone()
    }

    pub(crate) fn field_offset(&self, idx: FieldHandleIndex) -> usize {
        self.field_handles[idx.0 as usize].offset
    }

    pub(crate) fn field_instantiation_offset(&self, idx: FieldInstantiationIndex) -> usize {
        self.field_instantiations[idx.0 as usize].offset
    }

    pub(crate) fn single_type_at(&self, idx: SignatureIndex) -> &Type {
        self.single_signature_token_map.get(&idx).unwrap()
    }

    pub(crate) fn resolve_function_by_name(
        &self,
        function_name: &IdentStr,
    ) -> PartialVMResult<Arc<Function>> {
        match self
            .function_map
            .get(function_name)
            .and_then(|idx| self.function_defs.get(*idx))
        {
            Some(func) => Ok(func.clone()),
            None => {
                return Err(PartialVMError::new(StatusCode::FUNCTION_RESOLUTION_FAILURE)
                    .with_message(format!(
                        "Cannot find {:?}::{:?} in cache",
                        self.id, function_name
                    )))
            }
        }
    }

    pub(crate) fn get_struct_type_by_identifier(
        &self,
        struct_name: &IdentStr,
    ) -> PartialVMResult<Arc<StructType>> {
        self.struct_map
            .get(struct_name)
            .and_then(|idx| Some(self.structs.get(*idx)?.definition_struct_type.clone()))
            .ok_or_else(|| {
                PartialVMError::new(StatusCode::TYPE_RESOLUTION_FAILURE).with_message(format!(
                    "Cannot find {:?}::{:?} in cache",
                    self.id, struct_name
                ))
            })
    }
}

fn make_struct_type(
    module: &CompiledModule,
    struct_def: &StructDefinition,
    struct_identifiers: &[StructIdentifier],
) -> PartialVMResult<StructType> {
    let struct_handle = module.struct_handle_at(struct_def.struct_handle);
    let field_names = match &struct_def.field_information {
        StructFieldInformation::Native => vec![],
        StructFieldInformation::Declared(field_info) => field_info
            .iter()
            .map(|f| module.identifier_at(f.name).to_owned())
            .collect(),
    };
    let abilities = struct_handle.abilities;
    let name = module.identifier_at(struct_handle.name).to_owned();
    let type_parameters = struct_handle.type_parameters.clone();
    let fields = match &struct_def.field_information {
        StructFieldInformation::Native => unreachable!("native structs have been removed"),
        StructFieldInformation::Declared(fields) => fields,
    };

    let mut field_tys = vec![];
    for field in fields {
        let ty = intern_type(
            BinaryIndexedView::Module(module),
            &field.signature.0,
            struct_identifiers,
        )?;
        debug_assert!(field_tys.len() < usize::max_value());
        field_tys.push(ty);
    }

    Ok(StructType {
        fields: field_tys,
        phantom_ty_args_mask: struct_handle
            .type_parameters
            .iter()
            .map(|ty| ty.is_phantom)
            .collect(),
        field_names,
        abilities,
        type_parameters,
        id: struct_identifiers[struct_def.struct_handle.0 as usize].clone(),
        module: module.self_id(),
        name,
    })
}
