use std::sync::Arc;

use move_binary_format::{
    access::{ModuleAccess, ScriptAccess},
    errors::{PartialVMError, PartialVMResult},
    file_format::{
        Constant, ConstantPoolIndex, FieldHandleIndex, FieldInstantiationIndex,
        FunctionHandleIndex, FunctionInstantiationIndex, SignatureIndex,
        StructDefInstantiationIndex, StructDefinitionIndex, StructVariantHandleIndex,
        StructVariantInstantiationIndex, VariantFieldHandleIndex, VariantFieldInstantiationIndex,
        VariantIndex,
    },
};
use move_core_types::{
    gas_algebra::NumTypeNodes, identifier::IdentStr, language_storage::ModuleId,
    value::MoveTypeLayout, vm_status::StatusCode,
};
use move_vm_types::{
    gas::GasMeter,
    loaded_data::runtime_types::{AbilityInfo, StructType, Type},
};

use super::{
    function::{FunctionHandle, LoadedFunction, LoadedFunctionOwner},
    module::{Module, StructVariantInfo, VariantFieldInfo},
    script::Script,
    Loader, SessionStorage,
};

// A simple wrapper for a `Module` or a `Script` in the `Resolver`
enum BinaryType {
    Module(Arc<Module>),
    Script(Arc<Script>),
}

// A Resolver is a simple and small structure allocated on the stack and used by the
// interpreter. It's the only API known to the interpreter and it's tailored to the interpreter
// needs.
pub(crate) struct Resolver<'a> {
    loader: &'a Loader,
    binary: BinaryType,
}

impl<'a> Resolver<'a> {
    pub(crate) fn for_module(loader: &'a Loader, module: Arc<Module>) -> Self {
        let binary = BinaryType::Module(module);
        Self { loader, binary }
    }

    pub(crate) fn for_script(loader: &'a Loader, script: Arc<Script>) -> Self {
        let binary = BinaryType::Script(script);
        Self { loader, binary }
    }

    //
    // Constant resolution
    //

    pub(crate) fn constant_at(&self, idx: ConstantPoolIndex) -> &Constant {
        match &self.binary {
            BinaryType::Module(module) => module.module.constant_at(idx),
            BinaryType::Script(script) => script.script.constant_at(idx),
        }
    }
}

macro_rules! build_loaded_function {
    ($function_name:ident, $idx_ty:ty, $get_function_handle:ident) => {
        pub(crate) fn $function_name(
            &self,
            idx: $idx_ty,
            verified_ty_args: Vec<Type>,
            session_storage: &dyn SessionStorage,
        ) -> PartialVMResult<LoadedFunction> {
            let (owner, function) = match &self.binary {
                BinaryType::Module(module) => {
                    let handle = module.$get_function_handle(idx.0);
                    match handle {
                        FunctionHandle::Local(function) => (
                            LoadedFunctionOwner::Module(module.clone()),
                            function.clone(),
                        ),
                        FunctionHandle::Remote { module_id, name } => {
                            let (module, function) =
                                self.loader().resolve_module_and_function_by_name(
                                    session_storage,
                                    module_id,
                                    name,
                                )?;
                            (LoadedFunctionOwner::Module(module), function)
                        }
                    }
                }
                BinaryType::Script(script) => {
                    let handle = script.$get_function_handle(idx.0);
                    match handle {
                        FunctionHandle::Local(_) => {
                            return Err(PartialVMError::new(
                                StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR,
                            )
                            .with_message("Scripts never have local functions".to_string()));
                        }
                        FunctionHandle::Remote { module_id, name } => {
                            let (module, function) =
                                self.loader().resolve_module_and_function_by_name(
                                    session_storage,
                                    module_id,
                                    name,
                                )?;
                            (LoadedFunctionOwner::Module(module), function)
                        }
                    }
                }
            };
            Ok(LoadedFunction {
                owner,
                ty_args: verified_ty_args,
                function,
            })
        }
    };
}

impl<'a> Resolver<'a> {
    //
    // Function resolution
    //

    build_loaded_function!(
        build_loaded_function_from_handle_and_ty_args,
        FunctionHandleIndex,
        function_at
    );

    build_loaded_function!(
        build_loaded_function_from_instantiation_and_ty_args,
        FunctionInstantiationIndex,
        function_instantiation_handle_at
    );

    pub(crate) fn build_loaded_function_from_name_and_ty_args(
        &self,
        session_storage: &dyn SessionStorage,
        module_id: &ModuleId,
        function_name: &IdentStr,
        verified_ty_args: Vec<Type>,
    ) -> PartialVMResult<LoadedFunction> {
        let (module, function) = self.loader.resolve_module_and_function_by_name(
            session_storage,
            module_id,
            function_name,
        )?;
        Ok(LoadedFunction {
            owner: LoadedFunctionOwner::Module(module),
            ty_args: verified_ty_args,
            function,
        })
    }

    pub(crate) fn instantiate_generic_function(
        &self,
        gas_meter: Option<&mut impl GasMeter>,
        idx: FunctionInstantiationIndex,
        ty_args: &[Type],
    ) -> PartialVMResult<Vec<Type>> {
        let instantiation = match &self.binary {
            BinaryType::Module(module) => module.function_instantiation_at(idx.0),
            BinaryType::Script(script) => script.function_instantiation_at(idx.0),
        };

        if let Some(gas_meter) = gas_meter {
            for ty in instantiation {
                gas_meter
                    .charge_create_ty(NumTypeNodes::new(ty.num_nodes_in_subst(ty_args)? as u64))?;
            }
        }

        let ty_builder = self.loader().ty_builder();
        let instantiation = instantiation
            .iter()
            .map(|ty| ty_builder.create_ty_with_subst(ty, ty_args))
            .collect::<PartialVMResult<Vec<_>>>()?;
        Ok(instantiation)
    }

    //
    // Type resolution
    //

    pub(crate) fn get_struct_ty(&self, idx: StructDefinitionIndex) -> Type {
        let struct_ty = match &self.binary {
            BinaryType::Module(module) => module.struct_at(idx),
            BinaryType::Script(_) => unreachable!("Scripts cannot have type instructions"),
        };
        self.create_struct_ty(&struct_ty)
    }

    pub(crate) fn get_struct_variant_at(
        &self,
        idx: StructVariantHandleIndex,
    ) -> &StructVariantInfo {
        match &self.binary {
            BinaryType::Module(module) => module.struct_variant_at(idx),
            BinaryType::Script(_) => unreachable!("Scripts cannot have type instructions"),
        }
    }

    pub(crate) fn get_struct_variant_instantiation_at(
        &self,
        idx: StructVariantInstantiationIndex,
    ) -> &StructVariantInfo {
        match &self.binary {
            BinaryType::Module(module) => module.struct_variant_instantiation_at(idx),
            BinaryType::Script(_) => unreachable!("Scripts cannot have type instructions"),
        }
    }

    pub(crate) fn get_generic_struct_ty(
        &self,
        idx: StructDefInstantiationIndex,
        ty_args: &[Type],
    ) -> PartialVMResult<Type> {
        let struct_inst = match &self.binary {
            BinaryType::Module(module) => module.struct_instantiation_at(idx.0),
            BinaryType::Script(_) => unreachable!("Scripts cannot have type instructions"),
        };

        let struct_ty = &struct_inst.definition_struct_type;
        let ty_builder = self.loader().ty_builder();
        ty_builder.create_struct_instantiation_ty(struct_ty, &struct_inst.instantiation, ty_args)
    }

    pub(crate) fn get_field_ty(&self, idx: FieldHandleIndex) -> PartialVMResult<&Type> {
        match &self.binary {
            BinaryType::Module(module) => {
                let handle = &module.field_handles[idx.0 as usize];
                Ok(&handle.field_ty)
            }
            BinaryType::Script(_) => unreachable!("Scripts cannot have type instructions"),
        }
    }

    pub(crate) fn get_generic_field_ty(
        &self,
        idx: FieldInstantiationIndex,
        ty_args: &[Type],
    ) -> PartialVMResult<Type> {
        let field_instantiation = match &self.binary {
            BinaryType::Module(module) => &module.field_instantiations[idx.0 as usize],
            BinaryType::Script(_) => unreachable!("Scripts cannot have type instructions"),
        };
        let field_ty = &field_instantiation.uninstantiated_field_ty;
        self.instantiate_ty(field_ty, ty_args, &field_instantiation.instantiation)
    }

    pub(crate) fn instantiate_ty(
        &self,
        ty: &Type,
        ty_args: &[Type],
        instantiation_tys: &[Type],
    ) -> PartialVMResult<Type> {
        let ty_builder = self.loader().ty_builder();
        let instantiation_tys = instantiation_tys
            .iter()
            .map(|inst_ty| ty_builder.create_ty_with_subst(inst_ty, ty_args))
            .collect::<PartialVMResult<Vec<_>>>()?;
        ty_builder.create_ty_with_subst(ty, &instantiation_tys)
    }

    pub(crate) fn variant_field_info_at(&self, idx: VariantFieldHandleIndex) -> &VariantFieldInfo {
        match &self.binary {
            BinaryType::Module(module) => module.variant_field_info_at(idx),
            BinaryType::Script(_) => unreachable!("Scripts cannot have type instructions"),
        }
    }

    pub(crate) fn variant_field_instantiation_info_at(
        &self,
        idx: VariantFieldInstantiationIndex,
    ) -> &VariantFieldInfo {
        match &self.binary {
            BinaryType::Module(module) => module.variant_field_instantiation_info_at(idx),
            BinaryType::Script(_) => unreachable!("Scripts cannot have type instructions"),
        }
    }

    pub(crate) fn get_struct(
        &self,
        idx: StructDefinitionIndex,
    ) -> PartialVMResult<Arc<StructType>> {
        match &self.binary {
            BinaryType::Module(module) => Ok(module.struct_at(idx)),
            BinaryType::Script(_) => unreachable!("Scripts cannot have type instructions"),
        }
    }

    pub(crate) fn instantiate_generic_struct_fields(
        &self,
        idx: StructDefInstantiationIndex,
        ty_args: &[Type],
    ) -> PartialVMResult<Vec<Type>> {
        let struct_inst = match &self.binary {
            BinaryType::Module(module) => module.struct_instantiation_at(idx.0),
            BinaryType::Script(_) => unreachable!("Scripts cannot have type instructions"),
        };
        let struct_ty = &struct_inst.definition_struct_type;
        self.instantiate_generic_fields(struct_ty, None, &struct_inst.instantiation, ty_args)
    }

    pub(crate) fn instantiate_generic_struct_variant_fields(
        &self,
        idx: StructVariantInstantiationIndex,
        ty_args: &[Type],
    ) -> PartialVMResult<Vec<Type>> {
        let struct_inst = match &self.binary {
            BinaryType::Module(module) => module.struct_variant_instantiation_at(idx),
            BinaryType::Script(_) => unreachable!("Scripts cannot have type instructions"),
        };
        let struct_ty = &struct_inst.definition_struct_type;
        self.instantiate_generic_fields(
            struct_ty,
            Some(struct_inst.variant),
            &struct_inst.instantiation,
            ty_args,
        )
    }

    pub(crate) fn instantiate_generic_fields(
        &self,
        struct_ty: &Arc<StructType>,
        variant: Option<VariantIndex>,
        instantiation: &[Type],
        ty_args: &[Type],
    ) -> PartialVMResult<Vec<Type>> {
        let ty_builder = self.loader().ty_builder();
        let instantiation_tys = instantiation
            .iter()
            .map(|inst_ty| ty_builder.create_ty_with_subst(inst_ty, ty_args))
            .collect::<PartialVMResult<Vec<_>>>()?;

        struct_ty
            .fields(variant)?
            .iter()
            .map(|(_, inst_ty)| ty_builder.create_ty_with_subst(inst_ty, &instantiation_tys))
            .collect::<PartialVMResult<Vec<_>>>()
    }

    fn single_type_at(&self, idx: SignatureIndex) -> &Type {
        match &self.binary {
            BinaryType::Module(module) => module.single_type_at(idx),
            BinaryType::Script(script) => script.single_type_at(idx),
        }
    }

    pub(crate) fn instantiate_single_type(
        &self,
        idx: SignatureIndex,
        ty_args: &[Type],
    ) -> PartialVMResult<Type> {
        let ty = self.single_type_at(idx);

        if !ty_args.is_empty() {
            self.loader().ty_builder().create_ty_with_subst(ty, ty_args)
        } else {
            Ok(ty.clone())
        }
    }

    //
    // Fields resolution
    //

    //
    // Fields resolution
    //

    pub(crate) fn field_offset(&self, idx: FieldHandleIndex) -> usize {
        match &self.binary {
            BinaryType::Module(module) => module.field_offset(idx),
            BinaryType::Script(_) => unreachable!("Scripts cannot have field instructions"),
        }
    }

    pub(crate) fn field_instantiation_offset(&self, idx: FieldInstantiationIndex) -> usize {
        match &self.binary {
            BinaryType::Module(module) => module.field_instantiation_offset(idx),
            BinaryType::Script(_) => unreachable!("Scripts cannot have field instructions"),
        }
    }

    pub(crate) fn field_count(&self, idx: StructDefinitionIndex) -> u16 {
        match &self.binary {
            BinaryType::Module(module) => module.field_count(idx.0),
            BinaryType::Script(_) => unreachable!("Scripts cannot have type instructions"),
        }
    }

    pub(crate) fn field_instantiation_count(&self, idx: StructDefInstantiationIndex) -> u16 {
        match &self.binary {
            BinaryType::Module(module) => module.field_instantiation_count(idx.0),
            BinaryType::Script(_) => unreachable!("Scripts cannot have type instructions"),
        }
    }

    pub(crate) fn field_handle_to_struct(&self, idx: FieldHandleIndex) -> Type {
        match &self.binary {
            BinaryType::Module(module) => {
                let struct_ty = &module.field_handles[idx.0 as usize].definition_struct_type;
                self.loader()
                    .ty_builder()
                    .create_struct_ty(struct_ty.id(), AbilityInfo::struct_(struct_ty.abilities))
            }
            BinaryType::Script(_) => unreachable!("Scripts cannot have field instructions"),
        }
    }

    pub(crate) fn field_instantiation_to_struct(
        &self,
        idx: FieldInstantiationIndex,
        ty_args: &[Type],
    ) -> PartialVMResult<Type> {
        match &self.binary {
            BinaryType::Module(module) => {
                let field_inst = &module.field_instantiations[idx.0 as usize];
                let struct_ty = &field_inst.definition_struct_type;
                let ty_params = &field_inst.instantiation;
                self.create_struct_instantiation_ty(struct_ty, ty_params, ty_args)
            }
            BinaryType::Script(_) => unreachable!("Scripts cannot have field instructions"),
        }
    }

    pub(crate) fn create_struct_ty(&self, struct_ty: &Arc<StructType>) -> Type {
        self.loader()
            .ty_builder()
            .create_struct_ty(struct_ty.id(), AbilityInfo::struct_(struct_ty.abilities))
    }

    pub(crate) fn create_struct_instantiation_ty(
        &self,
        struct_ty: &Arc<StructType>,
        ty_params: &[Type],
        ty_args: &[Type],
    ) -> PartialVMResult<Type> {
        self.loader()
            .ty_builder()
            .create_struct_instantiation_ty(struct_ty, ty_params, ty_args)
    }

    pub(crate) fn type_to_type_layout(
        &self,
        ty: &Type,
        session_storage: &dyn SessionStorage,
    ) -> PartialVMResult<MoveTypeLayout> {
        self.loader.type_to_type_layout(ty, session_storage)
    }

    pub(crate) fn type_to_type_layout_with_identifier_mappings(
        &self,
        ty: &Type,
        session_storage: &dyn SessionStorage,
    ) -> PartialVMResult<(MoveTypeLayout, bool)> {
        self.loader
            .type_to_type_layout_with_identifier_mappings(ty, session_storage)
    }

    pub(crate) fn type_to_fully_annotated_layout(
        &self,
        ty: &Type,
        session_storage: &dyn SessionStorage,
    ) -> PartialVMResult<MoveTypeLayout> {
        self.loader
            .type_to_fully_annotated_layout(ty, session_storage)
    }

    pub(crate) fn loader(&self) -> &Loader {
        self.loader
    }
}
