use std::{collections::HashMap, num::NonZeroUsize, sync::Arc};

use lru::LruCache;
use move_binary_format::errors::{PartialVMError, PartialVMResult};
use move_core_types::{
    identifier::Identifier, language_storage::StructTag, value::MoveTypeLayout,
    vm_status::StatusCode,
};
use move_vm_types::loaded_data::runtime_types::{
    Checksum, DepthFormula, StructIdentifier, StructType, Type,
};

use super::{function::Function, module::Module, script::Script};

pub(crate) struct ModuleCache {
    modules: HashMap<Checksum, Arc<Module>>,
}

impl ModuleCache {
    pub(crate) fn new() -> Self {
        Self {
            modules: HashMap::new(),
        }
    }

    pub(crate) fn has(&self, checksum: &Checksum) -> bool {
        self.modules.contains_key(checksum)
    }

    pub(crate) fn get(&self, checksum: &Checksum) -> Option<Arc<Module>> {
        self.modules.get(checksum).cloned()
    }

    pub(crate) fn remove(&mut self, checksum: &Checksum) {
        self.modules.remove(checksum);
    }

    pub(crate) fn insert(&mut self, checksum: Checksum, module: Module) -> Arc<Module> {
        let module_ref = Arc::new(module);
        self.modules.insert(checksum, module_ref.clone());

        module_ref
    }

    pub(crate) fn get_struct_type_by_identifier(
        &self,
        checksum: &Checksum,
        id: &StructIdentifier,
    ) -> PartialVMResult<Arc<StructType>> {
        self.get(checksum)
            .and_then(|module| {
                let idx = module.struct_map.get(&id.name)?;
                Some(module.structs.get(*idx)?.definition_struct_type.clone())
            })
            .ok_or_else(|| {
                PartialVMError::new(StatusCode::TYPE_RESOLUTION_FAILURE).with_message(format!(
                    "Cannot find {:?}::{:?} in cache",
                    id.module_id, id.name
                ))
            })
    }
}

pub(crate) struct TypeCache {
    pub(crate) types: HashMap<Checksum, TypeCacheItem>,
}

impl TypeCache {
    pub(crate) fn new() -> Self {
        Self {
            types: HashMap::new(),
        }
    }

    pub(crate) fn create_type_cache(&mut self, checksum: Checksum) -> Option<TypeCacheItem> {
        self.types.insert(checksum, TypeCacheItem::new())
    }

    pub(crate) fn remove_type_cache(&mut self, checksum: &Checksum) {
        self.types.remove(checksum);
    }

    pub(crate) fn get_types(&self, checksum: &Checksum) -> Option<&TypeCacheItem> {
        self.types.get(checksum)
    }

    pub(crate) fn insert_type(
        &mut self,
        checksum: &Checksum,
        id: &StructIdentifier,
        ty_args: &[Type],
    ) -> PartialVMResult<&mut StructInfoCache> {
        match self.types.get_mut(checksum) {
            Some(item) => Ok(item
                .structs
                .entry(id.name.clone())
                .or_default()
                .entry(ty_args.to_vec())
                .or_insert_with(StructInfoCache::new)),
            None => Err(PartialVMError::new(StatusCode::LINKER_ERROR)
                .with_message(format!("Cannot find {:x?} in cache", id.module_id))),
        }
    }

    pub(crate) fn insert_depth_formula(
        &mut self,
        checksum: &Checksum,
        id: &StructIdentifier,
        depth_formula: DepthFormula,
    ) -> PartialVMResult<Option<DepthFormula>> {
        match self.types.get_mut(checksum) {
            Some(item) => Ok(item.depth_formula.insert(id.name.clone(), depth_formula)),
            None => Err(PartialVMError::new(StatusCode::LINKER_ERROR)
                .with_message(format!("Cannot find {:x?} in cache", id.module_id))),
        }
    }
}

pub(crate) struct TypeCacheItem {
    pub(crate) structs: HashMap<Identifier, HashMap<Vec<Type>, StructInfoCache>>,
    pub(crate) depth_formula: HashMap<Identifier, DepthFormula>,
}

impl TypeCacheItem {
    fn new() -> Self {
        Self {
            structs: HashMap::new(),
            depth_formula: HashMap::new(),
        }
    }
}

pub(crate) struct ScriptCache {
    scripts: HashMap<Checksum, Arc<Script>>,
}

impl ScriptCache {
    pub(crate) fn new() -> Self {
        Self {
            scripts: HashMap::new(),
        }
    }

    pub(crate) fn get_main(
        &self,
        checksum: &Checksum,
    ) -> Option<(Arc<Function>, Vec<Type>, Vec<Type>)> {
        self.scripts.get(checksum).cloned().map(|script| {
            (
                script.entry_point(),
                script.parameter_tys.clone(),
                script.return_tys.clone(),
            )
        })
    }

    pub(crate) fn get(&self, checksum: &Checksum) -> Option<Arc<Script>> {
        self.scripts.get(checksum).cloned()
    }

    pub(crate) fn insert(
        &mut self,
        checksum: Checksum,
        script: Script,
    ) -> (Arc<Function>, Vec<Type>, Vec<Type>) {
        let item = Arc::new(script);
        self.scripts.insert(checksum, item.clone());
        (
            item.entry_point(),
            item.parameter_tys.clone(),
            item.return_tys.clone(),
        )
    }

    pub(crate) fn remove(&mut self, checksum: &Checksum) {
        self.scripts.remove(checksum);
    }
}

//
// Cache for data associated to a Struct, used for de/serialization and more
//
#[derive(Clone)]
pub(crate) struct StructInfoCache {
    pub(crate) struct_tag: Option<(StructTag, u64)>,
    pub(crate) struct_layout_info: Option<StructLayoutInfoCacheItem>,
    pub(crate) annotated_struct_layout: Option<MoveTypeLayout>,
    pub(crate) annotated_node_count: Option<u64>,
}

impl StructInfoCache {
    fn new() -> Self {
        Self {
            struct_tag: None,
            struct_layout_info: None,
            annotated_struct_layout: None,
            annotated_node_count: None,
        }
    }
}

#[derive(Clone)]
pub(crate) struct StructLayoutInfoCacheItem {
    pub(crate) struct_layout: MoveTypeLayout,
    pub(crate) node_count: u64,
    pub(crate) has_identifier_mappings: bool,
}

pub(crate) struct CacheHitRecords {
    checksums: LruCache<Checksum, bool>,
}

impl CacheHitRecords {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            checksums: LruCache::new(NonZeroUsize::new(capacity).unwrap()),
        }
    }

    pub(crate) fn create(&mut self, checksum: Checksum) -> Option<Checksum> {
        // Pop least recently used cache item if the cache is full
        let popped_elem = if self.checksums.len() == self.checksums.cap().into() {
            self.checksums.pop_lru().map(|(k, _)| k)
        } else {
            None
        };

        // create new hit entry
        self.checksums.put(checksum, true);

        // return popped elem to remove from the cache
        popped_elem
    }

    pub(crate) fn record_hit(&mut self, checksum: &Checksum) {
        self.checksums.get(checksum);
    }

    pub(crate) fn peek(&self, checksum: &Checksum) -> bool {
        self.checksums.peek(checksum).is_some()
    }
}
