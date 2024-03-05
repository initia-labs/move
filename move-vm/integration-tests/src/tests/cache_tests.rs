use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use bytes::Bytes;
use move_binary_format::errors::VMResult;
use move_binary_format::CompiledModule;
use move_core_types::account_address::AccountAddress;
use move_core_types::effects::Op;
use move_core_types::identifier::Identifier;
use move_core_types::language_storage::ModuleId;
use move_core_types::value::{MoveTypeLayout, MoveValue};
use move_core_types::vm_status::StatusCode;
use move_vm_runtime::session::SerializedReturnValues;
use move_vm_runtime::{config::VMConfig, move_vm::MoveVM};
use move_vm_test_utils::InMemoryStorage;
use move_vm_types::gas::UnmeteredGasMeter;
use move_vm_types::loaded_data::runtime_types::Checksum;

use crate::compiler::compile_modules_in_file;
use sha3::{Digest, Sha3_256};

const WORKING_ACCOUNT: AccountAddress = AccountAddress::TWO;

fn get_test_base(config: VMConfig) -> (InMemoryStorage, Arc<MoveVM>) {
    let data_store = InMemoryStorage::new();
    let vm = MoveVM::new_with_config(vec![], config).expect("should make move vm");
    (data_store, Arc::new(vm))
}

fn get_modules(append_path: &str) -> Vec<CompiledModule> {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(append_path);
    compile_modules_in_file(&path).unwrap()
}

fn test_update_modules(
    data_store: &mut InMemoryStorage,
    vm: &MoveVM,
    base_path: &str,
    update_path: &str,
    updated_modules: Vec<&str>,
) {
    let mut session = vm.new_session(data_store);
    let mut module_bundles = vec![];
    for module in get_modules(base_path) {
        let mut module_bytes = vec![];
        module
            .serialize(&mut module_bytes)
            .unwrap_or_else(|_| panic!("failure in module serialization: {:#?}", module));
        module_bundles.push(module_bytes);
    }
    session
        .publish_module_bundle_relax_compatibility(
            module_bundles,
            WORKING_ACCOUNT,
            &mut UnmeteredGasMeter,
        )
        .unwrap_or_else(|_| panic!("failure publishing modules"));
    let changeset = session.finish().expect("failure getting write set");
    vm.flush_unused_module_cache();

    let account_changes = changeset
        .accounts()
        .get(&WORKING_ACCOUNT)
        .unwrap_or_else(|| panic!("should exist {}", WORKING_ACCOUNT));
    let checksums: BTreeMap<Identifier, Op<[u8; 32]>> = account_changes
        .modules()
        .iter()
        .map(|(id, blob_op)| {
            (
                id.clone(),
                blob_op.map_ref(|blob| {
                    let mut sha3_256 = Sha3_256::new();
                    sha3_256.update(&blob);
                    let checksum: Checksum = sha3_256.finalize().into();

                    checksum
                }),
            )
        })
        .collect();
    data_store
        .apply(changeset.clone())
        .expect("failure applying write set");

    let mut session = vm.new_session(data_store);
    let mut module_bundles = vec![];
    let mut update_module_map = BTreeMap::<ModuleId, (Bytes, Checksum)>::new();
    for module in get_modules(update_path) {
        let mut module_bytes = vec![];
        module
            .serialize(&mut module_bytes)
            .unwrap_or_else(|_| panic!("failure in module serialization: {:#?}", module));
        let mut sha3_256 = Sha3_256::new();
        sha3_256.update(module_bytes.clone());
        let checksum: Checksum = sha3_256.finalize().into();
        update_module_map.insert(
            module.self_id(),
            (Bytes::copy_from_slice(module_bytes.as_slice()), checksum),
        );

        module_bundles.push(module_bytes);
    }
    session
        .publish_module_bundle_relax_compatibility(
            module_bundles,
            WORKING_ACCOUNT,
            &mut UnmeteredGasMeter,
        )
        .unwrap_or_else(|_| panic!("failure publishing modules"));

    update_module_map
        .into_iter()
        .for_each(|(module_id, (module_bytes, checksum))| {
            let session_cache_module = session
                .load_module_from_cache(&module_id)
                .unwrap_or_else(|| panic!("module should exist in session cache"));
            let mut session_cache_module_bytes = vec![];
            session_cache_module.serialize(&mut session_cache_module_bytes).unwrap();
            assert_eq!(
                module_bytes, session_cache_module_bytes,
                "updated module bytes should equal with bytes in session cache"
            );

            let session_cache_checksum = session
                .load_checksum_from_cache(&module_id)
                .unwrap_or_else(|| panic!("checksum should exist in session cache"));
            assert_eq!(
                checksum, session_cache_checksum,
                "updated checksum should equal with checksum in session cache"
            );
        });

    let changeset = session.finish().expect("failure getting write set");
    vm.flush_unused_module_cache();
    let account_changes = changeset
        .accounts()
        .get(&WORKING_ACCOUNT)
        .unwrap_or_else(|| panic!("should exist {}", WORKING_ACCOUNT));

    let update_checksums: BTreeMap<Identifier, Op<[u8; 32]>> = account_changes
        .modules()
        .iter()
        .map(|(id, blob_op)| {
            (
                id.clone(),
                blob_op.map_ref(|blob| {
                    let mut sha3_256 = Sha3_256::new();
                    sha3_256.update(&blob);
                    let checksum: Checksum = sha3_256.finalize().into();

                    checksum
                }),
            )
        })
        .collect();

    update_checksums.iter().for_each(|(ident, op)| {
        let module_str = ident.as_str();
        assert!(
            matches!(op, Op::Modify(_)),
            "module is updated but not reflected to the change set"
        );
        let existing_checksum = checksums
            .get(ident)
            .unwrap_or_else(|| panic!("module is updated but not in change set"))
            .clone()
            .ok()
            .unwrap_or_else(|| panic!("should exist checksum"));
        let checksum = op
            .clone()
            .ok()
            .unwrap_or_else(|| panic!("should exist checksum"));

        if updated_modules.contains(&module_str) {
            assert_ne!(existing_checksum, checksum, "module is updated");
        } else {
            assert_eq!(existing_checksum, checksum, "module is not updated");
        }
    });
    data_store
        .apply(changeset.clone())
        .expect("failure applying write set");
}

#[test]
fn test_default_update_module() {
    let config = VMConfig::default();

    let (mut data_store, vm) = get_test_base(config);
    test_update_modules(
        &mut data_store,
        &vm,
        "src/tests/loader_tests_modules.move",
        "src/tests/loader_tests_update_modules.move",
        vec!["A", "D"],
    );
}

#[test]
fn test_small_cache_update_module() {
    let config = VMConfig {
        module_cache_capacity: 1,
        ..Default::default()
    };
    let (mut data_store, vm) = get_test_base(config);
    test_update_modules(
        &mut data_store,
        &vm,
        "src/tests/loader_tests_modules.move",
        "src/tests/loader_tests_update_modules.move",
        vec!["A", "D"],
    );
}

fn test_update_function(update_path: &str, cache_size: usize) -> VMResult<SerializedReturnValues> {
    let config = VMConfig {
        module_cache_capacity: cache_size,
        ..Default::default()
    };

    let (mut data_store, vm) = get_test_base(config);
    test_update_modules(
        &mut data_store,
        &vm,
        "src/tests/cache_test_modules/plus.move",
        update_path,
        vec!["B"],
    );

    let mut session = vm.new_session(&data_store);
    let module_id = ModuleId::new(WORKING_ACCOUNT, Identifier::new("A").unwrap());
    let fun_name = Identifier::new("get").unwrap();
    let args = vec![MoveValue::U64(10), MoveValue::U64(20)];

    let args: Vec<_> = args
        .into_iter()
        .map(|val| val.simple_serialize().unwrap())
        .collect();

    session.execute_function_bypass_visibility(
        &module_id,
        &fun_name,
        vec![],
        args,
        &mut UnmeteredGasMeter,
    )
}

#[test]
fn test_normal_function_update_module_1() {
    let SerializedReturnValues {
        return_values,
        mutable_reference_outputs: _,
    } = test_update_function("src/tests/cache_test_modules/plus_update.move", 1)
        .expect("should run get function");

    let mut values: Vec<Vec<u8>> = return_values
        .into_iter()
        .map(|(bytes, _layout)| bytes)
        .collect();

    let return_value = values
        .pop()
        .unwrap_or_else(|| panic!("get function should return value"));
    let return_value = MoveValue::simple_deserialize(return_value.as_slice(), &MoveTypeLayout::U64)
        .expect("get function return u64");
    if let MoveValue::U64(x) = return_value {
        assert_eq!(x, 130, "updated module return a+b+100");
    } else {
        panic!("failure getting return value");
    }
}

#[test]
fn test_normal_function_update_module_100() {
    let SerializedReturnValues {
        return_values,
        mutable_reference_outputs: _,
    } = test_update_function("src/tests/cache_test_modules/plus_update.move", 100)
        .expect("should run get function");

    let mut values: Vec<Vec<u8>> = return_values
        .into_iter()
        .map(|(bytes, _layout)| bytes)
        .collect();

    let return_value = values
        .pop()
        .unwrap_or_else(|| panic!("get function should return value"));
    let return_value = MoveValue::simple_deserialize(return_value.as_slice(), &MoveTypeLayout::U64)
        .expect("get function return u64");
    if let MoveValue::U64(x) = return_value {
        assert_eq!(x, 130, "updated module return a+b+100");
    } else {
        panic!("failure getting return value");
    }
}

#[test]
fn test_deleted_function_update_module() {
    let err = test_update_function(
        "src/tests/cache_test_modules/plus_update_delete_function.move",
        100,
    )
    .unwrap_err();

    assert_eq!(err.major_status(), StatusCode::UNEXPECTED_VERIFIER_ERROR);
}

#[test]
fn test_private_function_update_module() {
    let err = test_update_function(
        "src/tests/cache_test_modules/plus_update_private_function.move",
        100,
    )
    .unwrap_err();

    assert_eq!(err.major_status(), StatusCode::UNEXPECTED_VERIFIER_ERROR);
}

fn test_new_loader_after_update_function(
    update_path: &str,
    cache_size: usize,
) -> VMResult<SerializedReturnValues> {
    let config = VMConfig {
        module_cache_capacity: cache_size,
        ..Default::default()
    };

    let (mut data_store, vm) = get_test_base(config.clone());
    test_update_modules(
        &mut data_store,
        &vm,
        "src/tests/cache_test_modules/plus.move",
        update_path,
        vec!["B"],
    );

    let vm = MoveVM::new_with_config(vec![], config).expect("should make move vm");

    let mut session = vm.new_session(&data_store);
    let module_id = ModuleId::new(WORKING_ACCOUNT, Identifier::new("A").unwrap());
    let fun_name = Identifier::new("get").unwrap();
    let args = vec![MoveValue::U64(10), MoveValue::U64(20)];

    let args: Vec<_> = args
        .into_iter()
        .map(|val| val.simple_serialize().unwrap())
        .collect();

    session.execute_function_bypass_visibility(
        &module_id,
        &fun_name,
        vec![],
        args,
        &mut UnmeteredGasMeter,
    )
}

#[test]
fn test_new_loader_normal_function_update_module_100() {
    let SerializedReturnValues {
        return_values,
        mutable_reference_outputs: _,
    } = test_new_loader_after_update_function("src/tests/cache_test_modules/plus_update.move", 100)
        .expect("should run get function");

    let mut values: Vec<Vec<u8>> = return_values
        .into_iter()
        .map(|(bytes, _layout)| bytes)
        .collect();

    let return_value = values
        .pop()
        .unwrap_or_else(|| panic!("get function should return value"));
    let return_value = MoveValue::simple_deserialize(return_value.as_slice(), &MoveTypeLayout::U64)
        .expect("get function return u64");
    if let MoveValue::U64(x) = return_value {
        assert_eq!(x, 130, "updated module return a+b+100");
    } else {
        panic!("failure getting return value");
    }
}

#[test]
fn test_new_loader_normal_function_update_module_1() {
    let SerializedReturnValues {
        return_values,
        mutable_reference_outputs: _,
    } = test_new_loader_after_update_function("src/tests/cache_test_modules/plus_update.move", 1)
        .expect("should run get function");

    let mut values: Vec<Vec<u8>> = return_values
        .into_iter()
        .map(|(bytes, _layout)| bytes)
        .collect();

    let return_value = values
        .pop()
        .unwrap_or_else(|| panic!("get function should return value"));
    let return_value = MoveValue::simple_deserialize(return_value.as_slice(), &MoveTypeLayout::U64)
        .expect("get function return u64");
    if let MoveValue::U64(x) = return_value {
        assert_eq!(x, 130, "updated module return a+b+100");
    } else {
        panic!("failure getting return value");
    }
}
