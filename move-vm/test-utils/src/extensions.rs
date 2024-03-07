#[cfg(feature = "table-extension")]
use itertools::Itertools;
#[cfg(feature = "table-extension")]
use move_table_extension::NativeTableContext;
use move_vm_runtime::native_extensions::NativeContextExtensions;
use std::fmt::Write;

/// Print the change sets for available native context extensions.
#[allow(unused)]
pub(crate) fn print_change_sets<W: Write>(_w: &mut W, mut extensions: NativeContextExtensions) {
    #[cfg(feature = "table-extension")]
    print_table_extension(_w, &mut extensions);
}

#[cfg(feature = "table-extension")]
fn print_table_extension<W: Write>(w: &mut W, extensions: &mut NativeContextExtensions) {
    let cs = extensions.remove::<NativeTableContext>().into_change_set();
    if let Ok(cs) = cs {
        if !cs.new_tables.is_empty() {
            writeln!(
                w,
                "new tables {}",
                cs.new_tables
                    .iter()
                    .map(|(k, v)| format!("{}<{},{}>", k, v.key_type, v.value_type))
                    .join(", ")
            )
            .unwrap();
        }
        if !cs.removed_tables.is_empty() {
            writeln!(
                w,
                "removed tables {}",
                cs.removed_tables.iter().map(|h| h.to_string()).join(", ")
            )
            .unwrap();
        }
        for (h, c) in cs.changes {
            writeln!(w, "for {}", h).unwrap();
            for (k, v) in c.entries {
                writeln!(w, "  {:X?} := {:X?}", k, v).unwrap();
            }
        }
    }
}
