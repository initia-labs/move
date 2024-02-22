address 0x2 {
    module A {
       fun get(a: u64, b: u64): u64 {
            0x2::B::get(a, b)
       }
    }

    module B {
        public fun get(a: u64, b: u64): u64 {
            a + b
        }
    }
}
