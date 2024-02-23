address 0x2 {
    module B {
        public fun get(a: u64, b: u64): u64 {
            a + b + 100
        }
    }
}
