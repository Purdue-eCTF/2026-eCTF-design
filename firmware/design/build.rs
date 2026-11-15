fn main() {
    println!("cargo:rerun-if-changed=link.x");
    println!("cargo:rerun-if-changed=memory.x");
    println!("cargo:rustc-link-arg=-Xlinker");
    println!("cargo:rustc-link-arg=--print-memory-usage");
}
