use proc_macro::TokenStream;

use blake2::{Blake2s256, Digest};
use quote::quote;
use rand::{RngExt, SeedableRng, prelude::IndexedRandom, rngs::StdRng};
use syn::{Expr, parse_macro_input, spanned::Spanned};

const MAGIC_SEED_CONST: u64 = 0xD15E_A5E5_C0DE_C0DE;

fn hash_seed(build_seed: &str, file: &str, line: u32, column: u32) -> [u8; 32] {
    let mut hasher = Blake2s256::new();
    hasher.update(MAGIC_SEED_CONST.to_le_bytes());
    hasher.update(build_seed.as_bytes());
    hasher.update(file.as_bytes());
    hasher.update(line.to_le_bytes());
    hasher.update(column.to_le_bytes());
    hasher.finalize().into()
}

#[proc_macro]
pub fn rand_ops(input: TokenStream) -> TokenStream {
    let rng = parse_macro_input!(input as Expr);

    let build_seed = std::env::var("BUILD_SEED").unwrap_or("temp_seed".to_string());

    let call_site = rng.span();
    let call_site_start = call_site.start();
    let call_site_file = call_site.file();

    let seed = hash_seed(
        &build_seed,
        &call_site_file,
        call_site_start.line as u32,
        call_site_start.column as u32,
    );

    let mut rand_rng = StdRng::from_seed(seed);

    let num_ops_xor: u32 = rand_rng.random();
    let n_xor: u32 = rand_rng.random();

    let random_xor: u32 = rand_rng.random();
    let random_shift: u32 = rand_rng.random_range(0..32);
    let random_divide: u32 = rand_rng.random_range(1..=u32::MAX);

    let possible_rand_ops = [
        quote! { check = core::hint::black_box(check ^ i) },
        quote! { check = core::hint::black_box(check.wrapping_add(i)) },
        quote! { check = core::hint::black_box(check.wrapping_mul(i)) },
        quote! { check = core::hint::black_box(!(check ^ i)) },
        quote! { check = core::hint::black_box(!check) },
        quote! { check = core::hint::black_box(check ^ #random_xor) },
        quote! { check = core::hint::black_box((check / #random_divide) ^ (check % #random_divide))},
        quote! { check = core::hint::black_box(check.rotate_right(#random_shift)) },
        quote! { check = core::hint::black_box(#rng.word() ^ i) },
        quote! { check = core::hint::black_box(#rng.word() ^ check) },
    ];

    let num_ops: u32 = rand_rng.random_range(5..16);

    let mut ops = proc_macro2::TokenStream::new();
    for i in 0..num_ops {
        // TODO: maybe make duplicate ops have different constants
        let op = possible_rand_ops.choose(&mut rand_rng).unwrap();

        ops.extend(quote! {
            #i => #op,
        });
    }

    quote! {{
        // use design_utils::anti_hardware::RngCore;
        let num_ops = core::hint::black_box((#rng.word() ^ #num_ops_xor) % 256);

        let mut check = core::hint::black_box(#rng.word() ^ #n_xor);
        for i in 0..num_ops {
            match core::hint::black_box(check % #num_ops) {
                #ops
                _ => panic!("impossible check"),
            }
        }
    }}
    .into()
}
