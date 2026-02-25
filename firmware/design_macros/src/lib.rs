use proc_macro::TokenStream;

use quote::quote;
use rand::{Rng, RngExt, prelude::IndexedRandom};
use syn::{Expr, parse_macro_input};

#[proc_macro]
pub fn rand_ops(input: TokenStream) -> TokenStream {
    let rng = parse_macro_input!(input as Expr);
    let mut rand_rng = rand::rng();

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
        quote! { check = core::hint::black_box(#rng.next_u32() ^ i) },
        quote! { check = core::hint::black_box(#rng.next_u32() ^ check) },
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
        use design_utils::anti_hardware::RngCore;
        let num_ops = core::hint::black_box((#rng.next_u32() ^ #num_ops_xor) % 500);

        let mut check = core::hint::black_box(#rng.next_u32() ^ #n_xor);
        for i in 0..num_ops {
            match core::hint::black_box(check % #num_ops) {
                #ops
                _ => panic!("impossible check"),
            }
        }
    }}.into()
}
