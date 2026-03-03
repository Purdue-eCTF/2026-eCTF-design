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

fn build_rng(expr: &Expr) -> StdRng {
    let build_seed = std::env::var("BUILD_SEED").unwrap_or("temp_seed".to_string());

    let call_site = expr.span();
    let call_site_start = call_site.start();
    let call_site_file = call_site.file();

    let seed = hash_seed(
        &build_seed,
        &call_site_file,
        call_site_start.line as u32,
        call_site_start.column as u32,
    );

    StdRng::from_seed(seed)
}

fn emit_nops(count: usize) -> proc_macro2::TokenStream {
    let mut tokens = proc_macro2::TokenStream::new();

    for _ in 0..count {
        tokens.extend(quote! {
            unsafe {
                core::arch::asm!(
                    "nop",
                    options(nomem, nostack, preserves_flags),
                );
            }
        });
    }

    tokens
}

#[proc_macro]
pub fn rand_ops_old(input: TokenStream) -> TokenStream {
    let rng = parse_macro_input!(input as Expr);
    let mut rand_rng = build_rng(&rng);

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

#[proc_macro]
pub fn rand_ops(input: TokenStream) -> TokenStream {
    let rng = parse_macro_input!(input as Expr);
    let mut build_rng = build_rng(&rng);

    let base_check_val: u32 = build_rng.random();
    let check_inc_val: u32 = build_rng.random();
    let num_branches: u32 = build_rng.random_range(3..6);

    let loop_entry_nops = emit_nops(build_rng.random_range(0..=3));
    let before_break_nops = emit_nops(build_rng.random_range(0..=2));
    let after_break_nops = emit_nops(build_rng.random_range(0..=2));
    let init_nops = emit_nops(build_rng.random_range(0..=2));
    let post_check_1_nops = emit_nops(build_rng.random_range(0..=2));
    let post_check_2_nops = emit_nops(build_rng.random_range(0..=2));
    let post_check_3_nops = emit_nops(build_rng.random_range(0..=2));

    let region_size = (u32::MAX / num_branches).wrapping_add(1);
    let mut branches = proc_macro2::TokenStream::new();

    for branch_idx in 0..num_branches {
        let state_mul = build_rng.random::<u32>() | 1;
        let state_add = build_rng.random::<u32>();

        let before_nops = emit_nops(build_rng.random_range(0..=8));
        let after_nops = emit_nops(build_rng.random_range(0..=8));

        let branch_body = quote! {{
            #before_nops
            state = core::hint::black_box(
                state.wrapping_mul(#state_mul).wrapping_add(#state_add),
            );
            #after_nops
        }};

        let upper_bound = region_size.wrapping_mul(branch_idx + 1);

        if branch_idx == 0 {
            branches.extend(quote! {
                if core::hint::black_box(state < #upper_bound) {
                    #branch_body
                }
            });
        } else if branch_idx + 1 < num_branches {
            branches.extend(quote! {
                else if core::hint::black_box(state < #upper_bound) {
                    #branch_body
                }
            });
        } else {
            branches.extend(quote! {
                else {
                    #branch_body
                }
            });
        }
    }

    quote! {{
        let mut state = core::hint::black_box(#rng.word());
        // 1..1025 iterations
        let mut iteration_count = core::hint::black_box((#rng.word() & 0x2ff) + 1);
        let mut check = core::hint::black_box(#base_check_val);
        let mut i = core::hint::black_box(0u32);

        #init_nops

        loop {
            #loop_entry_nops
            #branches
            #before_break_nops

            if core::hint::black_box(i == iteration_count) {
                break;
            }

            #after_break_nops

            i = core::hint::black_box(i.wrapping_add(1));
            check = core::hint::black_box(check.wrapping_add(#check_inc_val));
        }

        #post_check_1_nops
        if core::hint::black_box(i != iteration_count || check != core::hint::black_box(
            (#base_check_val).wrapping_add(iteration_count.wrapping_mul(#check_inc_val)),
        )) {
            panic!();
        }

        #post_check_2_nops
        if core::hint::black_box(check != core::hint::black_box(
            (#base_check_val).wrapping_add(iteration_count.wrapping_mul(#check_inc_val)),
        ) || i != iteration_count) {
            panic!();
        }

        #post_check_3_nops
        if core::hint::black_box((i != iteration_count) | (check != core::hint::black_box(
            (#base_check_val).wrapping_add(iteration_count.wrapping_mul(#check_inc_val)),
        ))) {
            panic!();
        }
    }}
    .into()
}
