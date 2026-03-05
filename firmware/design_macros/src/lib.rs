use proc_macro::TokenStream;

use blake2::{Blake2s256, Digest};
use quote::quote;
use rand::{RngExt, SeedableRng, rngs::StdRng};
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

fn generate_rand_ops_body_inner(
    nop_index: usize,
    num_nops: usize,
    total_num_states: usize,
    state_positions: &[(usize, usize)],
    build_rng: &mut StdRng,
) -> proc_macro2::TokenStream {
    if state_positions.len() == 0 {
        // there be remaining nops, but they are useless, don't emit them
        return proc_macro2::TokenStream::new();
    }

    // +1 means last region will end at at least u32::MAX
    let region_size = (u32::MAX / total_num_states as u32) + 1;
    let (nop_position, state_number) = state_positions[0];
    assert!(nop_position >= nop_index && nop_position <= num_nops);

    let nops = emit_nops(nop_position - nop_index);
    let body = generate_rand_ops_body_inner(
        nop_position,
        num_nops,
        total_num_states,
        &state_positions[1..],
        build_rng,
    );

    let region_start = region_size * state_number as u32;
    let region_end = if state_number == total_num_states - 1 {
        u32::MAX
    } else {
        // -1 since we compare with <=
        region_size * ((state_number as u32) + 1) - 1
    };

    // TODO: better state transition function
    let state_mul = build_rng.random::<u32>() | 1;
    let state_add = build_rng.random::<u32>();

    quote! {{
        #nops
        if core::hint::black_box((state >= #region_start) && (state <= #region_end)) {
            state = core::hint::black_box(state.wrapping_mul(#state_mul).wrapping_add(#state_add));
        } else {
            #body
        }
    }}
    .into()
}

fn generate_rand_ops_body(build_rng: &mut StdRng) -> proc_macro2::TokenStream {
    let num_nops = build_rng.random_range(24..80);
    let num_states = build_rng.random_range(4..10);

    let mut state_ranges = (0..num_states)
        .map(|i| (build_rng.random_range(0..=num_nops), i))
        .collect::<Vec<_>>();
    state_ranges.sort_by_key(|(position, _)| *position);

    generate_rand_ops_body_inner(0, num_nops, num_states, &state_ranges, build_rng)
}

#[proc_macro]
pub fn rand_ops(input: TokenStream) -> TokenStream {
    let rng = parse_macro_input!(input as Expr);
    let mut build_rng = build_rng(&rng);

    let base_check_val: u32 = build_rng.random();
    let check_inc_val: u32 = build_rng.random();

    let init_nops = emit_nops(build_rng.random_range(0..=5));
    let post_check_1_nops = emit_nops(build_rng.random_range(0..=3));
    let post_check_2_nops = emit_nops(build_rng.random_range(0..=3));
    let post_check_3_nops = emit_nops(build_rng.random_range(0..=3));

    let loop_body = generate_rand_ops_body(&mut build_rng);

    quote! {{
        let mut rng = #rng;
        let mut state = core::hint::black_box(rng.word());
        // 16..1040 iterations
        let iteration_count = core::hint::black_box((rng.word() & 0x2ff) + 16);
        let mut check = core::hint::black_box(#base_check_val);
        let mut i = core::hint::black_box(0u32);

        // TODO: idk if keeping init nops is needed, no branches until after randomized loop body which could be glitched
        // maybe it is still good ot have random nops ran one iteration,  may be hard to measure exactly what they are
        #init_nops

        loop {
            #loop_body

            if core::hint::black_box(i == iteration_count) {
                break;
            }

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

#[proc_macro]
pub fn rand_ops_small(input: TokenStream) -> TokenStream {
    let rng = parse_macro_input!(input as Expr);
    let mut build_rng = build_rng(&rng);

    let base_check_val: u32 = build_rng.random();
    let check_inc_val: u32 = build_rng.random();

    let init_nops = emit_nops(build_rng.random_range(0..=2));
    let loop_body_nops = emit_nops(build_rng.random_range(0..=10));
    let post_check_1_nops = emit_nops(build_rng.random_range(0..=2));

    quote! {{
        // 16..1040 iterations
        let mut iteration_count = core::hint::black_box((#rng.word() & 0x2ff) + 16);
        let mut check = core::hint::black_box(#base_check_val);
        let mut i = core::hint::black_box(0u32);

        #init_nops

        loop {
            #loop_body_nops

            if core::hint::black_box(i == iteration_count) {
                break;
            }

            i = core::hint::black_box(i.wrapping_add(1));
            check = core::hint::black_box(check.wrapping_add(#check_inc_val));
        }

        #post_check_1_nops
        if core::hint::black_box(i != iteration_count || check != core::hint::black_box(
            (#base_check_val).wrapping_add(iteration_count.wrapping_mul(#check_inc_val)),
        )) {
            panic!();
        }

    }}
    .into()
}
