//! End-to-end test of the Option B (single-type) malicious-secure sketching protocol.
//!
//! Exercises the full client-encode + two-server-sketch + 2-round-MPC-verify path:
//! - An honest client (weight-1 DPF, consistent MAC) is ACCEPTED.
//! - A cheating client (tampered second component of one frontier slot, breaking the
//!   κ·x consistency) is REJECTED with overwhelming probability.

use counttree::prg::PrgSeed;
use counttree::sketch::SketchDPFKey;
use counttree::mpc::MulState;
use counttree::{FieldElm, Group, u32_to_bits};

fn run_one_level(
    keys: &[SketchDPFKey<FieldElm>; 2],
    seed: &PrgSeed,
    tamper_server0_slot1_kx: Option<FieldElm>,
) -> bool {
    let mut rng0 = seed.to_rng();
    let mut rng1 = seed.to_rng();

    // Both children of the root — both calls start from the same root state.
    let root0 = keys[0].eval_init();
    let root1 = keys[1].eval_init();

    let mut vec0 = Vec::new();
    let mut vec1 = Vec::new();
    for &bit in &[false, true] {
        let (_, x0, kx0) = keys[0].eval_bit(&root0, bit);
        let (_, x1, kx1) = keys[1].eval_bit(&root1, bit);
        vec0.push((x0, kx0));
        vec1.push((x1, kx1));
    }

    // Optional tamper: replace server 0's κx component at frontier slot 1 with `bogus`.
    // This breaks κ·x_1 = (server0_kx_1 + server1_kx_1), forcing the MAC check to fail
    // unless the client's κ happens to satisfy a degenerate condition.
    if let Some(bogus) = tamper_server0_slot1_kx {
        vec0[1].1 = bogus;
    }

    let sketch0 = keys[0].sketch_at(&vec0, &mut rng0);
    let sketch1 = keys[1].sketch_at(&vec1, &mut rng1);

    let level = 0usize;
    let st0 = MulState::new(false, keys[0].triples.clone(), &keys[0].mac_key, &keys[0].mac_key2, &sketch0, level);
    let st1 = MulState::new(true,  keys[1].triples.clone(), &keys[1].mac_key, &keys[1].mac_key2, &sketch1, level);

    let cor0 = st0.cor_share();
    let cor1 = st1.cor_share();
    let cor = MulState::cor(&cor0, &cor1);
    let out0 = st0.out_share(&cor);
    let out1 = st1.out_share(&cor);

    MulState::verify(&out0, &out1)
}

#[test]
fn sketch_accepts_honest_client() {
    let depth = 5u8;
    let alpha = u32_to_bits(depth, 21);
    let betas = vec![FieldElm::from(1u32); alpha.len()];
    let keys = SketchDPFKey::<FieldElm>::gen(&alpha, &betas);
    let seed = PrgSeed { key: [42u8; 16] };

    assert!(
        run_one_level(&keys, &seed, None),
        "honest weight-1 client must be accepted"
    );
}

#[test]
fn sketch_rejects_tampered_mac() {
    let depth = 5u8;
    let alpha = u32_to_bits(depth, 21);
    let betas = vec![FieldElm::from(1u32); alpha.len()];
    let keys = SketchDPFKey::<FieldElm>::gen(&alpha, &betas);
    let seed = PrgSeed { key: [42u8; 16] };

    // Add a non-zero garbage value to server 0's κx component at frontier slot 1.
    // After reconstruction κ·x_1 will be offset by `bogus`, breaking the MAC.
    let mut bogus = FieldElm::from(0x1234_5678u32);
    // Make it ≠ 0 mod MODULUS just to be safe.
    bogus.add(&FieldElm::from(1u32));

    assert!(
        !run_one_level(&keys, &seed, Some(bogus)),
        "tampered κx must be rejected by the malicious-secure sketch"
    );
}
