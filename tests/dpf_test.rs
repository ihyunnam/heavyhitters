use counttree::dpf::*;
use counttree::*;

#[test]
fn dpf_complete() {
    let nbits = 5;
    let alpha = u32_to_bits(nbits, 21);
    println!("alpha {:?}", alpha);
    let betas = vec![
        FieldElmBn254::from(7u32),
        FieldElmBn254::from(17u32),
        FieldElmBn254::from(2u32),
        FieldElmBn254::from(0u32),
    ];
    let beta_last = fastfield::FE::from(32u32);
    let (key0, key1) = DPFKey::gen(&alpha, &betas, &beta_last);

    for i in 0..(1 << nbits) {
        let alpha_eval = u32_to_bits(nbits, i);

        println!("Alpha: {:?}", alpha);
        for j in 0..((nbits-1) as usize) {  // nbits - 1 skips root (no need for us because 1. reversed and 2. root not included)
            if j < 2 {
                continue;
            }

            let eval0 = key0.eval(&alpha_eval[0..j].to_vec());
            let eval1 = key1.eval(&alpha_eval[0..j].to_vec());
            let mut tmp = FieldElmBn254::zero();

            tmp.add(&eval0.0[j - 2]);
            tmp.add(&eval1.0[j - 2]);
            println!("[{:?}] Tmp {:?} = {:?}", alpha_eval, j, tmp);
            if alpha[0..j-1] == alpha_eval[0..j-1] {
                assert_eq!(
                    betas[j - 2],
                    tmp,
                    "[Level {:?}] Value incorrect at {:?}",
                    j,
                    alpha_eval
                );
            } else {
                assert_eq!(FieldElmBn254::zero(), tmp);
            }
        }
    }
}
