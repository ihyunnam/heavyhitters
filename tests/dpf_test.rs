use counttree::dpf::*;
use counttree::*;
use ark_bn254::Fr;
// use ark_std::rand::thread_rng;
use ark_ff::{PrimeField, BigInteger};

#[test]
fn dpf_complete() {
    let nbits = 5;
    let alpha = u32_to_bits(nbits, 21);
    let betas = vec![
        FieldElm::from(1),
        FieldElm::from(1),
        FieldElm::from(1),
        FieldElm::from(1),
    ];
    // let beta_last = fastfield::FE::from(32u32);
    let beta_last = FieldElm::from(1);
    // also passes for 'let beta_last = FieldElm::from(1u32);'
    let (key0, key1) = DPFKey::gen(&alpha, &betas, &beta_last);
    // let mut rng: rand::prelude::ThreadRng = rand::thread_rng();
    let fr = Fr::from(1<<31);
    println!("fr {:?}", fr);
    let fr_bigint = num_bigint::BigUint::from_bytes_be(&fr.into_bigint().to_bytes_be());
    let fr_fieldelm: FieldElm = FieldElm::from(fr_bigint);
    // println!("fr arkworks bigint {:?}", fr.into_bigint().to_string());
    // println!("fr biguint {:?}", fr_bigint);  // CONFIRMED SAME 
    for i in 0..(1 << nbits) {
        let alpha_eval = u32_to_bits(nbits, i);

        println!("Alpha: {:?}", alpha);
        for j in 0..((nbits-1) as usize) {  // nbits - 1 skips root (no need for us because 1. reversed and 2. root not included)
            if j < 2 {
                continue;
            }

            let mut eval0 = key0.eval(&alpha_eval[0..j].to_vec());
            let mut eval1 = key1.eval(&alpha_eval[0..j].to_vec());
            let mut tmp = FieldElm::zero();
            // println!("tmp zero {:?}", tmp.value);    // CHECKED CORRECT

            // println!("SUM {:?}", eval0.0[j - 2].value + eval1.0[j - 2].value);
            // let eval0_fr = eval0.0[j - 2].value
            eval0.0[j - 2].mul(&fr_fieldelm);
            tmp.add(&eval0.0[j - 2]);    // Modified in place
            println!("eval0.0[j - 2] {:?}", eval0.0[j - 2]);
            eval1.0[j - 2].mul(&fr_fieldelm);
            tmp.add(&eval1.0[j - 2]);   // Modified in place
            println!("eval1.0[j - 2] {:?}", eval1.0[j - 2]);
            // println!("after add {:?}", tmp.value);
            println!("[{:?}] Tmp {:?} = {:?}", alpha_eval, j, tmp);
            let mut betas_in_place_mul: FieldElm = betas[j - 2].clone();
            betas_in_place_mul.mul(&fr_fieldelm);
            println!("betas_in_place_mul {:?}", betas_in_place_mul);
            // let recover_fr = Fr::from(betas_in_place_mul.clone().value); // CHECKED CORRECT
            
            // Sending as bytes // CHECKED CORRECT
            // let serial = bincode::serialize(&betas_in_place_mul.clone()).unwrap();
            // let deserial: FieldElm = bincode::deserialize(&serial).unwrap();
            // println!("deserialized betas in place mul {:?}", deserial);
            // let recover_fr = Fr::from(deserial.value); // CHECKED CORRECT
            // println!("recover fr {:?}", recover_fr);
            if alpha[0..j-1] == alpha_eval[0..j-1] {
                assert_eq!(
                    betas_in_place_mul,
                    tmp,
                    "[Level {:?}] Value incorrect at {:?}",
                    j,
                    alpha_eval
                );
            } else {
                assert_eq!(FieldElm::zero(), tmp, "[Level {:?}] Value incorrect at {:?}",
                j, alpha_eval);
            }
        }
    }
}
