use counttree::dpf::*;
use counttree::*;
use ark_bn254::Fr;
// use ark_std::rand::thread_rng;
use ark_ff::{PrimeField, BigInteger};

#[test]
fn dpf_complete() {
    const NBITS: u8 = 8;
    let alpha = u32_to_bits(NBITS, 2);
    println!("alpha {:?}", alpha);
    let betas = vec![FieldElm::from(1), FieldElm::from(2), FieldElm::from(3), FieldElm::from(4), FieldElm::from(5), FieldElm::from(6), FieldElm::from(7)];
    let beta_last = FieldElm::from(8);
    let (key0, key1) = DPFKey::gen(&alpha, &betas, &beta_last);
    let leaf_level_indices = [0,2,3,5]; // We want to select 2
    
    let mut alpha_eval_collected0 = Vec::new();
    let mut alpha_eval_collected1 = Vec::new();
    let mut level_eval0: [FieldElm; NBITS as usize] = [FieldElm::zero(),FieldElm::zero(),FieldElm::zero(),FieldElm::zero(),FieldElm::zero(),FieldElm::zero(),FieldElm::zero(),FieldElm::zero()];
    let mut level_eval1: [FieldElm; NBITS as usize] = [FieldElm::zero(),FieldElm::zero(),FieldElm::zero(),FieldElm::zero(),FieldElm::zero(),FieldElm::zero(),FieldElm::zero(),FieldElm::zero()];
    
    for i in leaf_level_indices {
        let alpha_eval = u32_to_bits(NBITS, i);
        println!("alpha_eval {:?}", alpha_eval);
        for j in 0..((NBITS - 1) as usize) {  // NBITS - 1 skips root (no need for us because 1. reversed and 2. root not included)
            if j < 2 {
                continue;
            }
            println!("j {:?}", j);

            let mut skip = false;

            // SERVER ZERO
            if !alpha_eval_collected0.contains(&alpha_eval[0..j-1].to_vec()) {
                let mut eval0 = key0.eval(&alpha_eval[0..j].to_vec());
                alpha_eval_collected0.push(alpha_eval[0..j-1].to_vec());  
                level_eval0[j-2].add(&eval0.0[j-2]);
                println!("added to {:?}", level_eval0[j-2]);
            } else {
                skip = true;
            }

            // SERVER ONE
            if !alpha_eval_collected1.contains(&alpha_eval[0..j-1].to_vec()) {
                let mut eval1 = key1.eval(&alpha_eval[0..j].to_vec());
                alpha_eval_collected1.push(alpha_eval[0..j-1].to_vec());  
                level_eval1[j-2].add(&eval1.0[j-2]);
            } else {
                skip = true;
            }
            if skip { continue; }
           
            level_eval0[j-2].add(&level_eval1[j-2]);
            let tmp = level_eval0[j-2].clone();
            if alpha[0..j-1] == alpha_eval[0..j-1] {
                println!("tmp {:?}", tmp);
                println!("betas[j-2] {:?}", betas[j-2]);
                assert_eq!(
                    betas[j-2],
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
