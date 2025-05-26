use counttree::dpf::*;
use counttree::*;
use ark_bn254::Fr;
// use ark_std::rand::thread_rng;
use ark_ff::{PrimeField, BigInteger};
use primitive_types::U512;

#[test]
fn dpf_complete() {
    const NBITS: usize = 259;
    let alpha = u512_to_bits(NBITS, U512::from(2));
    // println!("alpha {:?}", alpha);
    let mut betas = vec![FieldElmBn254::one(); 258];
    let beta_last = FieldElmBn254::one();
    let (key0, key1) = DPFKey::gen(&alpha, &betas, &beta_last);
    let leaf_level_indices = [0,2,3,5]; // We want to select 2
    let fr = Fr::from(3);
    let fr_FieldElmBn254 = FieldElmBn254::from(fr);
    println!("fr {:?}", fr);
    // let fr_bigint = num_bigint::BigUint::from_bytes_be(&fr.into_bigint().to_bytes_be());
    // let fr_FieldElmBn254 = FieldElmBn254::from(fr_bigint);
    let mut alpha_eval_collected0 = Vec::new();
    let mut alpha_eval_collected1 = Vec::new();
    let mut level_eval0: Vec<FieldElmBn254> = vec![FieldElmBn254::zero(); NBITS];
    // [FieldElmBn254::zero(),FieldElmBn254::zero(),FieldElmBn254::zero(),FieldElmBn254::zero(),FieldElmBn254::zero(),FieldElmBn254::zero()];
    let mut level_eval1: Vec<FieldElmBn254> = vec![FieldElmBn254::zero(); NBITS];
    
    for i in leaf_level_indices {
        let alpha_eval = u512_to_bits(NBITS, U512::from(i));
        // println!("alpha_eval {:?}", alpha_eval);
        for j in 0..((NBITS - 1) as usize) {  // NBITS - 1 skips root (no need for us because 1. reversed and 2. root not included)
            if j < 2 {
                continue;
            }
            // println!("j {:?}", j);

            let mut skip = false;

            // SERVER ZERO
            if !alpha_eval_collected0.contains(&alpha_eval[0..j-1].to_vec()) {
                // println!("alpha_eval[0..j-1].to_vec() {:?}", alpha_eval[0..j-1].to_vec());
                let mut eval0 = key0.eval(&alpha_eval[0..j].to_vec());
                alpha_eval_collected0.push(alpha_eval[0..j-1].to_vec());  
                // eval0.0[j-2].mul(&fr_FieldElmBn254);
                level_eval0[j-2].add(&eval0.0[j-2]);
                
                // println!("added to {:?}", level_eval0[j-2]);
            } else {
                skip = true;
            }

            // SERVER ONE
            if !alpha_eval_collected1.contains(&alpha_eval[0..j-1].to_vec()) {
                let mut eval1 = key1.eval(&alpha_eval[0..j].to_vec());
                alpha_eval_collected1.push(alpha_eval[0..j-1].to_vec());  
                // eval1.0[j-2].mul(&fr_FieldElmBn254);
                level_eval1[j-2].add(&eval1.0[j-2]);
            } else {
                skip = true;
            }
            if skip { continue; }
           
            level_eval0[j-2].add(&level_eval1[j-2]);
            let tmp = level_eval0[j-2].clone();
            // tmp.mul(&fr_FieldElmBn254);
            if alpha[0..j-1] == alpha_eval[0..j-1] {
                println!("tmp {:?}", tmp);
                betas[j-2].mul(&fr_FieldElmBn254);
                println!("betas[j-2] {:?}", betas[j-2]);
                assert_eq!(
                    betas[j-2],
                    tmp,
                    "[Level {:?}] Value incorrect at {:?}",
                    j,
                    alpha_eval
                );
            } else {
                assert_eq!(FieldElmBn254::zero(), tmp, "[Level {:?}] Value incorrect at {:?}",
                j, alpha_eval);
            }
        
        }

    // for (mut zero, one) in level_eval0.into_iter().zip(&level_eval1) {
    //     zero.add(one);
    //     println!("zero {:?}", zero);
    // }

    // level_eval0[j-2].add(&level_eval1[j-2]);
    // let tmp = level_eval0[j-2].clone();
    // if alpha[0..j-1] == alpha_eval[0..j-1] {
    //     println!("tmp {:?}", tmp);
    //     println!("betas[j-2] {:?}", betas[j-2]);
    //     assert_eq!(
    //         betas[j-2],
    //         tmp,
    //         "[Level {:?}] Value incorrect at {:?}",
    //         j,
    //         alpha_eval
    //     );
    // } else {
    //     assert_eq!(FieldElmBn254::zero(), tmp, "[Level {:?}] Value incorrect at {:?}",
    //     j, alpha_eval);
    // }
    }
    for i in 0..NBITS {
        level_eval0[i as usize].add(&level_eval1[i as usize]);
        let leaf1 = bincode::serialize(&level_eval0[i as usize]).expect("Failed to serialize DPF eval (leaf sum).");
        let leaf1_deserial: FieldElmBn254 = bincode::deserialize(&leaf1).unwrap();
        let leaf1_fr = Fr::from(leaf1_deserial.value);
        println!("fr recovered {:?}", leaf1_fr);
        // println!("should be tmp {:?}", level_eval0[i as usize]);
    }
}
