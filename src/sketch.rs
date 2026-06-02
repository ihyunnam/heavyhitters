use crate::dpf;
use crate::mpc;
use crate::{Group, Share};
use crate::prg::FromRng;
use crate::fastfield::FE;

use serde::{Deserialize, Serialize};

pub const TRIPLES_PER_LEVEL: usize = 3;

/// Embedding dimension carried by [`EmbCnt`]. Hardcoded here because the
/// `TwoTypeSketchDPFKey` path is only ever used with `EmbCnt` in
/// private-text-summary (`clustering_demo_indexed.rs`); see the note on
/// [`EmbCnt`].
pub const DIM: usize = 768;

/// `EmbCnt` — combined `(count, embedding)` DPF payload for `TwoTypeSketchDPFKey`.
///
/// This type exists **only** so `dpf::DPFKey::gen` has a concrete payload to
/// carry through the tree (private-text-summary manipulates `EmbCnt` values
/// during sketch-tree traversal). Inside counttree it is never arithmetically
/// operated on: the sketch checks read only the `count` field (an `FE`). The
/// `Group`/`Share` impls below exist to satisfy the `DPFKey` payload bounds —
/// `add`/`sub`/`negate` drive `gen`'s correction words; `mul`/`mul_lazy`/
/// `reduce` are required by the trait but never invoked on `EmbCnt`, so they
/// act on the `count` field only.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct EmbCnt {
    pub count: FE,
    pub embedding: Vec<u32>,
}

impl From<u32> for EmbCnt {
    #[inline]
    fn from(x: u32) -> Self {
        EmbCnt { count: FE::from(x), embedding: vec![0u32; DIM] }
    }
}

impl Group for EmbCnt {
    #[inline]
    fn zero() -> Self {
        EmbCnt { count: FE::new(0), embedding: vec![0u32; DIM] }
    }

    #[inline]
    fn one() -> Self {
        EmbCnt { count: FE::new(1), embedding: vec![1u32; DIM] }
    }

    #[inline]
    fn negate(&mut self) {
        self.count.negate();
        for a in self.embedding.iter_mut() {
            *a = a.wrapping_neg();
        }
    }

    #[inline]
    fn reduce(&mut self) {
        self.count.reduce();
    }

    #[inline]
    fn add(&mut self, other: &Self) {
        self.count.add(&other.count);
        if other.embedding.is_empty() {
            return;
        }
        for (a, b) in self.embedding.iter_mut().zip(other.embedding.iter()) {
            *a = a.wrapping_add(*b);
        }
    }

    #[inline]
    fn add_lazy(&mut self, other: &Self) {
        self.add(other);
    }

    #[inline]
    fn sub(&mut self, other: &Self) {
        self.count.sub(&other.count);
        if other.embedding.is_empty() {
            return;
        }
        for (a, b) in self.embedding.iter_mut().zip(other.embedding.iter()) {
            *a = a.wrapping_sub(*b);
        }
    }

    /// Never invoked on `EmbCnt` (only the `count` feeds the sketch checks);
    /// acts on the `count` field to keep the trait total.
    #[inline]
    fn mul(&mut self, other: &Self) {
        self.count.mul(&other.count);
    }

    #[inline]
    fn mul_lazy(&mut self, other: &Self) {
        self.count.mul_lazy(&other.count);
    }
}

impl crate::prg::FromRng for EmbCnt {
    fn from_rng(&mut self, rng: &mut (impl rand::Rng + rand_core::RngCore)) {
        <FE as crate::prg::FromRng>::from_rng(&mut self.count, rng);
        if self.embedding.len() != DIM {
            self.embedding = vec![0u32; DIM];
        }
        for x in self.embedding.iter_mut() {
            *x = rand::Rng::gen::<u32>(rng);
        }
    }
}

impl crate::Share for EmbCnt {}

/// Malicious-secure DPF (Section 4.2 of "Lightweight Techniques for Private Heavy Hitters", Boneh et al.).
///
/// Encodes the client's weight-one vector v̄ as (v̄, κ·v̄) for a random κ ∈ F.
/// The two servers can then run a constant-round sketching protocol to check that
/// the client-provided shares represent a vector of weight at most 1, without learning
/// the position or value of the non-zero entry.
///
/// Single-type variant (Option B): same field T used uniformly at every level of the
/// incremental DPF tree, including the leaves. This sacrifices the §4.3 extractability
/// guarantee (which uses a wider field at the leaves) but is sufficient for use cases
/// where the leaf semantic is "did this client cast its single vote" rather than "is
/// this leaf a member of some sparse set S".
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SketchDPFKey<T> {
    pub mac_key: T,
    pub mac_key2: T,
    key: dpf::DPFKey<(T, T)>,

    pub triples: Vec<mpc::TripleShare<T>>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SketchOutput<T> {
    // Compute
    //          <r, x>
    //          <r^2, x>
    //          <r, k.x>
    pub r_x: T,
    pub r2_x: T,
    pub r_kx: T,

    // Random values shared between the two
    // servers for taking a linear combination
    // of the sketch outputs.
    pub rand1: T,
    pub rand2: T,
    pub rand3: T,
}

impl<T> SketchOutput<T>
where
    T: crate::Group,
{
    pub fn zero() -> Self {
        SketchOutput {
            r_x: T::zero(),
            r2_x: T::zero(),
            r_kx: T::zero(),

            rand1: T::zero(),
            rand2: T::zero(),
            rand3: T::zero(),
        }
    }

    pub fn add(&mut self, other: &Self) {
        self.r_x.add(&other.r_x);
        self.r2_x.add(&other.r2_x);
        self.r_kx.add(&other.r_kx);
    }

    pub fn reduce(&mut self) {
        self.r_x.reduce();
        self.r2_x.reduce();
        self.r_kx.reduce();
    }
}

impl<T> SketchDPFKey<T>
where
    T: crate::Share + std::fmt::Debug + std::cmp::PartialEq,
{
    #[allow(clippy::needless_range_loop)]
    pub fn gen(alpha_bits: &[bool], values_in: &[T]) -> [SketchDPFKey<T>; 2] {
        debug_assert!(alpha_bits.len() == values_in.len());

        // For MAC key a, encode each level's value x as the pair (x, a·x).
        let mac_key = T::random();
        let (mac_key_sh0, mac_key_sh1) = mac_key.share();

        let mut mac_key2 = mac_key.clone();
        mac_key2.mul(&mac_key);
        let (mac_key2_sh0, mac_key2_sh1) = mac_key2.share();

        let mut values: Vec<(T, T)> = Vec::with_capacity(alpha_bits.len());
        for i in 0..alpha_bits.len() {
            let mut mac_val = values_in[i].clone();
            mac_val.mul(&mac_key);
            values.push((values_in[i].clone(), mac_val));
        }

        let (dpf_key0, dpf_key1) = dpf::DPFKey::gen(alpha_bits, &values);

        // Beaver triples for the per-level 2-round secure decision protocol.
        // TRIPLES_PER_LEVEL = 3 multiplications per level: one for the original
        // sketch check (z^2 - z* = 0), and two for verifying the MAC.
        let mut triples0 = vec![];
        let mut triples1 = vec![];
        for _i in 0..TRIPLES_PER_LEVEL * alpha_bits.len() {
            let t = mpc::TripleShare::new();
            triples0.push(t[0].clone());
            triples1.push(t[1].clone());
        }

        [
            SketchDPFKey {
                mac_key: mac_key_sh0,
                mac_key2: mac_key2_sh0,
                key: dpf_key0,
                triples: triples0,
            },
            SketchDPFKey {
                mac_key: mac_key_sh1,
                mac_key2: mac_key2_sh1,
                key: dpf_key1,
                triples: triples1,
            },
        ]
    }

    pub fn gen_from_str(s: &str) -> [SketchDPFKey<T>; 2] {
        let bits = crate::string_to_bits(s);
        let values = vec![T::one(); bits.len()];
        SketchDPFKey::gen(&bits, &values)
    }

    /// Non-incremental SketchDPFKey: the inner DPF carries the (value, κ·value)
    /// pair only at the leaf, all intermediate levels carry zero. Use this when
    /// you need a one-shot Hamming-weight-1 sketch over the full 2^depth domain
    /// (eval_full_domain reconstructs to (value, κ·value) at the target index and
    /// (0, 0) elsewhere) — typical for index-based histograms. With this layout
    /// `eval_full_domain` (which uses `eval_bit_seed_only` at intermediates) is
    /// correct, unlike `gen` which sets values at every level and requires a
    /// full eval_bit descent.
    ///
    /// Only `TRIPLES_PER_LEVEL` triples are produced (enough for one sketch check
    /// at level 0); MulState::new must be called with level=0.
    pub fn gen_non_incr(alpha_bits: &[bool], value_in: &T) -> [SketchDPFKey<T>; 2] {
        let mac_key = T::random();
        let (mac_key_sh0, mac_key_sh1) = mac_key.share();

        let mut mac_key2 = mac_key.clone();
        mac_key2.mul(&mac_key);
        let (mac_key2_sh0, mac_key2_sh1) = mac_key2.share();

        let mut mac_val = value_in.clone();
        mac_val.mul(&mac_key);
        let leaf_value: (T, T) = (value_in.clone(), mac_val);

        let (dpf_key0, dpf_key1) = dpf::DPFKey::gen_non_incr(alpha_bits, &leaf_value);

        let mut triples0 = vec![];
        let mut triples1 = vec![];
        for _ in 0..TRIPLES_PER_LEVEL {
            let t = mpc::TripleShare::new();
            triples0.push(t[0].clone());
            triples1.push(t[1].clone());
        }

        [
            SketchDPFKey {
                mac_key: mac_key_sh0,
                mac_key2: mac_key2_sh0,
                key: dpf_key0,
                triples: triples0,
            },
            SketchDPFKey {
                mac_key: mac_key_sh1,
                mac_key2: mac_key2_sh1,
                key: dpf_key1,
                triples: triples1,
            },
        ]
    }

    pub fn sketch_at(
        &self,
        vector_in: &[(T, T)],
        rand_stream: &mut impl rand::Rng,
    ) -> SketchOutput<T> {
        let mut out: SketchOutput<T> = SketchOutput::zero();

        out.rand1.from_rng(rand_stream);
        out.rand2.from_rng(rand_stream);
        out.rand3.from_rng(rand_stream);

        for v in vector_in {
            // Get r_i from PRG stream
            let mut sketch_r = T::zero();
            sketch_r.from_rng(rand_stream);

            // Compute r_i^2
            let mut sketch_r2 = sketch_r.clone();
            sketch_r2.mul_lazy(&sketch_r);

            // Compute
            //          <r, x>
            //          <r^2, x>
            //          <r, k.x>

            let (x, kx) = v;

            let mut tmp0 = x.clone();
            tmp0.mul_lazy(&sketch_r);

            let mut tmp1 = x.clone();
            tmp1.mul_lazy(&sketch_r2);

            let mut tmp2 = kx.clone();
            tmp2.mul_lazy(&sketch_r);

            out.r_x.add_lazy(&tmp0);
            out.r2_x.add_lazy(&tmp1);
            out.r_kx.add_lazy(&tmp2);
        }

        out.reduce();
        out
    }

    /// Evaluate the inner DPF at index `idx` and return the κ-MAC component
    /// (the second half of the (x, κ·x) pair).
    pub fn eval(&self, idx: &[bool]) -> T {
        debug_assert!(idx.len() <= self.key.domain_size());
        debug_assert!(!idx.is_empty());

        let (vals, _states) = self.key.eval(idx);
        vals.last().expect("eval returned no values").1.clone()
    }

    pub fn eval_bit(&self, state: &dpf::EvalState, dir: bool) -> (dpf::EvalState, T, T) {
        let (st, val) = self.key.eval_bit(state, dir);
        (st, val.0, val.1)
    }

    pub fn eval_init(&self) -> dpf::EvalState {
        self.key.eval_init()
    }

    /// Evaluate the inner (x, κ·x) DPF over the full domain. Used for
    /// regular-DPF (non-incremental) malicious-secure histogram writes: caller
    /// sketches the returned vector for a weight-1 + MAC check, then aggregates
    /// the on-path bin into the histogram.
    pub fn eval_full_domain(&self) -> Vec<(T, T)> {
        self.key.eval_full_domain()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TwoTypeSketchDPFKey<T> {    // U=FE when using with GlimpseKeyCollection
    pub mac_key: T,
    pub mac_key2: T,
    key: dpf::DPFKey<(EmbCnt, EmbCnt)>,
    pub triples: Vec<mpc::TripleShare<T>>,
}

// Concrete on `FE`: the per-level MAC is `κ·count` where `count` is the
// `EmbCnt`'s `FE` field, so the MAC key `κ` (and therefore `U`) is necessarily
// `FE`. The struct stays generic; only this functional `impl` is pinned to `FE`
// (the only instantiation private-text-summary uses).
impl TwoTypeSketchDPFKey<FE> {
    #[allow(clippy::needless_range_loop)]
    pub fn gen(alpha_bits: &[bool], values_in: &[EmbCnt]) -> [TwoTypeSketchDPFKey<FE>; 2] {
        debug_assert!(alpha_bits.len() == values_in.len());
        
        // For MAC key a, encode each level's value x as the pair (x, a·x).
        let mac_key = T::random();
        let (mac_key_sh0, mac_key_sh1) = mac_key.share();

        let mut mac_key2 = mac_key.clone();
        mac_key2.mul(&mac_key);
        let (mac_key2_sh0, mac_key2_sh1) = mac_key2.share();

        let mut values: Vec<(EmbCnt, EmbCnt)> = Vec::with_capacity(alpha_bits.len());
        for i in 0..alpha_bits.len() {
            let mut mac_val = values_in[i].count.clone();
            mac_val.mul(&mac_key);
            let payload = values_in[i].clone();
            let encoding = EmbCnt { count: mac_val, embedding: vec![0u32] };    // will not be used
            values.push((payload, encoding));
        }

        let (dpf_key0, dpf_key1) = dpf::DPFKey::gen(alpha_bits, &values);

        // Beaver triples for the per-level 2-round secure decision protocol.
        // TRIPLES_PER_LEVEL = 3 multiplications per level: one for the original
        // sketch check (z^2 - z* = 0), and two for verifying the MAC.
        let mut triples0 = vec![];
        let mut triples1 = vec![];
        for _i in 0..TRIPLES_PER_LEVEL * alpha_bits.len() {
            let t = mpc::TripleShare::new();
            triples0.push(t[0].clone());
            triples1.push(t[1].clone());
        }
        [
            TwoTypeSketchDPFKey {
                mac_key: mac_key_sh0,
                mac_key2: mac_key2_sh0,
                key: dpf_key0,
                triples: triples0,
            },
            TwoTypeSketchDPFKey {
                mac_key: mac_key_sh1,
                mac_key2: mac_key2_sh1,
                key: dpf_key1,
                triples: triples1,
            },
        ]
    }

    pub fn gen_from_str(s: &str) -> [TwoTypeSketchDPFKey<FE>; 2] {
        let bits = crate::string_to_bits(s);
        let values = vec![EmbCnt::one(); bits.len()];
        TwoTypeSketchDPFKey::gen(&bits, &values)
    }

    pub fn sketch_at(
        &self,
        vector_in: &[(FE, FE)],
        rand_stream: &mut impl rand::Rng,
    ) -> SketchOutput<FE> {
        let mut out: SketchOutput<FE> = SketchOutput::zero();

        out.rand1.from_rng(rand_stream);
        out.rand2.from_rng(rand_stream);
        out.rand3.from_rng(rand_stream);

        for v in vector_in {
            // Get r_i from PRG stream
            let mut sketch_r = FE::zero();
            sketch_r.from_rng(rand_stream);

            // Compute r_i^2
            let mut sketch_r2 = sketch_r.clone();
            sketch_r2.mul_lazy(&sketch_r);

            // Compute
            //          <r, x>
            //          <r^2, x>
            //          <r, k.x>

            let (x, kx) = v;

            let mut tmp0 = x.clone();
            tmp0.mul_lazy(&sketch_r);

            let mut tmp1 = x.clone();
            tmp1.mul_lazy(&sketch_r2);

            let mut tmp2 = kx.clone();
            tmp2.mul_lazy(&sketch_r);

            out.r_x.add_lazy(&tmp0);
            out.r2_x.add_lazy(&tmp1);
            out.r_kx.add_lazy(&tmp2);
        }

        out.reduce();
        out
    }

    /// Evaluate the inner DPF at index `idx` and return the κ-MAC component
    /// (the second half of the (x, κ·x) pair).
    pub fn eval(&self, idx: &[bool]) -> EmbCnt {
        debug_assert!(idx.len() <= self.key.domain_size());
        debug_assert!(!idx.is_empty());

        let (vals, _states) = self.key.eval(idx);
        vals.last().expect("eval returned no values").1.clone()
    }

    pub fn eval_bit(&self, state: &dpf::EvalState, dir: bool) -> (dpf::EvalState, EmbCnt, EmbCnt) {
        let (st, val) = self.key.eval_bit(state, dir);
        (st, val.0, val.1)
    }

    pub fn eval_init(&self) -> dpf::EvalState {
        self.key.eval_init()
    }

    /// Evaluate the inner (x, κ·x) DPF over the full domain. Used for
    /// regular-DPF (non-incremental) malicious-secure histogram writes: caller
    /// sketches the returned vector for a weight-1 + MAC check, then aggregates
    /// the on-path bin into the histogram.
    pub fn eval_full_domain(&self) -> Vec<(EmbCnt, EmbCnt)> {
        self.key.eval_full_domain()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::FieldElm;
    use crate::Group;

    #[test]
    fn sketch_add() {
        let a = SketchOutput {
            r_x: FieldElm::from(3),
            r2_x: FieldElm::from(4),
            r_kx: FieldElm::from(5),

            rand1: FieldElm::from(0),
            rand2: FieldElm::from(0),
            rand3: FieldElm::from(0),
        };

        let mut b = SketchOutput::<FieldElm>::zero();
        b.add(&a);

        assert_eq!(a, b);

        b.add(&a);
        assert_eq!(b.r_x, FieldElm::from(6));
        assert_eq!(b.r2_x, FieldElm::from(8));
        assert_eq!(b.r_kx, FieldElm::from(10));
    }

    #[test]
    fn mac_keys() {
        let nbits = 3;
        let alpha = crate::u32_to_bits(nbits, 3);
        // One β per level — same uniform value at every level of the tree.
        let betas = vec![
            FieldElm::from(7u32),
            FieldElm::from(17u32),
            FieldElm::from(2u32),
        ];
        let keys = SketchDPFKey::gen(&alpha, &betas);

        let mut mac = FieldElm::zero();
        let mut mac2 = FieldElm::zero();

        for i in 0..2 {
            mac.add(&keys[i].mac_key);
            mac2.add(&keys[i].mac_key2);
        }

        println!("mac  = {:?}", mac);
        println!("mac2 = {:?}", mac2);
        mac.mul(&mac.clone());
        assert_eq!(mac, mac2);
    }
}
