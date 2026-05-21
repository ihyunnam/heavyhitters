use crate::dpf;
use crate::prg;
use crate::sketch;

use rayon::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone)]
struct TreeNode<T> {
    path: Vec<bool>,
    value: T,
    key_states: Vec<dpf::EvalState>,
    key_values: Vec<(T, T)>,
}

unsafe impl<T> Send for TreeNode<T> {}
unsafe impl<T> Sync for TreeNode<T> {}

/// Server-side state for the malicious-secure subset-histogram / heavy-hitters protocol.
///
/// Single-type variant (Option B): same field type T at every level of the tree,
/// including the leaves. See `sketch.rs` for the trade-off vs. the original
/// two-type construction.
#[derive(Clone)]
pub struct KeyCollection<T> {
    depth: usize,
    pub keys: Vec<(bool, sketch::SketchDPFKey<T>)>,
    frontier: Vec<TreeNode<T>>,

    rand_stream: prg::PrgStream,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Result<T> {
    pub path: Vec<bool>,
    pub value: T,
}

impl<T> KeyCollection<T>
where
    T: crate::Share
        + std::fmt::Debug
        + std::cmp::PartialOrd
        + std::convert::From<u32>
        + Send
        + Sync,
{
    pub fn new(seed: &prg::PrgSeed, depth: usize) -> KeyCollection<T> {
        KeyCollection::<T> {
            depth,
            keys: vec![],
            frontier: vec![],
            rand_stream: seed.to_rng(),
        }
    }

    pub fn add_key(&mut self, key: sketch::SketchDPFKey<T>) {
        assert_eq!(key.triples.len(), sketch::TRIPLES_PER_LEVEL * self.depth);
        self.keys.push((true, key));
    }

    pub fn tree_init(&mut self) {
        let mut root = TreeNode::<T> {
            path: vec![],
            value: T::zero(),
            key_states: vec![],
            key_values: vec![],
        };

        for k in &self.keys {
            root.key_states.push(k.1.eval_init());
            root.key_values.push((T::zero(), T::zero()));
        }

        self.frontier.clear();
        self.frontier.push(root);
    }

    fn make_tree_node(&self, parent: &TreeNode<T>, dir: bool) -> TreeNode<T> {
        let (key_states, key_values): (Vec<dpf::EvalState>, Vec<(T, T)>) = self
            .keys
            .par_iter()
            .enumerate()
            .map(|(i, key)| {
                let (st, out0, out1) = key.1.eval_bit(&parent.key_states[i], dir);
                (st, (out0, out1))
            })
            .unzip();

        let mut child_val = T::zero();
        for (i, v) in key_values.iter().enumerate() {
            // Add in only live values
            if self.keys[i].0 {
                child_val.add_lazy(&v.0);
            }
        }
        child_val.reduce();

        let mut child = TreeNode::<T> {
            path: parent.path.clone(),
            value: child_val,
            key_states,
            key_values,
        };

        child.path.push(dir);

        child
    }

    pub fn tree_crawl(&mut self) -> Vec<T> {
        println!("Crawl");
        let next_frontier = self
            .frontier
            .par_iter()
            .map(|node| {
                assert!(node.path.len() <= self.depth);
                let child0 = self.make_tree_node(node, false);
                let child1 = self.make_tree_node(node, true);

                vec![child0, child1]
            })
            .flatten()
            .collect::<Vec<TreeNode<T>>>();

        let values = next_frontier
            .iter()
            .map(|node| node.value.clone())
            .collect::<Vec<T>>();
        println!("...done");

        self.frontier = next_frontier;
        values
    }

    pub fn tree_sketch_frontier(
        &mut self,
        start: usize,
        end: usize,
    ) -> Vec<sketch::SketchOutput<T>> {
        println!("Sketching frontier {:?} to {:?}", start, end);
        // sketch_vectors[i][j] = { j'th value expanded from i'th key }

        assert!(start < end);
        assert!(end <= self.keys.len());

        let mut sketch_vectors = Vec::with_capacity(end - start);
        for _ in &self.keys[start..end] {
            sketch_vectors.push(Vec::with_capacity(self.frontier.len()));
        }

        for node in &self.frontier {
            for (i, vec) in sketch_vectors.iter_mut().enumerate() {
                vec.push(node.key_values[start + i].clone());
            }
        }

        let out = self
            .keys[start..end]
            .par_iter()
            .enumerate()
            .map(|(i, k)| {
                let mut stream = self.rand_stream.clone();
                k.1.sketch_at(&sketch_vectors[i], &mut stream)
            })
            .collect::<Vec<sketch::SketchOutput<T>>>();

        println!("... Done");

        out
    }

    pub fn apply_sketch_results(&mut self, res: &[bool]) {
        assert_eq!(res.len(), self.keys.len());

        // Remove invalid keys
        for (i, alive) in res.iter().enumerate() {
            self.keys[i].0 &= alive;
        }
    }

    pub fn tree_prune(&mut self, alive_vals: &[bool]) {
        assert_eq!(alive_vals.len(), self.frontier.len());

        // Remove from back to front to preserve indices
        for i in (0..alive_vals.len()).rev() {
            if !alive_vals[i] {
                self.frontier.remove(i);
            }
        }
    }

    pub fn keep_values(nclients: usize, threshold: &T, vals0: &[T], vals1: &[T]) -> Vec<bool> {
        assert_eq!(vals0.len(), vals1.len());

        let nclients = T::from(nclients as u32);
        let mut keep = vec![];
        for i in 0..vals0.len() {
            let mut v = T::zero();
            v.add(&vals0[i]);
            v.add(&vals1[i]);

            debug_assert!(v <= nclients);

            // Keep nodes that are above threshold
            keep.push(v >= *threshold);
        }

        keep
    }

    pub fn final_shares(&self) -> Vec<Result<T>> {
        let mut alive = vec![];
        for n in &self.frontier {
            alive.push(Result::<T> {
                path: n.path.clone(),
                value: n.value.clone(),
            });

            println!("Final {:?}, value={:?}", n.path, n.value);
        }

        alive
    }

    pub fn final_values(res0: &[Result<T>], res1: &[Result<T>]) -> Vec<Result<T>> {
        assert_eq!(res0.len(), res1.len());

        let mut out = vec![];
        for i in 0..res0.len() {
            assert_eq!(res0[i].path, res1[i].path);

            let mut v = T::zero();
            v.add(&res0[i].value);
            v.add(&res1[i].value);

            out.push(Result {
                path: res0[i].path.clone(),
                value: v,
            });
        }

        out
    }
}
