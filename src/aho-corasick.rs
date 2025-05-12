//! <https://se.inf.ethz.ch/~meyer/publications/string/string_matching.pdf>

use std::collections::HashMap;

pub struct AhoCorasick {
    nodes: Vec<HashMap<u8, usize>>,

    output: Vec<Vec<usize>>,

    failure: Vec<usize>,
    inverse_failure: Vec<Vec<usize>>,
}

fn vec_set_add<T: Eq>(vec: &mut Vec<T>, value: T) {
    if !vec.contains(&value) {
        vec.push(value);
    }
}

fn vec_set_remove<T: Eq>(vec: &mut Vec<T>, value: T) {
    if let Some(pos) = vec.iter().position(|x| x == &value) {
        vec.swap_remove(pos);
    }
}

impl AhoCorasick {
    // N = sum of all search strings
    fn empty(preallocated_nodes: usize) -> Self {
        let mut result = Self {
            nodes: Vec::with_capacity(preallocated_nodes),

            output: Vec::new(),

            failure: Vec::new(),
            inverse_failure: Vec::new(),
        };

        result.nodes.push(HashMap::new());
        result.output.push(Vec::new());
        // F[0] is undefined
        result.failure.push(usize::MAX);
        result.inverse_failure.push(Vec::new());

        result
    }

    pub fn construct_with<'a>(
        sum_of_lengths: usize,
        strings: impl IntoIterator<Item = &'a [u8]>,
    ) -> Self {
        let mut result = Self::empty(sum_of_lengths);

        for (i, s) in strings.into_iter().enumerate() {
            result.t_insert(i, s);
        }

        // result.build_failure();

        // println!("strings={strings:#?}");
        // println!("trie table:");
        // for (i, s) in result.nodes.iter().enumerate() {
        //     print!("{i}:");
        //     for (&k, &v) in s.iter() {
        //         print!(" ['{}'] -> {v}", k.escape_ascii());
        //     }
        //     println!();
        // }

        // println!("output table:");
        // for (i, s) in result.output.iter().enumerate() {
        //     print!("{i}:");
        //     for &si in s {
        //         print!(" \"{}\"", strings[si].escape_ascii());
        //     }
        //     println!();
        // }

        // println!("failure table:");
        // for (i, s) in result.failure.iter().enumerate().skip(1) {
        //     print!("{i}: -> {s}");
        //     println!();
        // }

        result
    }

    fn t_get(&self, n: usize, c: u8) -> usize {
        self.nodes[n].get(&c).copied().unwrap_or(0)
    }

    fn t_set(&mut self, n: usize, np: usize, c: u8) {
        self.nodes[n].insert(c, np);
    }

    fn enter_child(&mut self, n: usize, np: usize, c: u8) {
        self.t_set(n, np, c);
        self.complete_failure(n, c, np);
        vec_set_add(&mut self.inverse_failure[self.failure[np]], np);
        self.complete_inverse(n, c, np);
    }

    fn enter_output(&mut self, n: usize, s: usize) {
        // workaround: "self is already borrowed"
        fn rec(output: &mut [Vec<usize>], inverse_failure: &[Vec<usize>], n: usize, s: usize) {
            vec_set_add(&mut output[n], s);

            for &x in &inverse_failure[n] {
                rec(output, inverse_failure, x, s)
            }
        }

        rec(&mut self.output, &self.inverse_failure, n, s)
    }

    fn t_insert(&mut self, i: usize, s: &[u8]) {
        let mut n = 0;
        for &c in s {
            let mut np = self.t_get(n, c);
            if np == 0 {
                np = self.nodes.len();

                self.nodes.push(HashMap::new());
                self.output.push(Vec::new());
                self.failure.push(usize::MAX);
                self.inverse_failure.push(Vec::new());

                self.enter_child(n, np, c);
            }
            n = np;
        }

        self.enter_output(n, i);
    }

    // fn build_failure(&mut self) {
    //     let mut q: VecDeque<usize> = VecDeque::new();

    //     for (_, &n) in self.nodes[0].iter() {
    //         q.push_back(n);
    //         self.failure[n] = 0;
    //     }

    //     while let Some(n) = q.pop_front() {
    //         q.reserve(self.nodes[n].len());
    //         let xd = self.nodes[n]
    //             .iter()
    //             .map(|(&a, &b)| (a, b))
    //             .collect::<Vec<_>>();
    //         for (chr, child) in xd {
    //             q.push_back(child);
    //             self.complete_failure(n, chr, child)
    //         }
    //     }
    // }

    fn complete_failure(&mut self, n: usize, c: u8, np: usize) {
        if n == 0 {
            self.failure[np] = 0;
            return;
        }

        let mut m = n;

        // println!("failure complete: n={n} c={c} np={np}");
        loop {
            m = self.failure[m];
            if m == 0 || self.t_get(m, c) != 0 {
                break;
            }
        }

        let mp = self.t_get(m, c);
        // println!("failure complete: n={n} c={c} np={np} m={m} failure is {mp}");
        self.failure[np] = mp;
        if let Ok([onp, omp]) = self.output.get_disjoint_mut([np, mp]) {
            onp.extend_from_slice(omp);
            onp.sort_unstable();
            onp.dedup();
        }
    }

    fn complete_inverse(&mut self, y: usize, c: u8, np: usize) {
        for xi in 0..self.inverse_failure[y].len() {
            let x = self.inverse_failure[y][xi];
            let xp = self.t_get(x, c);
            if xp != 0 {
                vec_set_remove(&mut self.inverse_failure[self.failure[xp]], xp);
                self.failure[xp] = np;
                vec_set_add(&mut self.inverse_failure[np], xp);
            } else {
                self.complete_inverse(x, c, np);
            }
        }
    }

    pub fn extend_by_one(&mut self, i: usize, s: &[u8]) {
        let mut n = 0;
        for &c in &s[..s.len() - 1] {
            n = self.t_get(n, c);
            if n == 0 {
                panic!("invalid use of AhoCorasick::extend_by_one")
            }
        }

        let Some(ri) = self.output[n].iter().position(|&l| l == i) else {
            panic!("invalid use of AhoCorasick::extend_by_one two")
        };

        self.output[n].swap_remove(ri);
        self.t_insert(i, s);
    }

    pub fn search(
        &mut self,
        text: &[u8],
        mut on_found: impl FnMut(&mut AhoCorasick, usize, usize),
    ) {
        let mut n = 0;
        for (i, &c) in text.iter().enumerate() {
            while n != 0 && self.t_get(n, c) == 0 {
                n = self.failure[n];
            }
            n = self.t_get(n, c);

            let v = self.output[n].to_vec();
            for s in v {
                on_found(self, i, s);
            }
        }
    }
}
