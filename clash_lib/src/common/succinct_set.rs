//! idea: https://github.com/openacid/succinct
//! impl: https://github.com/MetaCubeX/mihomo/blob/Meta/component/trie/domain_set.go
//! I have not idea what's going on here, just copy the code from above link.

use super::trie::StringTrie;

static COMPLEX_WILDCARD: u8 = b'+';
static WILDCARD: u8 = b'*';
static DOMAIN_STEP: u8 = b'.';

#[derive(Default)]
pub struct DomainSet {
    leaves: Vec<u64>,
    label_bit_map: Vec<u64>,
    labels: Vec<u8>,
    ranks: Vec<i32>,
    selects: Vec<i32>,
}

impl DomainSet {
    pub fn has(&self, key: &str) -> bool {
        let key = key
            .chars()
            .rev()
            .map(|x| x.to_ascii_lowercase())
            .collect::<Vec<_>>();
        let mut node_id = 0;
        let mut bm_idx = 0;

        struct Cursor {
            bm_idx: usize,
            index: usize,
        }

        let mut stack = vec![];

        #[derive(PartialEq)]
        enum State {
            Restart,
            Done,
        }

        let mut i: usize = 0;

        while i < key.len()
        // i++
        {
            let mut state = State::Restart;

            'ctrl: while state == State::Restart {
                state = State::Done;

                let c = key[i];
                loop
                // bm_idx++
                {
                    if get_bit(&self.label_bit_map, bm_idx) {
                        if !stack.is_empty() {
                            let cursor: Cursor = stack.pop().unwrap();
                            let next_node_id = count_zeros(
                                &self.label_bit_map,
                                &self.ranks,
                                cursor.bm_idx + 1,
                            );
                            let mut next_bm_idx = select_ith_one(
                                &self.label_bit_map,
                                &self.ranks,
                                &self.selects,
                                next_node_id - 1,
                            ) + 1;

                            let mut j = cursor.index;
                            while j < key.len() && key[j] != DOMAIN_STEP as char {
                                j += 1;
                            }
                            if j == key.len() {
                                if get_bit(&self.leaves, next_node_id as isize) {
                                    return true;
                                } else {
                                    state = State::Restart;
                                    continue 'ctrl;
                                }
                            }

                            while next_bm_idx - next_node_id < self.labels.len() {
                                if self.labels[next_bm_idx - next_node_id]
                                    == DOMAIN_STEP
                                {
                                    bm_idx = next_bm_idx as isize;
                                    node_id = next_node_id;
                                    i = j;

                                    state = State::Restart;
                                    continue 'ctrl;
                                }
                                next_bm_idx += 1;
                            }
                        }
                        return false;
                    }
                    
                    if self.labels.is_empty() {
                        return false;
                    }

                    if self.labels[bm_idx as usize - node_id] == COMPLEX_WILDCARD {
                        return true;
                    } else if self.labels[bm_idx as usize - node_id] == WILDCARD {
                        let cursor = Cursor {
                            bm_idx: bm_idx as usize,
                            index: i,
                        };
                        stack.push(cursor);
                    } else if self.labels[bm_idx as usize - node_id] == c as u8 {
                        break;
                    }

                    bm_idx += 1;
                }

                node_id = count_zeros(
                    &self.label_bit_map,
                    &self.ranks,
                    bm_idx as usize + 1,
                );
                bm_idx = select_ith_one(
                    &self.label_bit_map,
                    &self.ranks,
                    &self.selects,
                    node_id - 1,
                ) as isize
                    + 1;

                i += 1;
            }
        }

        get_bit(&self.leaves, node_id as isize)
    }

    #[cfg(test)]
    pub fn traverse<F>(&self, mut f: F)
    where
        F: FnMut(&String) -> bool,
    {
        self.keys(|x| f(&x.chars().rev().collect::<String>()));
    }
}

impl DomainSet {
    pub(crate) fn from_mrs_parts(
        leaves: Vec<u64>,
        label_bit_map: Vec<u64>,
        labels: Vec<u8>,
    ) -> Self {
        let mut set = Self {
            leaves,
            label_bit_map,
            labels,
            ranks: Vec::new(),
            selects: Vec::new(),
        };
        set.init();
        set
    }

    fn init(&mut self) {
        self.ranks.clear(); // Ensure clean state
        self.selects.clear();

        self.ranks.push(0);
        for i in 0..self.label_bit_map.len() {
            let n = self.label_bit_map[i].count_ones();
            // Ensure ranks has enough capacity or handle potential panic if last()
            // is called on empty vec
            let last_rank = self.ranks.last().copied().unwrap_or(0);
            self.ranks.push(last_rank + n as i32);
        }

        let mut n: u64 = 0; // bit counting
        let total_bits = self.label_bit_map.len() * 64;

        for i in 0..total_bits {
            let word_index = i >> 6;
            let bit_index = i & 63;

            if word_index >= self.label_bit_map.len() {
                break;
            }

            let is_set = (self.label_bit_map[word_index] >> bit_index) & 1;
            if is_set == 1 {
                if n & 63 == 0 {
                    // Check if it's the start of a select block (every 64th '1' bit)
                    self.selects.push(i as i32);
                }
                n += 1;
            }
        }
    }

    #[cfg(test)]
    fn keys<F>(&self, mut f: F)
    where
        F: FnMut(&String) -> bool,
    {
        let mut current_key = vec![];

        fn traverse<F>(
            this: &DomainSet,
            current_key: &mut Vec<char>,
            node_id: isize,
            bm_idx: isize,
            f: &mut F,
        ) -> bool
        where
            F: FnMut(&String) -> bool,
        {
            if get_bit(&this.leaves, node_id) && !f(&current_key.iter().collect()) {
                return false;
            }

            let mut bm_idx = bm_idx;

            loop {
                if get_bit(&this.label_bit_map, bm_idx) {
                    return true;
                }

                let next_label = this.labels[(bm_idx - node_id) as usize];
                current_key.push(next_label as char);
                let next_node_id = count_zeros(
                    &this.label_bit_map,
                    &this.ranks,
                    bm_idx as usize + 1,
                );
                let next_bm_idx = select_ith_one(
                    &this.label_bit_map,
                    &this.ranks,
                    &this.selects,
                    next_node_id - 1,
                ) + 1;

                if !traverse(
                    this,
                    current_key,
                    next_node_id as isize,
                    next_bm_idx as isize,
                    f,
                ) {
                    return false;
                }

                current_key.pop();

                bm_idx += 1;
            }
        }

        traverse(self, &mut current_key, 0, 0, &mut f);
    }
}

struct QElt {
    s: usize,
    e: usize,
    col: usize,
}

/// Convert a `StringTrie` to a `DomainSet`.
/// TODO: support loading from a binary file.
/// e.g. the so called 'mrs' file in the MiHoMo project.
impl<T> From<StringTrie<T>> for DomainSet {
    fn from(value: StringTrie<T>) -> Self {
        let mut keys = vec![];
        value.traverse(|key, _| {
            keys.push(key.chars().rev().collect::<String>());
            true
        });
        keys.sort();

        let mut rv = DomainSet::default();

        let mut l_idx = 0;

        let mut queue = vec![QElt {
            s: 0,
            e: keys.len(),
            col: 0,
        }];

        let mut i = 0;
        loop {
            let elt = &mut queue[i];
            if elt.col == keys[elt.s].len() {
                elt.s += 1;
                set_bit(&mut rv.leaves, i, true);
            }

            let mut j = elt.s;
            let e = elt.e;
            let col = elt.col;
            while j < e {
                let frm = j;
                while j < e && keys[j].chars().nth(col) == keys[frm].chars().nth(col)
                {
                    j += 1;
                }

                queue.push(QElt {
                    s: frm,
                    e: j,
                    col: col + 1,
                });
                // Safely handle potential None if keys[frm] is shorter than col
                if let Some(char_at_col) = keys[frm].chars().nth(col) {
                    rv.labels.push(char_at_col as u8);
                    set_bit(&mut rv.label_bit_map, l_idx, false);
                    l_idx += 1;
                }
            }

            set_bit(&mut rv.label_bit_map, l_idx, true);
            l_idx += 1;

            if i == queue.len() - 1 {
                break;
            }
            i += 1;
        }

        rv.init();

        rv
    }
}

fn get_bit(bm: &[u64], i: isize) -> bool {
    if bm.len() == 0 {
        return false;
    }
    bm[(i >> 6) as usize] & (1 << (i & 63) as usize) != 0
}

fn set_bit(bm: &mut Vec<u64>, i: usize, v: bool) {
    while i >> 6 >= (bm.len()) {
        bm.push(0);
    }
    bm[i >> 6] |= (v as u64) << (i & 63);
}

fn count_zeros(bm: &[u64], ranks: &[i32], i: usize) -> usize {
    i - ranks[i >> 6] as usize
        - (bm[i >> 6] & ((1 << (i & 63)) - 1)).count_ones() as usize
}

fn select_ith_one(bm: &[u64], ranks: &[i32], selects: &[i32], i: usize) -> usize {
    let base = selects[i >> 6] & !63;
    let mut find_ith_one = i as isize - ranks[base as usize >> 6] as isize;
    for (i, w) in bm.iter().enumerate().skip(base as usize >> 6) {
        let mut bit_idx = 0;
        let mut w = *w;
        while w > 0 {
            find_ith_one -= (w & 1) as isize;
            if find_ith_one < 0 {
                return (i << 6) + bit_idx;
            }

            let t0 = (w & !1).trailing_zeros();
            w = w.unbounded_shr(t0);
            bit_idx += t0 as usize;
        }
    }

    unreachable!("invalid data");
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    #[test]
    fn test_domain_set_complex_wildcard() {
        let mut tree = super::StringTrie::new();
        let domains = vec![
            "baidu.com",
            "google.com",
            "www.google.com",
            "test.a.net",
            "test.a.oc",
            "mijia cloud",
            ".qq.com",
            "+.cn",
        ];

        for d in domains {
            tree.insert(d, Arc::new(true));
        }

        let mut key_src = vec![];
        tree.traverse(|key, _| {
            key_src.push(key.to_owned());
            true
        });
        key_src.sort();

        let set = super::DomainSet::from(tree);
        assert!(set.has("test.cn"));
        assert!(set.has("cn"));
        assert!(set.has("mijia cloud"));
        assert!(set.has("test.a.net"));
        assert!(set.has("www.qq.com"));
        assert!(set.has("google.com"));
        assert!(!set.has("qq.com"));
        assert!(!set.has("www.baidu.com"));

        test_dump(&key_src, &set);
    }

    #[test]
    fn test_domain_set_wildcard() {
        let mut tree = super::StringTrie::new();
        let domains = vec![
            "*.*.*.baidu.com",
            "www.baidu.*",
            "stun.*.*",
            "*.*.qq.com",
            "test.*.baidu.com",
            "*.apple.com",
        ];

        for d in domains {
            tree.insert(d, Arc::new(true));
        }

        let mut key_src = vec![];
        tree.traverse(|key, _| {
            key_src.push(key.to_owned());
            true
        });
        key_src.sort();

        let set = super::DomainSet::from(tree);

        assert!(set.has("www.baidu.com"));
        assert!(set.has("test.test.baidu.com"));
        assert!(set.has("test.test.qq.com"));
        assert!(set.has("stun.ab.cd"));
        assert!(!set.has("test.baidu.com"));
        assert!(!set.has("www.google.com"));
        assert!(!set.has("a.www.google.com"));
        assert!(!set.has("test.qq.com"));
        assert!(!set.has("test.test.test.qq.com"));

        test_dump(&key_src, &set);
    }

    fn test_dump(data_src: &Vec<String>, set: &super::DomainSet) {
        let mut data_set = vec![];
        set.traverse(|key| {
            data_set.push(key.to_owned());
            true
        });
        data_set.sort();

        assert_eq!(data_src, &data_set);
    }
}
