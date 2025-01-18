use std::num::NonZeroUsize;

use crate::aho_corasick::AhoCorasick;

#[cfg_attr(not(test), expect(dead_code))]
pub fn find_signature(bytes: &[u8], offset: usize) -> Option<NonZeroUsize> {
    let mut result = [None];
    find_signature_many(bytes, &[offset], &mut result, false);
    result[0]
}

pub fn find_signature_many(
    bytes: &[u8],
    offsets: &[usize],
    output: &mut [Option<NonZeroUsize>],
    prefix_only_if_sorted: bool,
) {
    find_signature_many_ex(bytes, bytes, offsets, output, prefix_only_if_sorted);
}

pub fn find_signature_many_ex(
    haystack: &[u8],
    source: &[u8],
    offsets: &[usize],
    output: &mut [Option<NonZeroUsize>],
    prefix_only_if_sorted: bool,
) {
    output.fill(Some(NonZeroUsize::new(1).unwrap()));
    let mut aho = AhoCorasick::construct_with(
        offsets.len(),
        offsets.iter().map(|&off| &source[off..off + 1]),
    );

    aho.search(haystack, |aho, end_idx, sidx| {
        let Some(current) = output[sidx] else {
            return;
        };
        let mut current = current.get();
        let offset = offsets[sidx];

        let idx = end_idx + 1 - current;

        let invalidate = if prefix_only_if_sorted {
            let start = sidx.checked_sub(1).map(|i| offsets[i]).unwrap_or(0);
            if start > idx {
                // sorted sequence broken
                idx < offset
            } else {
                (start..offset).contains(&idx)
            }
        } else {
            idx != offset
        };

        if invalidate {
            if haystack[idx + current - 1] == source[offset + current - 1] {
                current += 1;
                if offset + current >= haystack.len() {
                    // FIXME: this is wrong it just doesn't matter and I can't be bothered
                    //        to think about this condition right now
                    if offset == 0 && haystack.as_ptr() == source.as_ptr() {
                        // the signature is the whole string
                    } else {
                        current = 0;
                    }
                } else {
                    aho.extend_by_one(sidx, &source[offset..offset + current]);
                }
            }

            output[sidx] = NonZeroUsize::new(current);
        }
    });
}

#[cfg(test)]
const LOREM256: &[u8] = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nam id imperdiet lacus. Etiam lacus felis, finibus in euismod in, sagittis non urna. Cras et malesuada lectus. Sed porttitor turpis vitae sem aliquet, in lobortis dui pharetra. Mauris lobortis velit.";

#[test]
fn test_find_signature_single() {
    let cases = [
        (LOREM256, 2, Some(&b"rem"[..])),
        (LOREM256, 6, Some(b"ips")),
        (LOREM256, 224, Some(b"ph")),
        (b"aaaaaa", 1, None),
        (b"aaaaaa", 0, Some(b"aaaaaa")),
        (b"abbbaaa", 2, Some(b"bba")),
        (b"aaaazaaaa", 4, Some(b"z")),
    ];

    for (text, offset, expected) in cases {
        let slen = find_signature(text, offset);

        match (slen, expected) {
            (None, None) => (),
            (None, Some(_)) => panic!("failed to find signature"),
            (Some(_), None) => panic!("found non-existent signature"),
            (Some(len), Some(ex)) => {
                let found = &text[offset..offset + len.get()];
                println!("{}", found.escape_ascii());
                assert!(
                    found == ex,
                    "{} != {}",
                    found.escape_ascii(),
                    ex.escape_ascii()
                )
            }
        }
    }
}

#[test]
fn test_find_signature_many() {
    let cases = [
        (
            LOREM256,
            &[2, 6, 224][..],
            &[Some(&b"rem"[..]), Some(b"ips"), Some(b"ph")][..],
        ),
        (b"aaaaaa", &[1, 0], &[None, Some(b"aaaaaa")]),
        (b"abbbazabba", &[2, 5, 6], &[
            Some(b"bbaz"),
            Some(b"z"),
            None,
        ]),
    ];

    for (text, offsets, expected) in cases {
        let mut results = vec![None; offsets.len()];
        find_signature_many(text, offsets, &mut results[..], false);

        for ((&offset, result), &expected) in
            offsets.iter().zip(results.into_iter()).zip(expected.iter())
        {
            match (result, expected) {
                (None, None) => (),
                (None, Some(_)) => panic!("failed to find signature"),
                (Some(_), None) => panic!("found non-existent signature"),
                (Some(len), Some(ex)) => {
                    let found = &text[offset..offset + len.get()];
                    assert!(
                        found == ex,
                        "{} != {}",
                        found.escape_ascii(),
                        ex.escape_ascii()
                    )
                }
            }
        }
    }
}
