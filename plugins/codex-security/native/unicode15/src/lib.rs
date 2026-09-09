//! The five Unicode primitives used by the pinned SRE engine, with Python 3.12 data.
#![no_std]

mod tables;

fn contains(table: &[(u32, u32)], c: char) -> bool {
    let index = table.partition_point(|(start, _)| *start <= c as u32);
    index != 0 && (c as u32) < table[index - 1].1
}

fn mapping(table: &[(u32, u32)], c: char) -> char {
    match table.binary_search_by_key(&(c as u32), |(cp, _)| *cp) {
        Ok(index) => char::from_u32(table[index].1).unwrap(),
        Err(_) => c,
    }
}

pub mod classify {
    pub fn is_alnum(c: char) -> bool {
        super::contains(super::tables::LETTERS, c) || super::contains(super::tables::NUMBERS, c)
    }

    pub fn is_decimal(c: char) -> bool {
        super::contains(super::tables::DIGITS, c)
    }

    pub fn is_space(c: char) -> bool {
        super::contains(super::tables::SPACES, c) || ('\u{1c}'..='\u{1f}').contains(&c)
    }
}

pub mod case {
    pub fn simple_lowercase(c: char) -> char {
        super::mapping(super::tables::LOWERCASE, c)
    }

    // SRE uses the first code point of CPython's full-uppercase mapping.
    pub fn simple_uppercase(c: char) -> char {
        super::mapping(super::tables::UPPERCASE, c)
    }
}
