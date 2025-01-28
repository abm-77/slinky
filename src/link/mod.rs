use std::collections::HashMap;

use crate::elf::{ElfFile, ElfSection, ElfSectionType};

struct Linker {}

#[derive(Debug, Clone)]
struct LinkerError;

// NOTE: we assume all alignments are a power of two
pub fn align_up(v: usize, a: usize) -> usize {
    assert!(a.is_power_of_two());
    (v + a - 1) & !(a - 1)
}

impl Linker {
    pub fn link(files: Vec<ElfFile>) -> Result<ElfFile, LinkerError> {
        let res = files.get(0).unwrap().clone();
        Ok(res)
    }

    fn link_files(&self, a: ElfFile, b: ElfFile) -> Result<ElfFile, LinkerError> {
        let mut new_file = a.clone();

        // section name to index
        let mut section2idx: HashMap<&String, usize> = a
            .sections
            .iter()
            .enumerate()
            .map(|(i, s)| (&s.name, i))
            .collect();

        // symbol name to index
        let mut symbol2idx: HashMap<&String, usize> = a
            .symbols
            .iter()
            .enumerate()
            .map(|(i, s)| (&s.name, i))
            .collect();

        // section index to merged index
        let mut merged_section_idx: HashMap<usize, usize> = HashMap::new();

        // symbol index to merged index
        let mut merged_symbol_idx: HashMap<usize, usize> = HashMap::new();

        // section index to value offset in bytes
        let mut value_offsets: HashMap<usize, usize> = HashMap::new();

        // we do not want to merged the symtab, strtab, or rela sections
        let sections_to_process = b.sections.iter().filter(|s| {
            s.header.ty != ElfSectionType::SYMTAB
                && s.header.ty != ElfSectionType::STRTAB
                && s.header.ty != ElfSectionType::RELA
        });

        for (idx, section) in sections_to_process.enumerate() {
            if let Some(existing_idx) = section2idx.get(&section.name) {
                let existing_section = &mut new_file.sections[*existing_idx];
                let offset = self.merge_sections(existing_section, &section);
                value_offsets.insert(idx, offset);
                merged_section_idx.insert(idx, *existing_idx);
            } else {
                section2idx.insert(&section.name, new_file.sections.len());
                merged_section_idx.insert(idx, new_file.sections.len());
                value_offsets.insert(idx, 0);
                new_file.sections.push(section.clone());
            }
        }

        for (idx, symbol) in b.symbols.iter().enumerate() {
            if !symbol.name.is_empty() && symbol2idx.contains_key(&symbol.name) {
                let existing_idx = symbol2idx.get(&symbol.name).unwrap();
                let existing_symbol = &mut new_file.symbols[*existing_idx];
                assert!(
                    !(existing_symbol.shndx != 0 && symbol.shndx != 0),
                    "symbol defined multiple times"
                );
                if existing_symbol.shndx == 0 && symbol.shndx != 0 {
                    let shndx = &(symbol.shndx as usize);
                    *existing_symbol = symbol.clone();
                    existing_symbol.shndx = *merged_section_idx.get(shndx).unwrap() as u16;
                    existing_symbol.value = *value_offsets.get(shndx).unwrap() as u64;
                }
                merged_symbol_idx.insert(idx, *existing_idx);
            } else {
                symbol2idx.insert(&symbol.name, new_file.symbols.len());
                merged_symbol_idx.insert(idx, new_file.symbols.len());
                let mut new_symbol = symbol.clone();
                if new_symbol.shndx != 0xfff1 {
                    let shndx = &(symbol.shndx as usize);
                    new_symbol.shndx = *merged_section_idx.get(shndx).unwrap() as u16;
                    new_symbol.value = *value_offsets.get(shndx).unwrap() as u64;
                }
                new_file.symbols.push(new_symbol);
            }
        }

        for section in new_file.sections.iter_mut() {
            if let Some(relocas) = section.relocations.as_mut() {
                for rela in relocas {
                    if rela.merged {
                    } else {
                    }
                }
            }
        }

        Ok(new_file)
    }

    // merge two sections into a new section.
    fn merge_sections(&self, a: &mut ElfSection, b: &ElfSection) -> usize {
        assert!(
            a.header.addralign == b.header.addralign,
            "sections must have same alignment"
        );
        assert!(a.header.ty == b.header.ty, "sections must be of same type");

        let align = a.header.addralign as usize;
        let mut len = a.data.len();
        let aligned = len.trailing_zeros() == align.trailing_zeros();
        len = if aligned { len } else { align_up(len, align) };

        a.data.append(&mut b.data.clone());
        a.header.size = len as u64;
        if let Some(relocas) = &b.relocations {
            if a.relocations.is_none() {
                a.relocations = Some(Vec::new());
            }
            for reloca in relocas {
                let mut new_reloca = reloca.clone();
                new_reloca.offset += len as u64;
                new_reloca.merged = true;
                a.relocations.as_mut().unwrap().push(new_reloca);
            }
        }
        len
    }
}
