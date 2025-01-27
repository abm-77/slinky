use super::{
    ElfFile, ElfFileIdentifier, ElfHeader, ElfRelocationA, ElfSectionHeader, ElfSectionType,
    ElfSegmentHeader, ElfSymbol,
};

use nom::bytes::complete::{tag, take};
use nom::combinator::all_consuming;
use nom::multi::many1;
use nom::number::complete as num_parse;
use nom::IResult;
use nom::{Finish, Parser};

impl ElfHeader {
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, _) = tag(super::ELF_MAGIC)(input)?;
        let (input, class) = num_parse::u8(input)?;
        let (input, b) = num_parse::u8(input)?;
        let endianness = match b {
            0x01 => nom::number::Endianness::Little,
            0x02 => nom::number::Endianness::Big,
            _ => unreachable!(),
        };
        let (input, version) = num_parse::u8(input)?;
        let (input, os_abi) = num_parse::u8(input)?;
        let (input, abi_version) = num_parse::u8(input)?;
        let (input, _) = take(7_usize)(input)?;

        let eident = ElfFileIdentifier {
            class,
            endianness,
            version,
            os_abi,
            abi_version,
        };

        let parse_u16 = |i| num_parse::u16(endianness)(i);
        let parse_u32 = |i| num_parse::u32(endianness)(i);
        let parse_u64 = |i| num_parse::u64(endianness)(i);

        let (input, ty) = parse_u16(input)?;
        let (input, machine) = parse_u16(input)?;
        let (input, version) = parse_u32(input)?;
        let (input, entry) = parse_u64(input)?;
        let (input, phoff) = parse_u64(input)?;
        let (input, shoff) = parse_u64(input)?;
        let (input, flags) = parse_u32(input)?;
        let (input, ehsize) = parse_u16(input)?;
        let (input, phentsize) = parse_u16(input)?;
        let (input, phnum) = parse_u16(input)?;
        let (input, shentsize) = parse_u16(input)?;
        let (input, shnum) = parse_u16(input)?;
        let (input, shstrndx) = parse_u16(input)?;

        let hdr = ElfHeader {
            eident,
            ty: ty.into(),
            machine: machine.into(),
            version,
            entry,
            phoff,
            shoff,
            flags,
            ehsize,
            phentsize,
            phnum,
            shentsize,
            shnum,
            shstrndx,
        };

        Ok((input, hdr))
    }
}

impl ElfSectionHeader {
    fn parse(input: &[u8], endianness: nom::number::Endianness) -> IResult<&[u8], Self> {
        let parse_u32 = |i| num_parse::u32(endianness)(i);
        let parse_u64 = |i| num_parse::u64(endianness)(i);

        let (input, name_offset) = parse_u32(input)?;
        let (input, ty) = parse_u32(input)?;
        let (input, flags) = parse_u64(input)?;
        let (input, addr) = parse_u64(input)?;
        let (input, offset) = parse_u64(input)?;
        let (input, size) = parse_u64(input)?;
        let (input, link) = parse_u32(input)?;
        let (input, info) = parse_u32(input)?;
        let (input, addralign) = parse_u64(input)?;
        let (input, entsize) = parse_u64(input)?;

        let hdr = ElfSectionHeader {
            name_offset,
            ty: ty.into(),
            flags,
            addr,
            offset,
            size,
            link,
            info,
            addralign,
            entsize,
            name: String::new(),
            data: Vec::new(),
            relocations: None,
        };

        Ok((input, hdr))
    }
}

impl ElfSegmentHeader {
    fn parse(input: &[u8], endianness: nom::number::Endianness) -> IResult<&[u8], Self> {
        let parse_u32 = |i| num_parse::u32(endianness)(i);
        let parse_u64 = |i| num_parse::u64(endianness)(i);

        let (input, ty) = parse_u32(input)?;
        let (input, flags) = parse_u64(input)?;
        let (input, offset) = parse_u64(input)?;
        let (input, vaddr) = parse_u64(input)?;
        let (input, paddr) = parse_u64(input)?;
        let (input, filesz) = parse_u64(input)?;
        let (input, memsz) = parse_u64(input)?;
        let (input, align) = parse_u64(input)?;

        let hdr = ElfSegmentHeader {
            ty: ty.into(),
            flags,
            offset,
            vaddr,
            paddr,
            filesz,
            memsz,
            align,
        };

        Ok((input, hdr))
    }
}

impl ElfSymbol {
    fn parse_many(
        input: &[u8],
        endianness: nom::number::Endianness,
    ) -> Result<Vec<Self>, ElfParseError> {
        let parser = ElfSymbol::parse_single(endianness);
        let (_, symbols) = Finish::finish(all_consuming(many1(parser)).parse(input))?;
        Ok(symbols)
    }

    fn parse_single(endianness: nom::number::Endianness) -> impl Fn(&[u8]) -> IResult<&[u8], Self> {
        move |input: &[u8]| {
            let parse_u8 = |i| num_parse::u8(i);
            let parse_u16 = |i| num_parse::u16(endianness)(i);
            let parse_u32 = |i| num_parse::u32(endianness)(i);
            let parse_u64 = |i| num_parse::u64(endianness)(i);

            let (input, name_offset) = parse_u32(input)?;
            let (input, info) = parse_u8(input)?;
            let (input, other) = parse_u8(input)?;
            let (input, shndx) = parse_u16(input)?;
            let (input, value) = parse_u64(input)?;
            let (input, size) = parse_u64(input)?;

            let sym = ElfSymbol {
                name_offset,
                name: String::new(),
                info,
                other,
                shndx,
                value,
                size,
            };

            Ok((input, sym))
        }
    }
}

#[derive(Debug)]
pub struct ElfParseError;
impl From<nom::error::Error<&[u8]>> for ElfParseError {
    fn from(_: nom::error::Error<&[u8]>) -> Self {
        ElfParseError
    }
}

impl ElfRelocationA {
    fn parse_many(
        input: &[u8],
        endianness: nom::number::Endianness,
    ) -> Result<Vec<Self>, ElfParseError> {
        let parser = ElfRelocationA::parse_single(endianness);
        let (_, relocs) = Finish::finish(all_consuming(many1(parser)).parse(input))?;
        Ok(relocs)
    }

    fn parse_single(endianness: nom::number::Endianness) -> impl Fn(&[u8]) -> IResult<&[u8], Self> {
        move |input: &[u8]| {
            let parse_u64 = |i| num_parse::u64(endianness)(i);

            let (input, offset) = parse_u64(input)?;
            let (input, info) = parse_u64(input)?;
            let (input, addend) = parse_u64(input)?;

            let reloca = ElfRelocationA {
                offset,
                info,
                addend: addend as i64,
            };

            Ok((input, reloca))
        }
    }
}

impl ElfFile {
    pub fn parse(input: &[u8]) -> Result<Self, ElfParseError> {
        let (_, file) = Finish::finish(all_consuming(ElfFile::parse_helper).parse(input))?;
        Ok(file)
    }

    pub fn get_symtab(&self) -> Option<&ElfSectionHeader> {
        for section in self.section_headers.iter() {
            if matches!(section.ty, ElfSectionType::SYMTAB) {
                return Some(section);
            }
        }
        return None;
    }

    pub fn get_symbols(&self) -> Option<Vec<ElfSymbol>> {
        if let Some(symtab) = self.get_symtab() {
            let get_name = |idx: usize| {
                let symbol_name_string_table_header = &self.section_headers[symtab.link as usize];
                let offset =
                    (symbol_name_string_table_header.offset - self.header.ehsize as u64) as usize;
                let name_start = &self.section_data[offset + idx] as *const u8 as *const i8;
                let name = unsafe { std::ffi::CStr::from_ptr(name_start) };
                name.to_str().expect("could not create &str").to_string()
            };

            let mut symbols =
                ElfSymbol::parse_many(&symtab.data[..], self.header.eident.endianness)
                    .expect("could not get symbols");

            for symbol in symbols.iter_mut() {
                symbol.name = get_name(symbol.name_offset as usize);
            }

            return Some(symbols);
        }

        None
    }

    pub fn parse_helper(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, header) = ElfHeader::parse(input)?;
        let (input, section_data) = take(header.shoff - header.ehsize as u64)(input)?;
        let (input, mut section_headers) =
            many1(|i| ElfSectionHeader::parse(i, header.eident.endianness)).parse(input)?;

        let section_name_string_table_header = section_headers[header.shstrndx as usize].clone();
        let get_name = |idx: usize| {
            let offset = (section_name_string_table_header.offset - header.ehsize as u64) as usize;
            let name_start = &section_data[offset + idx] as *const u8 as *const i8;
            let name = unsafe { std::ffi::CStr::from_ptr(name_start) };
            name.to_str().expect("could not create &str").to_string()
        };

        let get_data = |offset: usize, size: usize| {
            if offset == 0 && size == 0 {
                Vec::new()
            } else {
                let start = offset - header.ehsize as usize;
                let end = start + size as usize;
                let data = &section_data[start..end];
                data.to_owned()
            }
        };

        for sh in section_headers.iter_mut() {
            sh.name = get_name(sh.name_offset as usize);
            sh.data = get_data(sh.offset as usize, sh.size as usize);
            if matches!(sh.ty, ElfSectionType::RELA) {
                sh.relocations = Some(
                    ElfRelocationA::parse_many(&sh.data[..], header.eident.endianness)
                        .expect("could not get relocations"),
                );
            }
        }

        let file = ElfFile {
            header,
            section_data: section_data.to_vec(),
            section_headers,
        };

        Ok((input, file))
    }
}
