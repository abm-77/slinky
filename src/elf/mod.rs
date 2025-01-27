/*
 * https://www.sco.com/developers/gabi/2003-12-17/ch4.eheader.html
 * http://web.mit.edu/freebsd/head/sys/sys/elf64.h
 * https://github.com/RealNeGate/Cuik/blob/master/include/tb_elf.h
 * */

pub mod parse;

pub const ELF_MAGIC: &[u8] = b"\x7FELF";
pub const EHSIZE_64: usize = 64;

#[repr(u16)]
#[derive(Debug)]
pub enum ElfFileType {
    NONE = 0,        // none
    REL = 1,         // relocatable file
    EXEC = 2,        // executable file
    DYN = 3,         // shared object file
    CORE = 4,        // core file
    LOOS = 0xfe00,   // os specific
    HIOS = 0xfeff,   // os specific
    LOPROC = 0xff00, // processor specific
    HIPROC = 0xffff, // processor specific
}

impl From<u16> for ElfFileType {
    fn from(value: u16) -> Self {
        use ElfFileType::*;
        match value {
            0 => NONE,
            1 => REL,
            2 => EXEC,
            3 => DYN,
            4 => CORE,
            0xfe00 => LOOS,
            0xfeff => HIOS,
            0xff00 => LOPROC,
            0xffff => HIPROC,
            _ => panic!("Unknown file type: {}", value),
        }
    }
}

impl From<ElfFileType> for u16 {
    fn from(value: ElfFileType) -> Self {
        value as u16
    }
}

#[repr(u16)]
#[derive(Debug)]
pub enum ElfMachineType {
    NONE = 0,      // unknown machine
    MIPS = 8,      // mips
    X86_64 = 62,   // amd64
    AARCH64 = 183, // arm64
}

impl From<u16> for ElfMachineType {
    fn from(value: u16) -> Self {
        use ElfMachineType::*;
        match value {
            0 => NONE,
            8 => MIPS,
            62 => X86_64,
            183 => AARCH64,
            _ => panic!("Unknown machine type: {}", value),
        }
    }
}
impl From<ElfMachineType> for u16 {
    fn from(machine_type: ElfMachineType) -> Self {
        machine_type as u16
    }
}

#[repr(u32)]
#[derive(Debug, Clone)]
pub enum ElfSectionType {
    NULL = 0,               // inactive
    PROGBITS = 1,           // program defined information
    SYMTAB = 2,             // symbol table section
    STRTAB = 3,             // string table section
    RELA = 4,               // relocation section with addends
    NOTE = 7,               // holds information that marks the file in some way
    NOBITS = 8,             // no space section
    UNWINDX64 = 1879048193, // holds information about exception handling
    LOOS = 0x60000000,
    HIOS = 0x6fffffff,
    LOPROC = 0x70000000,
    HIPROC = 0x7fffffff,
}

impl From<u32> for ElfSectionType {
    fn from(value: u32) -> Self {
        use ElfSectionType::*;
        match value {
            0 => NULL,
            1 => PROGBITS,
            2 => SYMTAB,
            3 => STRTAB,
            4 => RELA,
            7 => NOTE,
            8 => NOBITS,
            1879048193 => UNWINDX64,
            0x60000000 => LOOS,
            0x6fffffff => HIOS,
            0x70000000 => LOPROC,
            0x7fffffff => HIPROC,
            _ => panic!("Unknown section type: {}", value),
        }
    }
}
impl From<ElfSectionType> for u32 {
    fn from(section_type: ElfSectionType) -> Self {
        section_type as u32
    }
}

#[repr(u32)]
#[derive(Debug)]
pub enum ElfSectionFlags {
    WRITE = 0x1,             // section contains writable data
    ALLOC = 0x2,             // section occupies memory
    EXECINSTR = 0x4,         // section contains instructions
    MERGE = 0x10,            // section may be merged
    STRINGS = 0x20,          // section contains strings
    INFOLINK = 0x40,         // sh_info holds section index
    LINKORDER = 0x80,        // special ordering requirements
    OSNONCONFORMING = 0x100, // os-specific processing required
    GROUP = 0x200,           // member of section group
    TLS = 0x400,             // section contains TLS data
    MASKOS = 0x0ff00000,     // os-specific semantics
    MASKPROC = 0xf0000000,   // processor-specific semantics
}

#[repr(u32)]
#[derive(Debug)]
pub enum ElfSegmentType {
    NULL = 0,    // unused entry
    LOAD = 1,    // loadable segment
    DYNAMIC = 2, // dynamic linking information segment
    INTERP = 3,  // path name of interpreter
    NOTE = 4,    // aux information
    SHLIB = 5,   // reserved (not used)
    PHDR = 6,    // location of progarm header
    TLS = 7,     // thread local storage segment
}

impl From<u32> for ElfSegmentType {
    fn from(value: u32) -> Self {
        use ElfSegmentType::*;
        match value {
            0 => NULL,
            1 => LOAD,
            2 => DYNAMIC,
            3 => INTERP,
            4 => NOTE,
            5 => SHLIB,
            6 => PHDR,
            7 => TLS,
            _ => panic!("Unknown segment type: {}", value),
        }
    }
}
impl From<ElfSegmentType> for u32 {
    fn from(segment_type: ElfSegmentType) -> Self {
        segment_type as u32
    }
}

#[repr(u32)]
#[derive(Debug)]
pub enum ElfSegmentFlags {
    X = 0x1,               // executable
    W = 0x2,               // writable
    R = 0x4,               // readable
    MASKOS = 0x0ff00000,   // os-specific semantics
    MASKPROC = 0xf0000000, // processor-specific semantics
}

#[derive(Debug)]
#[repr(u8)]
pub enum ElfSymbolType {
    NOTYPE = 0,  // not specified
    OBJECT = 1,  // data object (variable, array, etc.)
    FUNC = 2,    // function or other executable code
    SECTION = 3, // associated with a section, exists mainly for relocatiojn
    FILE = 4,    // symbol's name gives the name of the file associated with the object file
    COMMON = 5,  // unitialized common block
    TLS = 6,     // specifies a thread local storage entitiy
    LOOS = 10,   // os-specific semantics
    HIOS = 12,   // os-specific semantics
    LOPROC = 13, // processor-specific semantics
    HIPROC = 15, // procesoor-specific semantics
}

impl From<u8> for ElfSymbolType {
    fn from(value: u8) -> Self {
        use ElfSymbolType::*;
        match value {
            0 => NOTYPE,
            1 => OBJECT,
            2 => FUNC,
            3 => SECTION,
            4 => FILE,
            5 => COMMON,
            6 => TLS,
            10 => LOOS,
            12 => HIOS,
            13 => LOPROC,
            15 => HIPROC,
            _ => panic!("Unknown symbol type: {}", value),
        }
    }
}
impl From<ElfSymbolType> for u8 {
    fn from(symbol_type: ElfSymbolType) -> Self {
        symbol_type as u8
    }
}

#[derive(Debug)]
#[repr(u8)]
pub enum ElfSymbolBinding {
    LOCAL = 0,   // local symbols are not visible outside of object file containing def
    GLOBAL = 1,  // global symbols are visible to all objects being combined
    WEAK = 2, // weak symbols resemble global symbols, but their definitions have lower precedence
    LOOS = 10, // os-specific semantics
    HIOS = 12, // os-specific semantics
    LOPROC = 13, // processor-specific semantics
    HIPROC = 15, // procesoor-specific semantics
}

pub enum ElfSymbolVisibility {
    DEFAULT = 0,   // visibility specified by binding type
    INTERNAL = 1,  // defined by processor
    HIDDEN = 2,    // symbol not visible to other components
    PROTECTED = 3, // symbol is visible to other components but not preemptable
}

#[repr(u64)]
#[allow(non_camel_case_types)]
pub enum ElfRelocationType {
    NONE = 0,      // no relocaton
    X86_64_64 = 1, // absolute 64-bit reolocation
    X86_64_PC32 = 2,
    X86_64_GOT32 = 3,
    X86_64_PLT32 = 4,
    X86_64_GOTPCREL = 9,
    X86_64_GOTPCRELX = 41,
    X86_64_REX_GOTPCRELX = 42,

    ARM64_ABS64 = 257,         // absolute 64-bit relocation
    ARM64_PREL32 = 261,        // PC-relative 32-bit relocation
    ARM64_ADR_PREL_LO21 = 273, // relocation for instructions like ADR
}

impl From<u64> for ElfRelocationType {
    fn from(value: u64) -> Self {
        match value {
            0 => ElfRelocationType::NONE,
            1 => ElfRelocationType::X86_64_64,
            2 => ElfRelocationType::X86_64_PC32,
            3 => ElfRelocationType::X86_64_GOT32,
            4 => ElfRelocationType::X86_64_PLT32,
            9 => ElfRelocationType::X86_64_GOTPCREL,
            41 => ElfRelocationType::X86_64_GOTPCRELX,
            42 => ElfRelocationType::X86_64_REX_GOTPCRELX,
            257 => ElfRelocationType::ARM64_ABS64,
            261 => ElfRelocationType::ARM64_PREL32,
            273 => ElfRelocationType::ARM64_ADR_PREL_LO21,
            _ => panic!("Unknown relocation type: {}", value),
        }
    }
}

impl From<ElfRelocationType> for u64 {
    fn from(relocation_type: ElfRelocationType) -> Self {
        relocation_type as u64
    }
}

#[derive(Debug)]
pub struct ElfFileIdentifier {
    pub class: u8,
    pub endianness: nom::number::Endianness,
    pub version: u8,
    pub os_abi: u8,
    pub abi_version: u8,
}

#[derive(Debug)]
pub struct ElfHeader {
    pub eident: ElfFileIdentifier,
    pub ty: ElfFileType,         // file type
    pub machine: ElfMachineType, // machine architecture
    pub version: u32,            // elf format version
    pub entry: u64,              // entry point
    pub phoff: u64,              // program header file offset
    pub shoff: u64,              // section header file offset
    pub flags: u32,              // arch specific flags
    pub ehsize: u16,             // size of elf header i nbytes
    pub phentsize: u16,          // size of program header entry
    pub phnum: u16,              // number of program header entries
    pub shentsize: u16,          // size of section header entry
    pub shnum: u16,              // number of section header entries
    pub shstrndx: u16,           // section names tring section
}

#[derive(Debug, Clone)]
pub struct ElfSectionHeader {
    pub name_offset: u32, // section name (index into the section header string table)
    pub ty: ElfSectionType, // section type
    pub flags: u64,       // section flags
    pub addr: u64,        // address in memory image
    pub offset: u64,      // offset in file
    pub size: u64,        // size in bytes
    pub link: u32,        // index of a related section
    pub info: u32,        // depends on section type
    pub addralign: u64,   // alignment in bytes
    pub entsize: u64,     // size of each entry in section

    pub name: String,
    pub data: Vec<u8>,
    pub relocations: Option<Vec<ElfRelocationA>>,
}

#[derive(Debug)]
pub struct ElfSegmentHeader {
    pub ty: ElfSegmentType, // entry type
    pub flags: u64,         // access permission flags
    pub offset: u64,        // file offset of contents
    pub vaddr: u64,         // virtual address in memory image
    pub paddr: u64,         // physical address (not used)
    pub filesz: u64,        // size of contents in file
    pub memsz: u64,         // size of contents in memory
    pub align: u64,         // alignment in memory and file
}

#[derive(Debug)]
pub struct ElfSymbol {
    pub name_offset: u32, // symbol name (index into symbol string table)
    pub name: String,
    pub info: u8,   // specifies symbols type and binding attributes
    pub other: u8,  // specifies a symbol's visibility
    pub shndx: u16, // holds the relevant section header table index
    pub value: u64, // value of associated symbol (absolute value, address, etc.)
    pub size: u64,  // size of symbol
}

#[derive(Debug, Clone)]
pub struct ElfRelocationA {
    pub offset: u64, // gives the location at which to apply the relocation action
    pub info: u64,   // gives symbol table index to relocate and the type of relocation to apply
    pub addend: i64, // specifies constant addend used to compute the value to be stored in relocatable
                     // field
}

#[derive(Debug)]
pub struct ElfFile {
    pub header: ElfHeader,
    pub section_data: Vec<u8>,
    pub section_headers: Vec<ElfSectionHeader>,
}

impl ElfSymbol {
    pub fn bind(self) -> u8 {
        self.info >> 4
    }

    pub fn ty(self) -> u8 {
        self.info & 0xf
    }

    pub fn set_info(&mut self, binding: u8, ty: u8) {
        self.info = (binding << 4) + (ty & 0xf)
    }

    pub fn visibility(self) -> u8 {
        self.other & 0x3
    }
}

impl ElfRelocationA {
    pub fn sym(self) -> u64 {
        self.info >> 32
    }

    pub fn ty(self) -> u64 {
        self.info & 0xffffffff
    }

    pub fn set_info(&mut self, symbol: u64, ty: u64) {
        self.info = (symbol << 32) + (ty & 0xffffffff);
    }
}
