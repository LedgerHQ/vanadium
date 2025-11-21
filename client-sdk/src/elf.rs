use common::manifest::Manifest;
use goblin::elf::program_header::{PF_R, PF_W, PF_X, PT_LOAD};
use goblin::elf::{Elf, ProgramHeader};

use core::panic;
use std::fs::File;
use std::io;
use std::io::Read;
use std::path::Path;

// The section name where the V-App manifest is stored in a packaged ELF binary.
const MANIFEST_SECTION_NAME: &str = ".manifest";

#[derive(Debug)]
pub struct Segment {
    pub data: Vec<u8>,
    pub start: u32,
    pub end: u32,
}

impl Segment {
    fn new(segment: &ProgramHeader, data: &[u8], memsize: usize) -> Self {
        if (memsize as u64) < segment.p_filesz {
            panic!("memsize cannot be smaller than p_filesz");
        }

        let start = segment.p_vaddr as u32;

        let mut data = data.to_vec();
        data.resize(memsize, 0);

        Self {
            data,
            start,
            end: start + memsize as u32,
        }
    }
}

#[derive(Debug)]
pub struct VAppElfFile {
    pub code_segment: Segment,
    pub data_segment: Segment,
    pub entrypoint: u32,
    // If the elf file has a .manifest section, the Manifest is parsed from it and stored here
    pub manifest: Option<Manifest>,
}

impl VAppElfFile {
    pub fn new(path: &Path) -> io::Result<Self> {
        let mut file = File::open(path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        let elf = Elf::parse(&buffer).unwrap();
        assert_eq!(elf.header.e_machine, goblin::elf::header::EM_RISCV);

        let (code_segment, data_segment) = Self::parse_segments(&elf, &buffer)?;
        let entrypoint = elf.header.e_entry as u32;

        // extract the content of the .manifest section
        let manifest_section = elf.section_headers.iter().find(|section| {
            elf.shdr_strtab.get_at(section.sh_name).unwrap_or("") == MANIFEST_SECTION_NAME
        });

        let manifest = if let Some(section) = manifest_section {
            let start = section.sh_offset as usize;
            let size = section.sh_size as usize;
            let manifest_data = &buffer[start..start + size];

            // take the subslice without trailing null bytes (if any)
            let manifest_data = manifest_data
                .iter()
                .take_while(|&&byte| byte != 0)
                .cloned()
                .collect::<Vec<u8>>();

            if manifest_data.is_empty() {
                // empty .manifest section
                None
            } else {
                let manifest_str =
                    std::str::from_utf8(&manifest_data).expect("Manifest data is not valid UTF-8");
                let manifest: Manifest =
                    Manifest::from_json(manifest_str).expect("Failed to parse manifest data");

                Some(manifest)
            }
        } else {
            None
        };

        Ok(Self {
            code_segment,
            data_segment,
            entrypoint,
            manifest,
        })
    }

    // Parses the Elf, extracting the code and data segments.
    // Fails if there are not exactly two loadable segments, one read-execute and one read-write.
    fn parse_segments(elf: &Elf, data: &[u8]) -> io::Result<(Segment, Segment)> {
        let mut segments: Vec<_> = elf
            .program_headers
            .iter()
            .filter(|segment| segment.p_type == PT_LOAD)
            .collect();

        segments.sort_by_key(|segment| segment.p_flags);

        if segments.len() != 2 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Expected exactly 2 loadable segments",
            ));
        }

        let flags: Vec<_> = segments.iter().map(|segment| segment.p_flags).collect();

        let rx = PF_R | PF_X;
        let rw = PF_R | PF_W;
        if flags != vec![rx, rw] {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Expected exactly one read-execute and one read-write segment",
            ));
        }

        let code_start = segments[0].p_offset as usize;
        let code_size = segments[0].p_filesz as usize;

        // For the code section, we expect the memory size and the file size to be the same
        assert_eq!(segments[0].p_memsz, segments[0].p_filesz);

        let code_seg = Segment::new(
            segments[0],
            &data[code_start..code_start + code_size],
            code_size,
        );
        let data_start = segments[1].p_offset as usize;
        let data_filesize = segments[1].p_filesz as usize;
        let data_memsize = segments[1].p_memsz as usize;
        let data_seg = Segment::new(
            segments[1],
            &data[data_start..data_start + data_filesize],
            data_memsize,
        );

        Ok((code_seg, data_seg))
    }
}

#[cfg(feature = "cargo_toml")]
pub fn get_app_metadata(
    cargo_toml_path: &std::path::PathBuf,
) -> Result<(String, String, cargo_toml::Value), &'static str> {
    let manifest = cargo_toml::Manifest::from_path(&cargo_toml_path)
        .map_err(|_| "Failed to load Cargo.toml")?;

    let package = manifest
        .package
        .ok_or("Missing package section in Cargo.toml")?;

    Ok((
        package.name,
        package
            .version
            .get()
            .map_err(|_| "Failed to get package version")?
            .clone(),
        package
            .metadata
            .and_then(|metadata| metadata.get("vapp").cloned())
            .ok_or("VApp metadata missing in Cargo.toml (add [package.metadata.vapp] section)")?,
    ))
}
