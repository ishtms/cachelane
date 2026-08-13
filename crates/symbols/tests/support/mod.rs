use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

pub const GUID: [u8; 16] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
];

pub struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    pub fn new(label: &str) -> io::Result<Self> {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "cachelane-symbols-{}-{sequence}-{label}",
            std::process::id()
        ));
        fs::create_dir(&path)?;
        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

pub fn write_pe(
    path: &Path,
    guid: [u8; 16],
    age: u32,
    pdb_name: &str,
    dynamic_library: bool,
) -> io::Result<()> {
    let mut bytes = vec![0_u8; 0x400];
    bytes[0..2].copy_from_slice(b"MZ");
    write_u32(&mut bytes, 0x3C, 0x80);
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");

    let file_header = 0x84;
    write_u16(&mut bytes, file_header, 0x8664);
    write_u16(&mut bytes, file_header + 2, 1);
    write_u32(&mut bytes, file_header + 4, 0x1234_5678);
    write_u16(&mut bytes, file_header + 16, 0xF0);
    let characteristics = if dynamic_library { 0x2022 } else { 0x0022 };
    write_u16(&mut bytes, file_header + 18, characteristics);

    let optional_header = 0x98;
    write_u16(&mut bytes, optional_header, 0x20B);
    write_u64(&mut bytes, optional_header + 24, 0x0001_4000_0000);
    write_u32(&mut bytes, optional_header + 32, 0x1000);
    write_u32(&mut bytes, optional_header + 36, 0x200);
    write_u32(&mut bytes, optional_header + 56, 0x2000);
    write_u32(&mut bytes, optional_header + 60, 0x200);
    write_u16(&mut bytes, optional_header + 68, 3);
    write_u32(&mut bytes, optional_header + 108, 16);
    write_u32(&mut bytes, optional_header + 160, 0x1000);
    write_u32(&mut bytes, optional_header + 164, 28);

    let section = 0x188;
    bytes[section..section + 6].copy_from_slice(b".rdata");
    write_u32(&mut bytes, section + 8, 0x200);
    write_u32(&mut bytes, section + 12, 0x1000);
    write_u32(&mut bytes, section + 16, 0x200);
    write_u32(&mut bytes, section + 20, 0x200);
    write_u32(&mut bytes, section + 36, 0x4000_0040);

    let code_view_size = 4 + 16 + 4 + pdb_name.len() + 1;
    write_u32(&mut bytes, 0x20C, 2);
    write_u32(
        &mut bytes,
        0x210,
        u32::try_from(code_view_size).unwrap_or(u32::MAX),
    );
    write_u32(&mut bytes, 0x214, 0x1020);
    write_u32(&mut bytes, 0x218, 0x220);
    bytes[0x220..0x224].copy_from_slice(b"RSDS");
    bytes[0x224..0x234].copy_from_slice(&raw_guid(guid));
    write_u32(&mut bytes, 0x234, age);
    bytes[0x238..0x238 + pdb_name.len()].copy_from_slice(pdb_name.as_bytes());

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, bytes)
}

pub fn write_pdb(path: &Path, guid: [u8; 16], age: u32, original_age: u32) -> io::Result<()> {
    const PAGE_SIZE: usize = 512;
    const PAGE_SIZE_U32: u32 = 512;
    let mut bytes = vec![0_u8; PAGE_SIZE * 8];
    bytes[0..32].copy_from_slice(b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0");
    write_u32(&mut bytes, 32, PAGE_SIZE_U32);
    write_u32(&mut bytes, 36, 1);
    write_u32(&mut bytes, 40, 8);
    write_u32(&mut bytes, 44, 28);
    write_u32(&mut bytes, 52, 2);

    write_u32(&mut bytes, PAGE_SIZE * 2, 3);
    let directory = PAGE_SIZE * 3;
    write_u32(&mut bytes, directory, 4);
    write_u32(&mut bytes, directory + 4, u32::MAX);
    write_u32(&mut bytes, directory + 8, 32);
    write_u32(&mut bytes, directory + 12, u32::MAX);
    write_u32(&mut bytes, directory + 16, 64);
    write_u32(&mut bytes, directory + 20, 4);
    write_u32(&mut bytes, directory + 24, 5);

    let information = PAGE_SIZE * 4;
    write_u32(&mut bytes, information, 20_000_404);
    write_u32(&mut bytes, information + 4, 0x1234_5678);
    write_u32(&mut bytes, information + 8, age);
    write_guid_fields(&mut bytes, information + 12, guid);
    write_u32(&mut bytes, information + 28, 0);

    let debug = PAGE_SIZE * 5;
    write_u32(&mut bytes, debug, u32::MAX);
    write_u32(&mut bytes, debug + 4, 19_990_903);
    write_u32(&mut bytes, debug + 8, original_age);
    write_u16(&mut bytes, debug + 12, u16::MAX);
    write_u16(&mut bytes, debug + 16, u16::MAX);
    write_u16(&mut bytes, debug + 20, u16::MAX);
    write_u16(&mut bytes, debug + 58, 0x8664);

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, bytes)
}

#[allow(dead_code)]
pub fn write_large_dbi_pdb(
    path: &Path,
    guid: [u8; 16],
    age: u32,
    original_age: u32,
    debug_stream_size: usize,
) -> io::Result<()> {
    const PAGE_SIZE: usize = 512;
    let debug_pages = debug_stream_size.div_ceil(PAGE_SIZE);
    let directory_size = 24_usize
        .checked_add(
            debug_pages
                .checked_mul(4)
                .ok_or_else(|| io::Error::other("fixture is too large"))?,
        )
        .ok_or_else(|| io::Error::other("fixture is too large"))?;
    let directory_pages = directory_size.div_ceil(PAGE_SIZE);
    let block_map_pages = directory_pages
        .checked_mul(4)
        .ok_or_else(|| io::Error::other("fixture is too large"))?
        .div_ceil(PAGE_SIZE);
    let directory_first_page = 2 + block_map_pages;
    let information_page = directory_first_page + directory_pages;
    let debug_page = information_page + 1;
    let pages_used = debug_page + 1;
    let mut bytes = vec![0_u8; pages_used * PAGE_SIZE];

    bytes[0..32].copy_from_slice(b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0");
    write_u32(&mut bytes, 32, 512);
    write_u32(&mut bytes, 36, 1);
    write_u32(
        &mut bytes,
        40,
        u32::try_from(pages_used).map_err(io::Error::other)?,
    );
    write_u32(
        &mut bytes,
        44,
        u32::try_from(directory_size).map_err(io::Error::other)?,
    );
    for index in 0..block_map_pages {
        write_u32(
            &mut bytes,
            52 + index * 4,
            u32::try_from(2 + index).map_err(io::Error::other)?,
        );
    }

    let mut block_map = vec![0_u8; block_map_pages * PAGE_SIZE];
    for index in 0..directory_pages {
        write_u32(
            &mut block_map,
            index * 4,
            u32::try_from(directory_first_page + index).map_err(io::Error::other)?,
        );
    }
    for index in 0..block_map_pages {
        let start = index * PAGE_SIZE;
        let destination = (2 + index) * PAGE_SIZE;
        bytes[destination..destination + PAGE_SIZE]
            .copy_from_slice(&block_map[start..start + PAGE_SIZE]);
    }

    let mut directory = vec![0_u8; directory_pages * PAGE_SIZE];
    write_u32(&mut directory, 0, 4);
    write_u32(&mut directory, 4, u32::MAX);
    write_u32(&mut directory, 8, 32);
    write_u32(&mut directory, 12, u32::MAX);
    write_u32(
        &mut directory,
        16,
        u32::try_from(debug_stream_size).map_err(io::Error::other)?,
    );
    write_u32(
        &mut directory,
        20,
        u32::try_from(information_page).map_err(io::Error::other)?,
    );
    for index in 0..debug_pages {
        write_u32(
            &mut directory,
            24 + index * 4,
            u32::try_from(debug_page).map_err(io::Error::other)?,
        );
    }
    for index in 0..directory_pages {
        let start = index * PAGE_SIZE;
        let destination = (directory_first_page + index) * PAGE_SIZE;
        bytes[destination..destination + PAGE_SIZE]
            .copy_from_slice(&directory[start..start + PAGE_SIZE]);
    }

    let information = information_page * PAGE_SIZE;
    write_u32(&mut bytes, information, 20_000_404);
    write_u32(&mut bytes, information + 4, 0x1234_5678);
    write_u32(&mut bytes, information + 8, age);
    write_guid_fields(&mut bytes, information + 12, guid);
    write_u32(&mut bytes, information + 28, 0);

    let debug = debug_page * PAGE_SIZE;
    write_u32(&mut bytes, debug, u32::MAX);
    write_u32(&mut bytes, debug + 4, 19_990_903);
    write_u32(&mut bytes, debug + 8, original_age);
    write_u16(&mut bytes, debug + 12, u16::MAX);
    write_u16(&mut bytes, debug + 16, u16::MAX);
    write_u16(&mut bytes, debug + 20, u16::MAX);
    write_u16(&mut bytes, debug + 58, 0x8664);

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, bytes)
}

fn raw_guid(guid: [u8; 16]) -> [u8; 16] {
    [
        guid[3], guid[2], guid[1], guid[0], guid[5], guid[4], guid[7], guid[6], guid[8], guid[9],
        guid[10], guid[11], guid[12], guid[13], guid[14], guid[15],
    ]
}

fn write_guid_fields(bytes: &mut [u8], offset: usize, guid: [u8; 16]) {
    bytes[offset..offset + 16].copy_from_slice(&raw_guid(guid));
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
