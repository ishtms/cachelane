use std::{error::Error, io::Write};

use cachelane_unreal::{
    CrashRequestErrorKind, CrashRequestFile, CrashRequestFileKind, CrashRequestLimits,
    inspect_crash_request, read_crash_request,
};
use flate2::{Compression, write::ZlibEncoder};

const HEADER_SIZE_OFFSET: usize = 3 + 264 + 264;
const HEADER_BYTES: usize = HEADER_SIZE_OFFSET + 8;

struct EncodedRequest {
    compressed: Vec<u8>,
    expanded_size: usize,
}

fn write_i32(output: &mut Vec<u8>, value: i32) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn write_ansi_field(output: &mut Vec<u8>, value: &str) {
    write_i32(output, 260);
    output.extend_from_slice(value.as_bytes());
    output.resize(output.len() + 260 - value.len(), 0);
}

fn expanded_request(files: &[(&str, &[u8])]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut expanded = Vec::new();
    expanded.extend_from_slice(b"CR1");
    write_ansi_field(&mut expanded, "UECC-Windows-Synthetic");
    write_ansi_field(&mut expanded, "UECC-Windows-Synthetic.uecrash");
    write_i32(&mut expanded, 0);
    write_i32(&mut expanded, i32::try_from(files.len())?);

    for (index, (name, contents)) in files.iter().enumerate() {
        write_i32(&mut expanded, i32::try_from(index)?);
        write_ansi_field(&mut expanded, name);
        write_i32(&mut expanded, i32::try_from(contents.len())?);
        expanded.extend_from_slice(contents);
    }

    let expanded_size = i32::try_from(expanded.len())?;
    expanded[HEADER_SIZE_OFFSET..HEADER_SIZE_OFFSET + 4]
        .copy_from_slice(&expanded_size.to_le_bytes());
    Ok(expanded)
}

fn compress(expanded: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(expanded)?;
    encoder.finish()
}

fn crash_request(files: &[(&str, &[u8])]) -> Result<EncodedRequest, Box<dyn Error>> {
    let expanded = expanded_request(files)?;
    Ok(EncodedRequest {
        compressed: compress(&expanded)?,
        expanded_size: expanded.len(),
    })
}

fn assert_error(request: &[u8], limits: CrashRequestLimits, expected: CrashRequestErrorKind) {
    let result = inspect_crash_request(request, limits);
    let Err(error) = result else {
        panic!("request unexpectedly passed");
    };

    assert_eq!(error.kind(), expected);
}

#[test]
fn inspects_real_format_records_in_source_order() -> Result<(), Box<dyn Error>> {
    let xml = b"<FGenericCrashContext/>";
    let log = b"LogCacheLane: synthetic\n";
    let request = crash_request(&[
        ("CrashContext.runtime-xml", xml),
        ("Synthetic.log", log),
        ("Future.bin", b"future"),
    ])?;
    let manifest = inspect_crash_request(&request.compressed[..], CrashRequestLimits::default())?;

    assert_eq!(manifest.schema_version, 1);
    assert_eq!(manifest.envelope, "cr1");
    assert_eq!(manifest.directory_name, "UECC-Windows-Synthetic");
    assert_eq!(manifest.archive_name, "UECC-Windows-Synthetic.uecrash");
    assert_eq!(manifest.compressed_size, request.compressed.len() as u64);
    assert_eq!(manifest.expanded_size, request.expanded_size as u64);
    assert_eq!(
        manifest.files,
        vec![
            CrashRequestFile {
                index: 0,
                name: "CrashContext.runtime-xml".to_owned(),
                size: xml.len() as u64,
                kind: CrashRequestFileKind::CrashContext,
            },
            CrashRequestFile {
                index: 1,
                name: "Synthetic.log".to_owned(),
                size: log.len() as u64,
                kind: CrashRequestFileKind::Log,
            },
            CrashRequestFile {
                index: 2,
                name: "Future.bin".to_owned(),
                size: 6,
                kind: CrashRequestFileKind::Unknown,
            },
        ]
    );
    Ok(())
}

#[test]
fn reads_only_bounded_processing_contents() -> Result<(), Box<dyn Error>> {
    let xml = b"<FGenericCrashContext><RuntimeProperties><CrashGUID>UECC-Synthetic</CrashGUID></RuntimeProperties></FGenericCrashContext>";
    let minidump = b"synthetic minidump";
    let log = b"old line\nmiddle line\nnewest\n";
    let request = crash_request(&[
        ("CrashContext.runtime-xml", xml),
        ("Synthetic.log", log),
        ("UEMinidump.dmp", minidump),
        ("Future.bin", b"do-not-retain"),
    ])?;
    let contents = read_crash_request(
        &request.compressed[..],
        CrashRequestLimits {
            log_tail_bytes: 12,
            log_tail_lines: 1,
            ..CrashRequestLimits::default()
        },
    )?;

    assert_eq!(contents.manifest.files.len(), 4);
    assert_eq!(
        contents.crash_context.as_deref(),
        std::str::from_utf8(xml).ok()
    );
    assert_eq!(contents.minidump.as_deref(), Some(minidump.as_slice()));
    let log = contents.log.ok_or("missing log")?;
    assert_eq!(log.name, "Synthetic.log");
    assert_eq!(log.tail.text(), "newest\n");
    assert!(log.tail.truncated());
    assert!(!log.tail.had_invalid_utf8());
    Ok(())
}

#[test]
fn capture_applies_the_minidump_limit_without_changing_inspection() -> Result<(), Box<dyn Error>> {
    let request = crash_request(&[("UEMinidump.dmp", b"too large")])?;
    let limits = CrashRequestLimits {
        minidump_bytes: 1,
        ..CrashRequestLimits::default()
    };

    assert!(inspect_crash_request(&request.compressed[..], limits).is_ok());
    let error = read_crash_request(&request.compressed[..], limits)
        .err()
        .ok_or("captured minidump must exceed its limit")?;
    assert_eq!(error.kind(), CrashRequestErrorKind::FileTooLarge);
    Ok(())
}

#[test]
fn enforces_stream_resource_limits() -> Result<(), Box<dyn Error>> {
    let request = crash_request(&[("CrashContext.runtime-xml", b"<FGenericCrashContext/>")])?;
    let defaults = CrashRequestLimits::default();

    assert_error(
        &request.compressed,
        CrashRequestLimits {
            compressed_bytes: request.compressed.len() as u64 - 1,
            ..defaults
        },
        CrashRequestErrorKind::CompressedTooLarge,
    );
    assert_error(
        &request.compressed,
        CrashRequestLimits {
            expanded_bytes: HEADER_BYTES as u64 - 1,
            ..defaults
        },
        CrashRequestErrorKind::ExpandedTooLarge,
    );
    assert_error(
        &request.compressed,
        CrashRequestLimits {
            expansion_ratio: 1,
            ..defaults
        },
        CrashRequestErrorKind::ExpansionRatioExceeded,
    );
    assert_error(
        &request.compressed,
        CrashRequestLimits {
            files: 0,
            ..defaults
        },
        CrashRequestErrorKind::TooManyFiles,
    );
    assert_error(
        &request.compressed,
        CrashRequestLimits {
            file_bytes: 1,
            ..defaults
        },
        CrashRequestErrorKind::FileTooLarge,
    );
    assert_error(
        &request.compressed,
        CrashRequestLimits {
            crash_context_bytes: 1,
            ..defaults
        },
        CrashRequestErrorKind::FileTooLarge,
    );
    Ok(())
}

#[test]
fn rejects_unsafe_and_duplicate_names() -> Result<(), Box<dyn Error>> {
    for name in ["../secret.txt", "C:\\secret.txt", "/secret.txt", "bad?.txt"] {
        let request = crash_request(&[(name, b"secret")])?;
        assert_error(
            &request.compressed,
            CrashRequestLimits::default(),
            CrashRequestErrorKind::UnsafeFilename,
        );
    }

    let duplicate = crash_request(&[
        ("CrashContext.runtime-xml", b"<FGenericCrashContext/>"),
        ("CRASHCONTEXT.RUNTIME-XML", b"<FGenericCrashContext/>"),
    ])?;
    assert_error(
        &duplicate.compressed,
        CrashRequestLimits::default(),
        CrashRequestErrorKind::DuplicateCriticalFile,
    );
    Ok(())
}

#[test]
fn rejects_invalid_record_metadata() -> Result<(), Box<dyn Error>> {
    let mut bad_padding = expanded_request(&[("Safe.txt", b"safe")])?;
    let filename_start = HEADER_BYTES + 4 + 4;
    bad_padding[filename_start + "Safe.txt".len() + 1] = b'x';
    assert_error(
        &compress(&bad_padding)?,
        CrashRequestLimits::default(),
        CrashRequestErrorKind::InvalidHeader,
    );

    let mut bad_index = expanded_request(&[("Safe.txt", b"safe")])?;
    bad_index[HEADER_BYTES..HEADER_BYTES + 4].copy_from_slice(&1_i32.to_le_bytes());
    assert_error(
        &compress(&bad_index)?,
        CrashRequestLimits::default(),
        CrashRequestErrorKind::FileCountMismatch,
    );

    let mut bad_size = expanded_request(&[("Safe.txt", b"safe")])?;
    bad_size[HEADER_SIZE_OFFSET..HEADER_SIZE_OFFSET + 4].copy_from_slice(&1_i32.to_le_bytes());
    assert_error(
        &compress(&bad_size)?,
        CrashRequestLimits::default(),
        CrashRequestErrorKind::ExpandedSizeMismatch,
    );
    Ok(())
}

#[test]
fn rejects_unsafe_and_malformed_crash_contexts() -> Result<(), Box<dyn Error>> {
    let cases: &[(&[u8], CrashRequestErrorKind)] = &[
        (
            br#"<!DOCTYPE FGenericCrashContext [<!ENTITY secret "value">]><FGenericCrashContext/>"#,
            CrashRequestErrorKind::InvalidCrashContext,
        ),
        (
            b"<FGenericCrashContext>",
            CrashRequestErrorKind::InvalidCrashContext,
        ),
        (
            b"<FGenericCrashContext>\xff",
            CrashRequestErrorKind::InvalidCrashContextUtf8,
        ),
    ];

    for (xml, expected) in cases {
        let request = crash_request(&[("CrashContext.runtime-xml", xml)])?;
        assert_error(
            &request.compressed,
            CrashRequestLimits::default(),
            *expected,
        );
    }
    Ok(())
}

#[test]
fn rejects_malformed_truncated_and_trailing_data() -> Result<(), Box<dyn Error>> {
    assert_error(
        b"not a zlib stream",
        CrashRequestLimits::default(),
        CrashRequestErrorKind::InvalidCompression,
    );

    let request = crash_request(&[("Safe.txt", b"safe")])?;
    assert_error(
        &request.compressed[..request.compressed.len() / 2],
        CrashRequestLimits::default(),
        CrashRequestErrorKind::TruncatedArchive,
    );

    let mut trailing = request.compressed;
    trailing.push(0);
    assert_error(
        &trailing,
        CrashRequestLimits::default(),
        CrashRequestErrorKind::TrailingData,
    );
    Ok(())
}
