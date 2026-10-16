//! I12: the outgoing image pipeline strips EXIF/GPS/ICC and enforces limits.

use image::codecs::jpeg::JpegEncoder;
use image::{DynamicImage, ImageEncoder, RgbImage, RgbaImage};
use sme_media::{MAX_LONG_EDGE, MAX_OUTPUT_BYTES, MediaError, prepare_image};

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn sample_jpeg(width: u32, height: u32) -> Vec<u8> {
    let mut image = RgbImage::new(width, height);
    for (x, y, pixel) in image.enumerate_pixels_mut() {
        *pixel = image::Rgb([(x % 256) as u8, (y % 256) as u8, 77]);
    }
    let mut bytes = Vec::new();
    JpegEncoder::new_with_quality(&mut bytes, 90)
        .encode_image(&DynamicImage::ImageRgb8(image))
        .unwrap();
    bytes
}

fn sample_png_with_alpha() -> Vec<u8> {
    let image = RgbaImage::from_pixel(32, 32, image::Rgba([0, 0, 0, 0]));
    let mut bytes = Vec::new();
    image::codecs::png::PngEncoder::new(&mut bytes)
        .write_image(
            image.as_raw(),
            image.width(),
            image.height(),
            image::ExtendedColorType::Rgba8,
        )
        .unwrap();
    bytes
}

/// Insert an APP1 segment right after SOI with arbitrary (test) payload.
fn inject_app1(jpeg: &[u8], payload: &[u8]) -> Vec<u8> {
    assert_eq!(&jpeg[..2], &[0xFF, 0xD8], "expected a JPEG");
    let mut out = Vec::with_capacity(jpeg.len() + payload.len() + 4);
    out.extend_from_slice(&jpeg[..2]);
    out.push(0xFF);
    out.push(0xE1);
    out.extend_from_slice(&((payload.len() + 2) as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out.extend_from_slice(&jpeg[2..]);
    out
}

/// True when the JPEG still carries an APP1 (EXIF) segment.
fn has_app1(jpeg: &[u8]) -> bool {
    let mut index = 2;
    while index + 4 <= jpeg.len() {
        if jpeg[index] != 0xFF {
            index += 1;
            continue;
        }
        let marker = jpeg[index + 1];
        if marker == 0xE1 {
            return true;
        }
        if marker == 0xDA || marker == 0xD9 {
            return false;
        }
        if marker == 0x01 || (0xD0..=0xD7).contains(&marker) {
            index += 2;
            continue;
        }
        let length = u16::from_be_bytes([jpeg[index + 2], jpeg[index + 3]]) as usize;
        index += 2 + length;
    }
    false
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// A valid PNG whose IHDR declares an absurd size (tiny file, huge bitmap).
fn png_with_declared_size(width: u32, height: u32) -> Vec<u8> {
    let mut png = sample_png_with_alpha();
    png[16..20].copy_from_slice(&width.to_be_bytes());
    png[20..24].copy_from_slice(&height.to_be_bytes());
    let crc = crc32(&png[12..29]);
    png[29..33].copy_from_slice(&crc.to_be_bytes());
    png
}

#[test]
fn gps_exif_is_stripped() {
    let payload = b"Exif\0\0GPS-CANARY-LAT-52.5200-LON-13.4050";
    let jpeg = inject_app1(&sample_jpeg(64, 64), payload);
    assert!(
        contains(&jpeg, b"GPS-CANARY"),
        "fixture must carry the canary"
    );

    let prepared = prepare_image(&jpeg).unwrap();

    assert!(
        prepared.bytes.starts_with(&[0xFF, 0xD8]),
        "output must be JPEG"
    );
    assert!(
        !contains(&prepared.bytes, b"GPS-CANARY"),
        "GPS metadata survived the pipeline"
    );
    assert!(
        !has_app1(&prepared.bytes),
        "output still has an EXIF APP1 segment"
    );
    assert_eq!((prepared.width, prepared.height), (64, 64));
    assert!(prepared.bytes.len() <= MAX_OUTPUT_BYTES);
}

#[test]
fn oversized_edge_is_scaled_down() {
    let prepared = prepare_image(&sample_jpeg(3000, 1000)).unwrap();
    assert_eq!(prepared.width, MAX_LONG_EDGE);
    assert!(prepared.height < MAX_LONG_EDGE);
    assert!(prepared.height >= 600, "aspect ratio must be preserved");
}

#[test]
fn decompression_bomb_is_rejected() {
    let bomb = png_with_declared_size(30_000, 30_000);
    match prepare_image(&bomb) {
        Err(MediaError::TooManyPixels { width, height }) => {
            assert_eq!((width, height), (30_000, 30_000));
        }
        other => panic!("expected TooManyPixels, got {other:?}"),
    }
}

#[test]
fn unsupported_formats_are_rejected() {
    assert!(matches!(
        prepare_image(b"<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>"),
        Err(MediaError::UnsupportedFormat)
    ));
    assert!(matches!(
        prepare_image(b"%PDF-1.7 not an image"),
        Err(MediaError::UnsupportedFormat)
    ));
    assert!(matches!(
        prepare_image(&[]),
        Err(MediaError::UnsupportedFormat)
    ));
}

#[test]
fn alpha_is_flattened_onto_white() {
    let prepared = prepare_image(&sample_png_with_alpha()).unwrap();
    let decoded = image::load_from_memory(&prepared.bytes).unwrap().to_rgb8();
    let pixel = decoded.get_pixel(0, 0);
    assert!(
        pixel[0] >= 200 && pixel[1] >= 200 && pixel[2] >= 200,
        "transparent pixels must flatten to white, got {pixel:?}"
    );
}
