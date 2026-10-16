//! Image preparation for sending (plan.md §7, I12).
//!
//! Pure byte transform: decode with a bomb guard, apply EXIF orientation, resize to
//! a bounded edge, then re-encode as JPEG. Re-encoding is what strips EXIF/GPS/ICC:
//! none of the source metadata can survive the decode/encode round trip.
//!
//! This crate must not use file / network / process APIs (I2 gate).

use std::io::Cursor;

use image::codecs::jpeg::JpegEncoder;
use image::imageops::FilterType;
use image::metadata::Orientation;
use image::{DynamicImage, ImageDecoder, ImageFormat, ImageReader};

/// Longest edge of the compressed image (plan.md §7).
pub const MAX_LONG_EDGE: u32 = 2048;

/// Decompression-bomb guard: declared source pixels may not exceed this.
pub const MAX_SOURCE_PIXELS: u64 = 40_000_000;

/// Compressed output cap (plan.md D21).
pub const MAX_OUTPUT_BYTES: usize = 1_000_000;

/// JPEG quality ladder (plan.md §7: q80 -> q70 -> q60).
const QUALITY_LADDER: [u8; 3] = [80, 70, 60];

/// A processed image ready to be put into a `MessageBody::Image`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedImage {
    pub width: u32,
    pub height: u32,
    /// JPEG bytes; always <= [`MAX_OUTPUT_BYTES`].
    pub bytes: Vec<u8>,
}

#[derive(Debug)]
pub enum MediaError {
    /// Not a JPEG / PNG / WebP / GIF (SVG, PDF and friends are rejected).
    UnsupportedFormat,
    /// Declared pixel count exceeds [`MAX_SOURCE_PIXELS`].
    TooManyPixels {
        width: u32,
        height: u32,
    },
    Decode(image::ImageError),
    Encode(image::ImageError),
    /// Still larger than [`MAX_OUTPUT_BYTES`] after the lowest quality.
    TooLarge,
}

impl std::fmt::Display for MediaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedFormat => write!(f, "unsupported image format"),
            Self::TooManyPixels { width, height } => {
                write!(f, "image too large: {width}x{height} pixels")
            }
            Self::Decode(error) => write!(f, "image decode failed: {error}"),
            Self::Encode(error) => write!(f, "image encode failed: {error}"),
            Self::TooLarge => write!(f, "image still exceeds the size limit after compression"),
        }
    }
}

impl std::error::Error for MediaError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Decode(error) | Self::Encode(error) => Some(error),
            _ => None,
        }
    }
}

/// Decode, sanitize and compress an image; the output is always JPEG.
pub fn prepare_image(input: &[u8]) -> Result<PreparedImage, MediaError> {
    let format = sniff_format(input).ok_or(MediaError::UnsupportedFormat)?;

    let reader = ImageReader::with_format(Cursor::new(input), format);
    let mut decoder = reader.into_decoder().map_err(MediaError::Decode)?;

    // Read the declared header size first: a small file can claim a huge bitmap.
    let (width, height) = decoder.dimensions();
    if u64::from(width) * u64::from(height) > MAX_SOURCE_PIXELS {
        return Err(MediaError::TooManyPixels { width, height });
    }

    // Apply EXIF orientation before stripping it, so photos are not rotated.
    let orientation = decoder.orientation().unwrap_or(Orientation::NoTransforms);
    let mut image = DynamicImage::from_decoder(decoder).map_err(MediaError::Decode)?;
    image.apply_orientation(orientation);

    if image.width().max(image.height()) > MAX_LONG_EDGE {
        image = image.resize(MAX_LONG_EDGE, MAX_LONG_EDGE, FilterType::Lanczos3);
    }
    let rgb = flatten_to_rgb8(&image);

    for quality in QUALITY_LADDER {
        let mut bytes = Vec::new();
        let mut encoder = JpegEncoder::new_with_quality(&mut bytes, quality);
        encoder.encode_image(&rgb).map_err(MediaError::Encode)?;
        if bytes.len() <= MAX_OUTPUT_BYTES {
            return Ok(PreparedImage {
                width: rgb.width(),
                height: rgb.height(),
                bytes,
            });
        }
    }
    Err(MediaError::TooLarge)
}

/// Only these formats are accepted; anything scriptable or exotic is rejected.
fn sniff_format(input: &[u8]) -> Option<ImageFormat> {
    const PNG_MAGIC: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];

    if input.len() >= 3 && input[0] == 0xFF && input[1] == 0xD8 && input[2] == 0xFF {
        return Some(ImageFormat::Jpeg);
    }
    if input.len() >= 8 && input[..8] == PNG_MAGIC {
        return Some(ImageFormat::Png);
    }
    if input.len() >= 6 && (&input[..6] == b"GIF87a" || &input[..6] == b"GIF89a") {
        return Some(ImageFormat::Gif);
    }
    if input.len() >= 12 && &input[..4] == b"RIFF" && &input[8..12] == b"WEBP" {
        return Some(ImageFormat::WebP);
    }
    None
}

/// Flatten alpha onto white; JPEG has no alpha channel and must not turn transparent
/// pixels black.
fn flatten_to_rgb8(image: &DynamicImage) -> image::RgbImage {
    let rgba = image.to_rgba8();
    image::RgbImage::from_fn(rgba.width(), rgba.height(), |x, y| {
        let pixel = rgba.get_pixel(x, y);
        let alpha = u16::from(pixel[3]);
        let blend = |channel: u8| -> u8 {
            ((u16::from(channel) * alpha + 255 * (255 - alpha)) / 255) as u8
        };
        image::Rgb([blend(pixel[0]), blend(pixel[1]), blend(pixel[2])])
    })
}
