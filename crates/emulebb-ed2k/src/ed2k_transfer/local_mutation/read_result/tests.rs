use super::super::{LocalMutationError, MAX_BYTES, capacity::CapacityControl};
use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

const TEXT_BYTES: usize = 65_536;
const INPUT_CHARGE: usize = TEXT_BYTES + 4096;
const ENCODED_BYTES: usize = 6 * TEXT_BYTES + 2;

#[derive(Clone, Copy)]
enum Mode {
    Same,
    FailSecond,
    GrowSecond,
}
struct ProbedText {
    text: String,
    capacity: Arc<CapacityControl>,
    calls: Arc<AtomicUsize>,
    expected: [usize; 2],
    mode: Mode,
}
impl serde::Serialize for ProbedText {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let pass = self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(self.capacity.usage().bytes, self.expected[pass]);
        match (pass, self.mode) {
            (1, Mode::FailSecond) => Err(serde::ser::Error::custom("sample encoding failure")),
            (0, Mode::GrowSecond) => serializer.serialize_str("x"),
            _ => serializer.serialize_str(&self.text),
        }
    }
}
fn input(
    capacity: &Arc<CapacityControl>,
    bytes: usize,
    expected: [usize; 2],
    mode: Mode,
) -> (RetainedRead<ProbedText>, Arc<AtomicUsize>) {
    let lease = capacity.reserve(bytes + 4096, false, false).unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    (
        RetainedRead::new(
            ProbedText {
                text: "\0".repeat(bytes),
                capacity: Arc::clone(capacity),
                calls: Arc::clone(&calls),
                expected,
                mode,
            },
            lease,
        ),
        calls,
    )
}

#[test]
fn worst_case_escaped_text_admits_simultaneous_exact_backing_before_encoding() {
    let capacity = Arc::new(CapacityControl::default());
    let headroom = capacity
        .reserve(MAX_BYTES - INPUT_CHARGE - ENCODED_BYTES, false, false)
        .unwrap();
    let (value, calls) = input(
        &capacity,
        TEXT_BYTES,
        [MAX_BYTES - ENCODED_BYTES, MAX_BYTES],
        Mode::Same,
    );
    let encoded = value.serialize_json().unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(encoded.len(), ENCODED_BYTES);
    assert_eq!(encoded[0], b'"');
    assert!(
        encoded[1..encoded.len() - 1]
            .as_chunks::<6>()
            .0
            .iter()
            .all(|chunk| chunk == br"\u0000")
    );
    assert_eq!(encoded[encoded.len() - 1], b'"');
    assert_eq!(capacity.usage().bytes, MAX_BYTES - INPUT_CHARGE);
    drop(headroom);
    // Boxed encoded backing has exactly this length and no spare Vec capacity.
    assert_eq!(capacity.usage().bytes, ENCODED_BYTES);
    drop(encoded);
    assert_eq!(capacity.usage().bytes, 0);
}

#[test]
fn escaped_text_admission_failure_never_enters_buffered_encoding_and_releases_input() {
    let capacity = Arc::new(CapacityControl::default());
    let headroom = capacity
        .reserve(MAX_BYTES - INPUT_CHARGE, false, false)
        .unwrap();
    let (value, calls) = input(&capacity, TEXT_BYTES, [MAX_BYTES, 0], Mode::Same);
    let error = value.serialize_json().unwrap_err();
    assert!(matches!(
        error.downcast_ref::<LocalMutationError>(),
        Some(LocalMutationError::Busy)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(capacity.usage().bytes, MAX_BYTES - INPUT_CHARGE);
    drop(headroom);
    assert_eq!(capacity.usage().bytes, 0);
}

#[test]
fn escaped_output_larger_than_entire_budget_fails_without_encoded_backing() {
    let capacity = Arc::new(CapacityControl::default());
    let bytes = MAX_BYTES / 6 + 1;
    let (value, calls) = input(&capacity, bytes, [bytes + 4096, 0], Mode::Same);
    assert!(value.serialize_json().is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(capacity.usage().bytes, 0);
}

#[test]
fn encoding_error_releases_input_and_admitted_output() {
    let capacity = Arc::new(CapacityControl::default());
    let (value, calls) = input(
        &capacity,
        TEXT_BYTES,
        [INPUT_CHARGE, INPUT_CHARGE + ENCODED_BYTES],
        Mode::FailSecond,
    );
    assert!(
        value
            .serialize_json()
            .unwrap_err()
            .to_string()
            .contains("sample encoding failure")
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(capacity.usage().bytes, 0);
}

#[test]
fn stateful_serializer_cannot_grow_encoded_backing_past_admission() {
    let capacity = Arc::new(CapacityControl::default());
    let (value, calls) = input(
        &capacity,
        TEXT_BYTES,
        [INPUT_CHARGE, INPUT_CHARGE + 3],
        Mode::GrowSecond,
    );
    assert!(value.serialize_json().is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(capacity.usage().bytes, 0);
}

#[test]
fn maximum_provider_native_path_projection_and_open_copy_fit_exact_read_charge() {
    use crate::ed2k_transfer::{PAYLOAD_FILE_NAME, piece_store::job_payload_path};
    use std::path::PathBuf;
    const EXACT_CHARGE: usize = 1024 * 1024;
    const MAX_NATIVE_BYTES: usize = 65_536;
    let capacity = Arc::new(CapacityControl::default());
    let lease = capacity.reserve(EXACT_CHARGE, false, false).unwrap();
    // Three-byte BMP text maximizes Windows WTF-8 backing within the provider's
    // 65,536-byte native UTF-16 cap. Unix paths use the full byte allowance.
    #[cfg(windows)]
    let path = PathBuf::from(format!(
        "C:\\{}",
        "\u{0800}".repeat(MAX_NATIVE_BYTES / 2 - 3)
    ));
    #[cfg(not(windows))]
    let path = PathBuf::from(format!("/{}", "x".repeat(MAX_NATIVE_BYTES - 1)));
    let original_capacity = path.capacity();
    let mapped = Arc::new(RetainedRead::new(path, lease).map(job_payload_path));
    let open_copy = mapped.to_path_buf();
    assert!(mapped.ends_with(PAYLOAD_FILE_NAME));
    // Cover the original storage allocation during reallocation, another
    // maximum selected-temp path, maximum display text and fixed record data.
    let mapping_peak = 2 * original_capacity + mapped.capacity() + TEXT_BYTES + 4096;
    // The original result has been consumed. Cover both resulting path buffers,
    // native encoding scratch and path/Arc/lease metadata during native open.
    let open_peak = mapped.capacity()
        + open_copy.capacity()
        + 2 * (MAX_NATIVE_BYTES + 2 * PAYLOAD_FILE_NAME.len() + 2)
        + 4096;
    assert!(
        mapping_peak <= EXACT_CHARGE,
        "mapping backing {mapping_peak}"
    );
    assert!(open_peak <= EXACT_CHARGE, "native open backing {open_peak}");
    assert_eq!(capacity.usage().bytes, EXACT_CHARGE);
    drop(open_copy);
    drop(mapped);
    assert_eq!(capacity.usage().bytes, 0);
}

#[test]
fn consumer_projection_admits_before_conversion_and_keeps_output_charged() {
    let capacity = Arc::new(CapacityControl::default());
    let input = RetainedRead::new(
        vec![7u8; 4096],
        capacity.reserve(4096, false, false).unwrap(),
    );
    let output = input
        .try_project(8192, |value| {
            assert_eq!(capacity.usage().bytes, 12_288);
            let mut output = Vec::with_capacity(8192);
            output.extend_from_slice(&value);
            output.extend_from_slice(&value);
            Ok(output)
        })
        .unwrap();
    assert_eq!(output.len(), 8192);
    assert_eq!(capacity.usage().bytes, 8192);
    drop(output);
    assert_eq!(capacity.usage().bytes, 0);
}
#[test]
fn consumer_projection_refusal_never_runs_conversion() {
    let capacity = Arc::new(CapacityControl::default());
    let headroom = capacity.reserve(MAX_BYTES - 4096, false, false).unwrap();
    let input = RetainedRead::new(
        vec![1u8; 4096],
        capacity.reserve(4096, false, false).unwrap(),
    );
    let mut called = false;
    assert!(
        input
            .try_project(1, |_| {
                called = true;
                Ok(())
            })
            .is_err()
    );
    assert!(!called);
    assert_eq!(capacity.usage().bytes, MAX_BYTES - 4096);
    drop(headroom);
}
#[test]
fn consumer_projection_error_and_panic_release_both_allowances() {
    let capacity = Arc::new(CapacityControl::default());
    let input = RetainedRead::new(
        vec![1u8; 4096],
        capacity.reserve(4096, false, false).unwrap(),
    );
    assert!(
        input
            .try_project::<()>(8192, |_| anyhow::bail!("projection failed"))
            .is_err()
    );
    assert_eq!(capacity.usage().bytes, 0);
    let input = RetainedRead::new(
        vec![1u8; 4096],
        capacity.reserve(4096, false, false).unwrap(),
    );
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = input.try_project::<()>(8192, |_| panic!("projection panicked"));
    }));
    assert!(result.is_err());
    assert_eq!(capacity.usage().bytes, 0);
}
