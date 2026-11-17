//! Result backing retains the original registry charge through owned conversion.
use super::capacity::CapacityLease;

/// An admitted read result. Borrow its value or convert it while retaining the
/// same capacity charge; dropping it releases both backing and admission bytes.
#[derive(Debug)]
pub struct RetainedRead<T> {
    value: T,
    lease: CapacityLease,
}
impl<T> RetainedRead<T> {
    pub(super) fn new(value: T, lease: CapacityLease) -> Self {
        Self { value, lease }
    }
    /// Internal projections may move backing within the existing read workspace.
    /// Allocating encoders must separately admit their simultaneous output.
    pub(in crate::ed2k_transfer) fn map<U>(self, convert: impl FnOnce(T) -> U) -> RetainedRead<U> {
        RetainedRead {
            value: convert(self.value),
            lease: self.lease,
        }
    }
    /// Admit a consumer projection before constructing it. `bytes` must cover
    /// all retained output and simultaneous conversion scratch; moved source
    /// backing remains charged by both allowances until conversion finishes.
    /// Errors and unwinding release both allowances with their actual backing.
    pub fn try_project<U>(
        self,
        bytes: usize,
        convert: impl FnOnce(T) -> anyhow::Result<U>,
    ) -> anyhow::Result<RetainedRead<U>> {
        let output_lease = self.lease.reserve_result(bytes)?;
        let output = convert(self.value)?;
        drop(self.lease);
        Ok(RetainedRead::new(output, output_lease))
    }

    /// Encode JSON into separately admitted exact-size backing. Input and output
    /// share the existing registry budget while both are live. Saturation and
    /// serialization errors release all backing owned by this call.
    pub fn serialize_json(self) -> anyhow::Result<RetainedRead<Box<[u8]>>>
    where
        T: serde::Serialize,
    {
        let mut length = EncodedLength(0);
        serde_json::to_writer(&mut length, &self.value)?;
        // WHY: escaped text can expand sixfold. Reserve the simultaneous output
        // before allocating it; reusing only the input lease undercounts backing.
        let output_lease = self.lease.reserve_result(length.0)?;
        let mut encoded = vec![0u8; length.0].into_boxed_slice();
        let mut remaining = encoded.as_mut();
        // A stateful serializer cannot grow this fixed slice beyond admission.
        serde_json::to_writer(&mut remaining, &self.value)?;
        anyhow::ensure!(remaining.is_empty(), "read encoding length changed");
        drop(self);
        Ok(RetainedRead::new(encoded, output_lease))
    }
}

/// Count without backing allocation, rejecting output larger than the entire
/// existing registry budget before an encoded buffer can be allocated.
struct EncodedLength(usize);
impl std::io::Write for EncodedLength {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len())
            .filter(|&length| length <= super::MAX_BYTES)
            .ok_or_else(|| std::io::Error::other(super::LocalMutationError::TooLarge))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl<T> std::ops::Deref for RetainedRead<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.value
    }
}
impl<'a, T> IntoIterator for &'a RetainedRead<Vec<T>> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;
    fn into_iter(self) -> Self::IntoIter {
        self.value.iter()
    }
}

#[cfg(test)]
mod tests;
