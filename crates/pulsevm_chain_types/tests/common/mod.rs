use std::fmt::Debug;

use pulsevm_serialization::{
    NumBytes,
    Read,
    Write,
};

// Check against independent wire bytes, not just a potentially symmetric round trip.
pub fn assert_wire<T: Debug + PartialEq + NumBytes + Read + Write>(value: &T, bytes: &[u8]) {
    assert_eq!(value.num_bytes(), bytes.len());
    assert_eq!(value.pack().unwrap(), bytes);
    let mut framed = vec![0xa5; bytes.len() + 2];
    let mut pos = 1;
    value.write(&mut framed, &mut pos).unwrap();
    assert_eq!(pos, bytes.len() + 1);
    assert_eq!(framed[0], 0xa5);
    assert_eq!(framed[pos], 0xa5);
    pos = 1;
    assert_eq!(&T::read(&framed, &mut pos).unwrap(), value);
    assert_eq!(pos, bytes.len() + 1);
    for len in 0..bytes.len() {
        assert!(T::read(&bytes[..len], &mut 0).is_err(), "read length {len}");
        assert!(
            value.write(&mut vec![0; len], &mut 0).is_err(),
            "write length {len}"
        );
    }
}
