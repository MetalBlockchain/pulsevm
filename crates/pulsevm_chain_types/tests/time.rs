use pulsevm_chain_types::{
    BlockTimestamp,
    Microseconds,
    TimePoint,
    TimePointSec,
    days,
    hours,
    microseconds,
    milliseconds,
    minutes,
    seconds,
};
use serde::{
    Deserialize,
    de::value::{
        Error,
        StringDeserializer,
    },
};

mod common;
use common::assert_wire;

#[test]
fn duration_units_arithmetic_and_signed_truncation() {
    assert_eq!(Microseconds::default(), microseconds(0));
    assert_eq!(Microseconds::maximum().count(), i64::MAX);
    for sign in [-1, 0, 1] {
        assert_eq!(milliseconds(sign), microseconds(sign * 1000));
        assert_eq!(seconds(sign), milliseconds(sign * 1000));
        assert_eq!(minutes(sign), seconds(sign * 60));
        assert_eq!(hours(sign), minutes(sign * 60));
        assert_eq!(days(sign), hours(sign * 24));
    }
    assert_eq!(microseconds(1_999_999).to_seconds(), 1);
    assert_eq!(microseconds(-1_999_999).to_seconds(), -1);
    let mut duration = seconds(2);
    duration += milliseconds(500);
    assert_eq!(duration, seconds(2) + milliseconds(500));
    duration -= seconds(3);
    assert_eq!(duration, milliseconds(-500));
    assert_eq!(seconds(2) - seconds(3), seconds(-1));
    assert!(seconds(-1) < Microseconds::default());
}

#[test]
fn time_point_arithmetic_preserves_microseconds() {
    let origin = TimePoint::new(microseconds(1_234_567));
    let mut point = origin + milliseconds(1);
    assert_eq!(point.time_since_epoch().count(), 1_235_567);
    assert_eq!(point.sec_since_epoch(), 1);
    assert_eq!(point - origin, milliseconds(1));
    assert_eq!(point - milliseconds(1), origin);
    point += seconds(1);
    point -= milliseconds(1);
    assert_eq!(point, origin + seconds(1));
    assert_eq!(origin + origin, TimePoint::new(microseconds(2_469_134)));
    assert!(origin < point);
    assert_eq!(origin.partial_cmp(&origin), Some(std::cmp::Ordering::Equal));
}

#[test]
fn time_point_parsing_accepts_eos_formats_and_rejects_invalid_dates() {
    for (text, micros) in [
        ("1970-01-01T00:00:00", 0),
        ("1970-01-01T00:00:01Z", 1_000_000),
        ("1970-01-01T00:00:00.123", 123_000),
        ("1970-01-01T00:00:00.123Z  ", 123_000),
        ("1969-12-31T23:59:59.500Z", -500_000),
        ("2000-02-29T00:00:00", 951_782_400_000_000),
    ] {
        assert_eq!(
            text.parse::<TimePoint>()
                .unwrap()
                .time_since_epoch()
                .count(),
            micros
        );
        assert_eq!(
            serde_json::from_value::<TimePoint>(serde_json::json!(text)).unwrap(),
            TimePoint::new(microseconds(micros))
        );
    }
    let whole = TimePoint::new(seconds(946_684_800));
    assert_eq!(whole.to_string(), "2000-01-01T00:00:00.000Z");
    assert_eq!(
        serde_json::to_string(&whole).unwrap(),
        "\"2000-01-01T00:00:00.000Z\""
    );
    let owned = StringDeserializer::<Error>::new("2000-01-01T00:00:00Z".into());
    assert_eq!(TimePoint::deserialize(owned).unwrap(), whole);
    for text in [
        "",
        "not-a-date",
        "1900-02-29T00:00:00",
        "2000-13-01T00:00:00",
        "2000-01-01T24:00:00",
        "2000-01-01T00:00:00+01:00",
    ] {
        assert!(
            text.parse::<TimePoint>()
                .unwrap_err()
                .contains("invalid EOS time_point")
        );
        assert!(serde_json::from_value::<TimePoint>(serde_json::json!(text)).is_err());
    }
    assert!(
        serde_json::from_str::<TimePoint>("42")
            .unwrap_err()
            .to_string()
            .contains("EOS time string")
    );
}

#[test]
fn seconds_timestamp_parsing_bounds_and_json() {
    for (text, expected) in [
        ("1970-01-01T00:00:00", 0),
        ("1970-01-01T00:00:00Z", 0),
        ("2106-02-07T06:28:15Z", u32::MAX),
    ] {
        let value = text.parse::<TimePointSec>().unwrap();
        assert_eq!(value.sec_since_epoch(), expected);
        assert_eq!(value.to_string().parse::<TimePointSec>().unwrap(), value);
        assert_eq!(
            serde_json::from_str::<TimePointSec>(&serde_json::to_string(&value).unwrap()).unwrap(),
            value
        );
    }
    assert_eq!(TimePointSec::min(), TimePointSec::default());
    assert_eq!(TimePointSec::maximum(), TimePointSec::new(u32::MAX));
    assert_eq!(
        TimePointSec::deserialize(StringDeserializer::<Error>::new(
            "1970-01-01T00:00:00Z".into()
        ))
        .unwrap(),
        TimePointSec::min()
    );
    for text in ["1969-12-31T23:59:59Z", "2106-02-07T06:28:16Z"] {
        assert!(
            text.parse::<TimePointSec>()
                .unwrap_err()
                .contains("out of range")
        );
    }
    for text in [
        "",
        "2001-02-29T00:00:00",
        "1970-01-01T00:00:00.500Z",
        "1970-01-01T00:00:00Z ",
    ] {
        assert!(text.parse::<TimePointSec>().is_err());
        assert!(serde_json::from_value::<TimePointSec>(serde_json::json!(text)).is_err());
    }
    assert!(
        serde_json::from_str::<TimePointSec>("null")
            .unwrap_err()
            .to_string()
            .contains("EOS time string")
    );
}

#[test]
fn seconds_timestamp_conversions_truncate_and_addition_wraps() {
    for (micros, expected) in [
        (1_999_999, 1),
        (-999_999, 0),
        (-1_000_000, u32::MAX),
        (4_294_967_296_000_000, 0),
    ] {
        assert_eq!(
            TimePointSec::from(TimePoint::new(microseconds(micros))).sec_since_epoch(),
            expected
        );
    }
    for value in [0, 1, u32::MAX] {
        let sec = TimePointSec::new(value);
        assert_eq!(
            TimePoint::from(sec).time_since_epoch(),
            seconds(i64::from(value))
        );
        assert_eq!(TimePoint::from(&sec), TimePoint::from(sec));
    }
    let mut sec = TimePointSec::maximum();
    assert_eq!(sec + 1, TimePointSec::min());
    sec += 2;
    assert_eq!(sec, TimePointSec::new(1));
}

#[test]
fn block_slots_convert_at_half_second_boundaries() {
    assert_eq!(BlockTimestamp::min(), BlockTimestamp::default());
    assert_eq!(BlockTimestamp::maximum().slot(), 0xffff);
    for (slot, text) in [
        (0, "2000-01-01T00:00:00.000"),
        (1, "2000-01-01T00:00:00.500"),
        (2, "2000-01-01T00:00:01.000"),
    ] {
        let block = BlockTimestamp::new(slot);
        assert_eq!(block.to_eos_string(), text);
        assert_eq!(
            serde_json::to_value(block).unwrap(),
            serde_json::json!(text)
        );
        for input in [text.to_owned(), format!("{text}Z")] {
            assert_eq!(
                serde_json::from_value::<BlockTimestamp>(serde_json::json!(input)).unwrap(),
                block
            );
        }
        let tp = block.to_time_point();
        assert_eq!(
            tp.time_since_epoch().count(),
            946_684_800_000_000 + i64::from(slot) * 500_000
        );
        assert_eq!(TimePoint::from(block), tp);
        assert_eq!(BlockTimestamp::from(tp), block);
        assert_eq!(BlockTimestamp::from(&tp), block);
        assert_eq!(BlockTimestamp::from(tp + microseconds(499_999)), block);
        let grpc = prost_types::Timestamp::from(&block);
        assert_eq!(grpc.seconds, 946_684_800 + i64::from(slot / 2));
        assert_eq!(grpc.nanos, (slot % 2) as i32 * 500_000_000);
        assert_eq!(block.next().slot(), slot + 1);
    }
    let max = BlockTimestamp::new(u32::MAX);
    assert_eq!(BlockTimestamp::new(u32::MAX - 1).next(), max);
    assert_eq!(BlockTimestamp::from(max.to_time_point()), max);
    assert_eq!(
        serde_json::from_str::<BlockTimestamp>(&serde_json::to_string(&max).unwrap()).unwrap(),
        max
    );
    assert_eq!(
        serde_json::from_str::<BlockTimestamp>("\"2000-01-01T00:00:00\"").unwrap(),
        BlockTimestamp::min()
    );
}

#[test]
fn block_timestamps_reject_unaligned_pre_epoch_and_malformed_json() {
    for (text, message) in [
        ("1999-12-31T23:59:59.500", "before EOS"),
        ("2000-01-01T00:00:00.001", "500ms boundary"),
        ("2000-01-01T00:00:00.499", "500ms boundary"),
        ("2000-01-01T00:00:00.501", "500ms boundary"),
        ("garbage", "invalid block timestamp"),
        ("2001-02-29T00:00:00", "invalid block timestamp"),
    ] {
        assert!(
            serde_json::from_value::<BlockTimestamp>(serde_json::json!(text))
                .unwrap_err()
                .to_string()
                .contains(message)
        );
    }
    assert!(
        serde_json::from_str::<BlockTimestamp>("123")
            .unwrap_err()
            .to_string()
            .contains("EOS block timestamp")
    );
}

#[test]
#[should_panic(expected = "block timestamp overflow")]
fn next_block_slot_panics_at_u32_max() {
    BlockTimestamp::new(u32::MAX).next();
}

#[test]
fn time_wire_encodings_are_fixed_width_little_endian() {
    for value in [i64::MIN, -1, 0, 0x0807060504030201, i64::MAX] {
        assert_wire(&Microseconds::new(value), &value.to_le_bytes());
        assert_wire(&TimePoint::new(microseconds(value)), &value.to_le_bytes());
    }
    for value in [0u32, 1, 0x04030201, u32::MAX] {
        assert_wire(&TimePointSec::new(value), &value.to_le_bytes());
        assert_wire(&BlockTimestamp::new(value), &value.to_le_bytes());
    }
}
