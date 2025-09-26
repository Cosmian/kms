use num_traits::Signed as _;

use crate::ttlv::{
    kmip_big_int,
    tags::BYTE_LIKE_TAGS,
    ttlv_struct::{TTLV, TTLValue},
}; // for BigInt::abs

// Collapse an Adjacently tagged structure with a tag and a content into a single TTLV element.
// See kmip_ttlv_serializer.rs for the documentation example of _t/_c collapse.
pub(crate) fn collapse_adjacently_tagged_structure(ttlv: &mut TTLV) {
    if let TTLValue::Structure(items) = &mut ttlv.value {
        if items.len() == 2 {
            if let Some(v) = items
                .iter()
                .find(|i| i.tag == "_c")
                .map(|c| c.value.clone())
            {
                ttlv.value = v;
            }
        }
    }
}

fn bytes_from(node: &TTLV) -> Option<Vec<u8>> {
    fn collect(n: &TTLV, out: &mut Vec<u8>) -> bool {
        match &n.value {
            TTLValue::ByteString(bs) => {
                out.extend_from_slice(bs);
                true
            }
            TTLValue::Integer(v) if (0..=255).contains(v) => u8::try_from(*v)
                .map(|b| {
                    out.push(b);
                    true
                })
                .unwrap_or(false),
            TTLValue::Structure(inner) => inner.iter().all(|c| collect(c, out)),
            _ => false,
        }
    }
    let mut buf = Vec::new();
    if collect(node, &mut buf) {
        Some(buf)
    } else {
        None
    }
}

/// Post-serialization normalization pass. See prior implementation notes in serializer.
pub(crate) fn normalize_ttlv(ttlv: &mut TTLV) {
    match &mut ttlv.value {
        TTLValue::Structure(items) => {
            let mut pending_replacement: Option<TTLValue> = None;
            {
                let items_mut: &mut Vec<TTLV> = items;

                // 0) Retag _c-only children to parent tag (except AttributeValue which is handled later)
                if ttlv.tag != "AttributeValue"
                    && !items_mut.is_empty()
                    && items_mut.iter().all(|c| c.tag == "_c")
                {
                    for ch in items_mut.iter_mut() {
                        ch.tag.clone_from(&ttlv.tag);
                    }
                }

                // 1) Collapse adjacency _t/_c
                if items_mut.iter().any(|c| c.tag == "_t")
                    && items_mut.iter().any(|c| c.tag == "_c")
                {
                    let mut content_children: Vec<TTLV> = items_mut
                        .iter()
                        .filter(|c| c.tag == "_c")
                        .cloned()
                        .collect();
                    if !content_children.is_empty() {
                        let type_tag = items_mut
                            .iter()
                            .find(|c| c.tag == "_t")
                            .and_then(|t| match &t.value {
                                TTLValue::Enumeration(e) => Some(e.name.clone()),
                                _ => None,
                            })
                            .unwrap_or_else(|| ttlv.tag.clone());

                        for ch in &mut content_children {
                            ch.tag.clone_from(&type_tag);
                            if let TTLValue::Structure(ref mut grandkids) = ch.value {
                                for g in grandkids {
                                    g.tag.clone_from(&type_tag);
                                }
                            }
                        }

                        let mut temp = if content_children.len() == 1 {
                            TTLV {
                                tag: type_tag,
                                value: content_children.remove(0).value,
                            }
                        } else {
                            TTLV {
                                tag: type_tag,
                                value: TTLValue::Structure(content_children),
                            }
                        };
                        normalize_ttlv(&mut temp);

                        pending_replacement = Some(temp.value);
                    }
                }

                // 2) Interval as single Integer child
                if pending_replacement.is_none() && ttlv.tag == "Interval" && items_mut.len() == 1 {
                    if let Some(TTLV {
                        value: TTLValue::Integer(v),
                        ..
                    }) = items_mut.first()
                    {
                        if let Ok(u) = u32::try_from(*v) {
                            pending_replacement = Some(TTLValue::Interval(u));
                        }
                    }
                }

                // 2b) AttributeValue unwrap
                if pending_replacement.is_none()
                    && ttlv.tag == "AttributeValue"
                    && !items_mut.is_empty()
                {
                    if items_mut.len() == 1 {
                        if let Some(first) = items_mut.first() {
                            pending_replacement = Some(first.value.clone());
                        }
                    } else {
                        const TYPE_TAGS: &[&str] = &[
                            "TextString",
                            "Integer",
                            "LongInteger",
                            "BigInteger",
                            "ByteString",
                            "Boolean",
                            "DateTime",
                            "Interval",
                            "DateTimeExtended",
                        ];
                        if let Some(idx) = items_mut
                            .iter()
                            .position(|c| TYPE_TAGS.contains(&c.tag.as_str()))
                        {
                            if let Some(el) = items_mut.get(idx) {
                                pending_replacement = Some(el.value.clone());
                            }
                        }
                    }
                }

                // 2c) Aggressive nested unwrap for known byte-vector tags
                if pending_replacement.is_none()
                    && !items_mut.is_empty()
                    && BYTE_LIKE_TAGS.contains(&ttlv.tag.as_str())
                    && items_mut.len() == 1
                {
                    let Some(child) = items_mut.first() else {
                        return;
                    };
                    if matches!(child.value, TTLValue::Structure(_))
                        || matches!(child.value, TTLValue::ByteString(_))
                    {
                        pending_replacement = Some(child.value.clone());
                    }
                }

                // 3) ByteString collapse for whitelisted tags from runs of Integer(0..255)
                if pending_replacement.is_none() && !items_mut.is_empty() {
                    let first_tag = items_mut.first().map(|c| c.tag.as_str());
                    let all_same_tag = items_mut.iter().all(|c| Some(c.tag.as_str()) == first_tag);
                    let all_bytes = items_mut
                        .iter()
                        .all(|c| matches!(c.value, TTLValue::Integer(0..=255)));
                    if all_same_tag && all_bytes {
                        let child_tag = items_mut.first().map_or("", |c| c.tag.as_str());
                        let collapse_as_bytestring = (BYTE_LIKE_TAGS.contains(&child_tag)
                            && child_tag == ttlv.tag)
                            || (ttlv.tag == "AttributeValue" && child_tag == "_c");
                        if collapse_as_bytestring {
                            let bytes: Vec<u8> = items_mut
                                .iter()
                                .filter_map(|c| {
                                    if let TTLValue::Integer(v) = c.value {
                                        u8::try_from(v).ok()
                                    } else {
                                        None
                                    }
                                })
                                .collect();
                            pending_replacement = Some(TTLValue::ByteString(bytes));
                        }
                    }
                }

                // 4) Named fields DateTime synthesis
                if pending_replacement.is_none() && !items_mut.is_empty() {
                    use std::collections::HashMap;
                    let mut map = HashMap::new();
                    for el in items_mut.iter() {
                        if let TTLValue::Integer(v) = el.value {
                            map.insert(el.tag.as_str(), v);
                        }
                    }
                    if map.contains_key("Year")
                        && map.contains_key("DayOfYear")
                        && map.contains_key("Hour")
                        && map.contains_key("Minute")
                        && map.contains_key("Second")
                        && map.contains_key("OffsetSign")
                        && map.contains_key("OffsetHour")
                        && map.contains_key("OffsetMinute")
                    {
                        if let (
                            Some(year),
                            Some(day),
                            Some(hour),
                            Some(minute),
                            Some(second),
                            Some(offset_sign),
                            Some(offset_hour),
                            Some(offset_minute),
                        ) = (
                            map.get("Year"),
                            map.get("DayOfYear"),
                            map.get("Hour"),
                            map.get("Minute"),
                            map.get("Second"),
                            map.get("OffsetSign"),
                            map.get("OffsetHour"),
                            map.get("OffsetMinute"),
                        ) {
                            if *day > 0
                                && *day <= 366
                                && *hour >= 0
                                && *hour < 24
                                && *minute >= 0
                                && *minute < 60
                                && *second >= 0
                                && *second < 61
                            {
                                if let Ok(jan1) =
                                    time::Date::from_calendar_date(*year, time::Month::January, 1)
                                {
                                    if let Some(date) =
                                        jan1.checked_add(time::Duration::days(i64::from(*day - 1)))
                                    {
                                        let mut oh = *offset_hour;
                                        let mut om = *offset_minute;
                                        if *offset_sign < 0 {
                                            oh = -oh;
                                            om = -om;
                                        }
                                        if let (Ok(offset), Ok(tm)) = (
                                            time::UtcOffset::from_hms(
                                                i8::try_from(oh).unwrap_or(0),
                                                i8::try_from(om).unwrap_or(0),
                                                0,
                                            ),
                                            time::Time::from_hms(
                                                u8::try_from(*hour).unwrap_or(0),
                                                u8::try_from(*minute).unwrap_or(0),
                                                u8::try_from(*second).unwrap_or(0),
                                            ),
                                        ) {
                                            pending_replacement = Some(TTLValue::DateTime(
                                                date.with_time(tm).assume_offset(offset),
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // 4b) Sliding window DateTime synthesis
                if pending_replacement.is_none() && items_mut.len() >= 9 {
                    let mut idx = 0_usize;
                    while idx + 8 < items_mut.len() {
                        let Some(window) = items_mut.get(idx..idx + 9) else {
                            break;
                        };
                        let tags_match_parent_or_c = window.iter().all(|c| {
                            c.tag == ttlv.tag || (ttlv.tag == "AttributeValue" && c.tag == "_c")
                        });
                        if tags_match_parent_or_c
                            && window
                                .iter()
                                .all(|c| matches!(c.value, TTLValue::Integer(_)))
                        {
                            let (
                                year,
                                day_of_year,
                                hour,
                                minute,
                                second,
                                fractional_or_reserved,
                                off_h,
                                off_m,
                                off_s_or_res,
                            ) = match window {
                                [
                                    year_node,
                                    doy_node,
                                    hour_node,
                                    minute_node,
                                    second_node,
                                    frac_node,
                                    offh_node,
                                    offm_node,
                                    offs_node,
                                ] => match (
                                    &year_node.value,
                                    &doy_node.value,
                                    &hour_node.value,
                                    &minute_node.value,
                                    &second_node.value,
                                    &frac_node.value,
                                    &offh_node.value,
                                    &offm_node.value,
                                    &offs_node.value,
                                ) {
                                    (
                                        TTLValue::Integer(v0),
                                        TTLValue::Integer(v1),
                                        TTLValue::Integer(v2),
                                        TTLValue::Integer(v3),
                                        TTLValue::Integer(v4),
                                        TTLValue::Integer(v5),
                                        TTLValue::Integer(v6),
                                        TTLValue::Integer(v7),
                                        TTLValue::Integer(v8),
                                    ) => (*v0, *v1, *v2, *v3, *v4, *v5, *v6, *v7, *v8),
                                    _ => (0, 0, 0, 0, 0, 0, 0, 0, 0),
                                },
                                _ => (0, 0, 0, 0, 0, 0, 0, 0, 0),
                            };
                            if year >= 0
                                && (1..=366).contains(&day_of_year)
                                && (0..24).contains(&hour)
                                && (0..60).contains(&minute)
                                && (0..=61).contains(&second)
                                && fractional_or_reserved >= 0
                                && off_h.abs() <= 23
                                && off_m.abs() <= 59
                            {
                                const MDAYS: [i32; 12] =
                                    [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
                                let leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
                                let mut remaining = day_of_year;
                                let mut month = 1;
                                for (m_idx, md) in MDAYS.iter().enumerate() {
                                    let dim = if m_idx == 1 {
                                        if leap { 29 } else { 28 }
                                    } else {
                                        *md
                                    };
                                    if remaining > dim {
                                        remaining -= dim;
                                        month += 1;
                                    } else {
                                        break;
                                    }
                                }
                                let day = remaining;
                                if (1..=31).contains(&day) {
                                    if let Ok(month_enum) =
                                        time::Month::try_from(u8::try_from(month).unwrap_or(1))
                                    {
                                        if let Ok(date) = time::Date::from_calendar_date(
                                            year,
                                            month_enum,
                                            u8::try_from(day).unwrap_or(1),
                                        ) {
                                            let frac_ns: u32 =
                                                u32::try_from(fractional_or_reserved.max(0))
                                                    .unwrap_or(0)
                                                    .min(999_999_999);
                                            if let Ok(time_) = time::Time::from_hms_nano(
                                                u8::try_from(hour).unwrap_or(0),
                                                u8::try_from(minute).unwrap_or(0),
                                                u8::try_from(second).unwrap_or(0),
                                                frac_ns,
                                            ) {
                                                let off_s = off_s_or_res;
                                                let total_offset = if off_s.abs() <= 59 {
                                                    off_h * 3600 + off_m * 60 + off_s
                                                } else {
                                                    off_h * 3600 + off_m * 60
                                                };
                                                if let Ok(offset) =
                                                    time::UtcOffset::from_whole_seconds(
                                                        total_offset,
                                                    )
                                                {
                                                    pending_replacement = Some(TTLValue::DateTime(
                                                        date.with_time(time_).assume_offset(offset),
                                                    ));
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        idx += 1;
                    }
                }

                // Recurse into children when no early replacement
                if pending_replacement.is_none() {
                    for child in items_mut.iter_mut() {
                        normalize_ttlv(child);
                    }
                }

                // DateTimeExtended under DateTime parent
                if pending_replacement.is_none() && ttlv.tag == "DateTime" && items_mut.len() == 1 {
                    if let Some(child) = items_mut.first() {
                        if child.tag == "DateTime" {
                            match child.value {
                                TTLValue::LongInteger(v) => {
                                    pending_replacement =
                                        Some(TTLValue::DateTimeExtended(i128::from(v)));
                                }
                                TTLValue::Integer(v) => {
                                    pending_replacement =
                                        Some(TTLValue::DateTimeExtended(i128::from(v)));
                                }
                                _ => {}
                            }
                        }
                    }
                }

                // BigInteger normalization and sibling merge logic
                if pending_replacement.is_none() {
                    let try_collapse_digits_run = |parent_tag: &str,
                                                   sign_hint: i8|
                     -> Option<TTLValue> {
                        if items_mut.is_empty() {
                            return None;
                        }
                        if !items_mut.iter().all(|c| c.tag == parent_tag) {
                            return None;
                        }
                        let mut digits: Vec<u32> = Vec::new();
                        for c in items_mut.iter() {
                            match c.value {
                                TTLValue::Integer(v) => {
                                    let Ok(u) = u32::try_from(v) else { return None };
                                    digits.push(u);
                                }
                                TTLValue::LongInteger(v) => {
                                    let Ok(u) = u32::try_from(v) else { return None };
                                    digits.push(u);
                                }
                                _ => return None,
                            }
                        }
                        if digits.is_empty() {
                            return None;
                        }
                        let sign = match sign_hint.cmp(&0) {
                            std::cmp::Ordering::Less => -1,
                            std::cmp::Ordering::Equal => 0,
                            std::cmp::Ordering::Greater => 1,
                        };
                        if let Ok(kbi) = kmip_big_int::KmipBigInt::from_u32_digits(sign, &digits) {
                            return Some(TTLValue::BigInteger(kbi));
                        }
                        None
                    };

                    let try_collapse_sign_and_child_big = |parent_tag: &str| -> Option<TTLValue> {
                        if items_mut.len() < 2 {
                            return None;
                        }
                        if !items_mut.iter().all(|c| c.tag == parent_tag) {
                            return None;
                        }

                        let sign_val: i32 = items_mut
                            .iter()
                            .find_map(|e| match e.value {
                                TTLValue::Integer(v) => Some(v),
                                _ => None,
                            })
                            .unwrap_or(0);

                        if let Some(kbi_inner) = items_mut.iter().find_map(|e| match &e.value {
                            TTLValue::BigInteger(bi) => Some(bi.clone()),
                            _ => None,
                        }) {
                            let big_mag = num_bigint_dig::BigInt::from(kbi_inner).abs();
                            let new_big = match sign_val.cmp(&0) {
                                std::cmp::Ordering::Less => -big_mag,
                                std::cmp::Ordering::Equal => num_bigint_dig::BigInt::from(0),
                                std::cmp::Ordering::Greater => big_mag,
                            };
                            return Some(TTLValue::BigInteger(super::KmipBigInt::from(new_big)));
                        }

                        if let Some(inner) = items_mut.iter().find_map(|e| match &e.value {
                            TTLValue::Structure(inner) => Some(inner),
                            _ => None,
                        }) {
                            if !inner.is_empty()
                                && inner.iter().all(|e| {
                                    e.tag == parent_tag
                                        && matches!(
                                            e.value,
                                            TTLValue::Integer(_) | TTLValue::LongInteger(_)
                                        )
                                })
                            {
                                let mut digits: Vec<u32> = Vec::with_capacity(inner.len());
                                for e in inner {
                                    match e.value {
                                        TTLValue::Integer(v) => {
                                            if let Ok(u) = u32::try_from(v) {
                                                digits.push(u);
                                            } else {
                                                return None;
                                            }
                                        }
                                        TTLValue::LongInteger(v) => {
                                            if let Ok(u) = u32::try_from(v) {
                                                digits.push(u);
                                            } else {
                                                return None;
                                            }
                                        }
                                        _ => {
                                            return None;
                                        }
                                    }
                                }
                                let sign = match sign_val.cmp(&0) {
                                    std::cmp::Ordering::Less => -1,
                                    std::cmp::Ordering::Equal => 0,
                                    std::cmp::Ordering::Greater => 1,
                                };
                                if let Ok(kbi) =
                                    kmip_big_int::KmipBigInt::from_u32_digits(sign, &digits)
                                {
                                    return Some(TTLValue::BigInteger(kbi));
                                }
                            }
                        }
                        None
                    };

                    if ttlv.tag == "BigInteger" && !items_mut.is_empty() {
                        if let Some(val) = try_collapse_digits_run("BigInteger", 1) {
                            pending_replacement = Some(val);
                        }
                        if pending_replacement.is_none() && items_mut.len() >= 2 {
                            if let (Some(sign_el), Some(inner_el)) = (
                                items_mut.iter().find(|e| e.tag == "Sign"),
                                items_mut.iter().find(|e| e.tag == "BigInteger"),
                            ) {
                                if let (TTLValue::Integer(sign_val), TTLValue::Structure(inner)) =
                                    (&sign_el.value, &inner_el.value)
                                {
                                    if !inner.is_empty()
                                        && inner.iter().all(|e| {
                                            e.tag == "BigInteger"
                                                && matches!(
                                                    e.value,
                                                    TTLValue::Integer(_) | TTLValue::LongInteger(_)
                                                )
                                        })
                                    {
                                        let mut digits: Vec<u32> = Vec::with_capacity(inner.len());
                                        let mut all_ok = true;
                                        for e in inner {
                                            match e.value {
                                                TTLValue::Integer(v) => {
                                                    if let Ok(u) = u32::try_from(v) {
                                                        digits.push(u);
                                                    } else {
                                                        all_ok = false;
                                                        break;
                                                    }
                                                }
                                                TTLValue::LongInteger(v) => {
                                                    if let Ok(u) = u32::try_from(v) {
                                                        digits.push(u);
                                                    } else {
                                                        all_ok = false;
                                                        break;
                                                    }
                                                }
                                                _ => {}
                                            }
                                        }
                                        if all_ok {
                                            let sign = match sign_val.cmp(&0) {
                                                std::cmp::Ordering::Less => -1,
                                                std::cmp::Ordering::Equal => 0,
                                                std::cmp::Ordering::Greater => 1,
                                            };
                                            if let Ok(kbi) =
                                                kmip_big_int::KmipBigInt::from_u32_digits(
                                                    sign, &digits,
                                                )
                                            {
                                                pending_replacement =
                                                    Some(TTLValue::BigInteger(kbi));
                                            }
                                        }
                                    } else if inner.len() == 1 {
                                        if let Some(single) = inner.first() {
                                            if let TTLValue::BigInteger(ref kbi_inner) =
                                                single.value
                                            {
                                                let mut big =
                                                    num_bigint_dig::BigInt::from(kbi_inner.clone());
                                                big = match sign_val.cmp(&0) {
                                                    std::cmp::Ordering::Less => -big,
                                                    std::cmp::Ordering::Equal => {
                                                        num_bigint_dig::BigInt::from(0)
                                                    }
                                                    std::cmp::Ordering::Greater => big,
                                                };
                                                pending_replacement = Some(TTLValue::BigInteger(
                                                    super::KmipBigInt::from(big),
                                                ));
                                            }
                                        }
                                    }
                                }
                            }
                            if pending_replacement.is_none() {
                                if let Some(sign_idx) = items_mut
                                    .iter()
                                    .position(|e| matches!(e.value, TTLValue::Integer(_)))
                                {
                                    let sign_val = match items_mut.get(sign_idx) {
                                        Some(TTLV {
                                            value: TTLValue::Integer(v),
                                            ..
                                        }) => *v,
                                        _ => 1,
                                    };
                                    if let Some(kbi_inner) =
                                        items_mut.iter().find_map(|e| match &e.value {
                                            TTLValue::BigInteger(bi) => Some(bi.clone()),
                                            _ => None,
                                        })
                                    {
                                        let big_mag = num_bigint_dig::BigInt::from(kbi_inner).abs();
                                        let new_big = match sign_val.cmp(&0) {
                                            std::cmp::Ordering::Less => -big_mag,
                                            std::cmp::Ordering::Equal => {
                                                num_bigint_dig::BigInt::from(0)
                                            }
                                            std::cmp::Ordering::Greater => big_mag,
                                        };
                                        pending_replacement = Some(TTLValue::BigInteger(
                                            super::KmipBigInt::from(new_big),
                                        ));
                                    } else if let Some(inner) =
                                        items_mut.iter().find_map(|e| match &e.value {
                                            TTLValue::Structure(inner) => Some(inner),
                                            _ => None,
                                        })
                                    {
                                        if !inner.is_empty()
                                            && inner.iter().all(|e| {
                                                matches!(
                                                    e.value,
                                                    TTLValue::Integer(_) | TTLValue::LongInteger(_)
                                                )
                                            })
                                        {
                                            let mut digits: Vec<u32> =
                                                Vec::with_capacity(inner.len());
                                            for e in inner {
                                                match e.value {
                                                    TTLValue::Integer(v) => {
                                                        if let Ok(u) = u32::try_from(v) {
                                                            digits.push(u);
                                                        }
                                                    }
                                                    TTLValue::LongInteger(v) => {
                                                        if let Ok(u) = u32::try_from(v) {
                                                            digits.push(u);
                                                        }
                                                    }
                                                    _ => {}
                                                }
                                            }
                                            let sign = match sign_val.cmp(&0) {
                                                std::cmp::Ordering::Less => -1,
                                                std::cmp::Ordering::Equal => 0,
                                                std::cmp::Ordering::Greater => 1,
                                            };
                                            if let Ok(kbi) =
                                                kmip_big_int::KmipBigInt::from_u32_digits(
                                                    sign, &digits,
                                                )
                                            {
                                                pending_replacement =
                                                    Some(TTLValue::BigInteger(kbi));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Known BigInt field tags
                    if pending_replacement.is_none() {
                        const BIGINT_FIELD_TAGS: &[&str] = &[
                            "Modulus",
                            "PublicExponent",
                            "PrivateExponent",
                            "PrimeExponentP",
                            "PrimeExponentQ",
                            "CrtCoefficient",
                            "CRTCoefficient",
                            "P",
                            "Q",
                            "G",
                            "J",
                            "Y",
                            "X",
                            "D",
                        ];
                        if BIGINT_FIELD_TAGS.contains(&ttlv.tag.as_str()) {
                            if let Some(val) = try_collapse_digits_run(ttlv.tag.as_str(), 1) {
                                pending_replacement = Some(val);
                            }
                            if pending_replacement.is_none() {
                                if let Some(val) =
                                    try_collapse_sign_and_child_big(ttlv.tag.as_str())
                                {
                                    pending_replacement = Some(val);
                                }
                            }
                        }
                    }

                    // Tests and unambiguous generic collapse
                    if pending_replacement.is_none() {
                        const TEST_BIGINT_TAGS: &[&str] = &["BigIntNeg", "BigIntPos", "TheBigUint"];
                        if TEST_BIGINT_TAGS.contains(&ttlv.tag.as_str()) {
                            let sign = if ttlv.tag == "BigIntNeg" { -1 } else { 1 };
                            if let Some(val) = try_collapse_digits_run(ttlv.tag.as_str(), sign) {
                                pending_replacement = Some(val);
                            }
                        }
                    }

                    if pending_replacement.is_none() {
                        const TEST_BIGINT_TAGS: &[&str] = &["BigIntNeg", "BigIntPos"];
                        if TEST_BIGINT_TAGS.contains(&ttlv.tag.as_str()) {
                            if let Some(val) = try_collapse_sign_and_child_big(ttlv.tag.as_str()) {
                                pending_replacement = Some(val);
                            }
                        }
                    }

                    if pending_replacement.is_none() && !items_mut.is_empty() {
                        let all_same_tag = items_mut.iter().all(|c| c.tag == ttlv.tag);
                        let all_numeric = items_mut.iter().all(|c| {
                            matches!(c.value, TTLValue::Integer(_) | TTLValue::LongInteger(_))
                        });
                        if all_same_tag && all_numeric {
                            let any_long = items_mut
                                .iter()
                                .any(|c| matches!(c.value, TTLValue::LongInteger(_)));
                            let any_non_byte = items_mut.iter().any(|c| match c.value {
                                TTLValue::Integer(v) => !(0..=255).contains(&v),
                                _ => false,
                            });
                            if any_long || any_non_byte {
                                if let Some(val) = try_collapse_digits_run(ttlv.tag.as_str(), 1) {
                                    pending_replacement = Some(val);
                                }
                            }
                        }
                    }
                }

                // Sibling-level merge sign+magnitude
                if pending_replacement.is_none() {
                    const BIGINT_FIELD_TAGS: &[&str] = &[
                        "Modulus",
                        "PublicExponent",
                        "PrivateExponent",
                        "PrimeExponentP",
                        "PrimeExponentQ",
                        "CrtCoefficient",
                        "CRTCoefficient",
                        "P",
                        "Q",
                        "G",
                        "J",
                        "Y",
                        "X",
                        "D",
                        "BigIntNeg",
                        "BigIntPos",
                        "TheBigUint",
                    ];
                    let mut i = 0_usize;
                    while i < items_mut.len() {
                        let Some(current_tag) = items_mut.get(i).map(|e| e.tag.clone()) else {
                            break;
                        };
                        let tag_matches = BIGINT_FIELD_TAGS.contains(&current_tag.as_str());
                        if tag_matches {
                            let mut sign_opt: Option<i32> = None;
                            let mut mag_opt: Option<kmip_big_int::KmipBigInt> = None;
                            let mut last_same_tag_index = i;

                            match items_mut.get(i).map(|e| &e.value) {
                                Some(TTLValue::Integer(v)) => {
                                    sign_opt = Some(*v);
                                }
                                Some(TTLValue::BigInteger(kbi)) => {
                                    mag_opt = Some(kbi.clone());
                                }
                                Some(TTLValue::Structure(inner)) => {
                                    if !inner.is_empty()
                                        && inner.iter().all(|e| {
                                            e.tag == current_tag
                                                && matches!(
                                                    e.value,
                                                    TTLValue::Integer(_) | TTLValue::LongInteger(_)
                                                )
                                        })
                                    {
                                        let mut digits: Vec<u32> = Vec::with_capacity(inner.len());
                                        for e in inner {
                                            match e.value {
                                                TTLValue::Integer(v) => {
                                                    if let Ok(u) = u32::try_from(v) {
                                                        digits.push(u);
                                                    }
                                                }
                                                TTLValue::LongInteger(v) => {
                                                    if let Ok(u) = u32::try_from(v) {
                                                        digits.push(u);
                                                    }
                                                }
                                                _ => {}
                                            }
                                        }
                                        if let Ok(kbi) =
                                            kmip_big_int::KmipBigInt::from_u32_digits(1, &digits)
                                        {
                                            mag_opt = Some(kbi);
                                        }
                                    }
                                }
                                _ => {}
                            }

                            let mut j = i + 1;
                            while j < items_mut.len()
                                && items_mut.get(j).is_some_and(|e| e.tag == current_tag)
                            {
                                last_same_tag_index = j;
                                match items_mut.get(j).map(|e| &e.value) {
                                    Some(TTLValue::Integer(v)) => {
                                        if sign_opt.is_none() {
                                            sign_opt = Some(*v);
                                        }
                                    }
                                    Some(TTLValue::BigInteger(kbi)) => {
                                        if mag_opt.is_none() {
                                            mag_opt = Some(kbi.clone());
                                        }
                                    }
                                    Some(TTLValue::Structure(inner)) => {
                                        if mag_opt.is_none()
                                            && !inner.is_empty()
                                            && inner.iter().all(|e| {
                                                e.tag == current_tag
                                                    && matches!(
                                                        e.value,
                                                        TTLValue::Integer(_)
                                                            | TTLValue::LongInteger(_)
                                                    )
                                            })
                                        {
                                            let mut digits: Vec<u32> =
                                                Vec::with_capacity(inner.len());
                                            for e in inner {
                                                match e.value {
                                                    TTLValue::Integer(v) => {
                                                        if let Ok(u) = u32::try_from(v) {
                                                            digits.push(u);
                                                        }
                                                    }
                                                    TTLValue::LongInteger(v) => {
                                                        if let Ok(u) = u32::try_from(v) {
                                                            digits.push(u);
                                                        }
                                                    }
                                                    _ => {}
                                                }
                                            }
                                            if let Ok(kbi) =
                                                kmip_big_int::KmipBigInt::from_u32_digits(
                                                    1, &digits,
                                                )
                                            {
                                                mag_opt = Some(kbi);
                                            }
                                        }
                                    }
                                    _ => {}
                                }
                                j += 1;
                            }

                            if let Some(mut mag) = mag_opt {
                                if let Some(sign) = sign_opt {
                                    let big_mag = num_bigint_dig::BigInt::from(mag.clone()).abs();
                                    let new_big = match sign.cmp(&0) {
                                        std::cmp::Ordering::Less => -big_mag,
                                        std::cmp::Ordering::Equal => {
                                            num_bigint_dig::BigInt::from(0)
                                        }
                                        std::cmp::Ordering::Greater => big_mag,
                                    };
                                    mag = super::KmipBigInt::from(new_big);
                                }
                                let new_child = TTLV {
                                    tag: current_tag.clone(),
                                    value: TTLValue::BigInteger(mag),
                                };
                                for _ in i..=last_same_tag_index {
                                    items_mut.remove(i);
                                }
                                items_mut.insert(i, new_child);
                            }
                        }
                        i += 1;
                    }
                }

                // 8) Byte-like wrappers and concatenations
                if pending_replacement.is_none() && items_mut.len() == 1 {
                    let Some(child) = items_mut.first() else {
                        return;
                    };
                    if BYTE_LIKE_TAGS.contains(&ttlv.tag.as_str()) {
                        if let Some(bytes) = bytes_from(child) {
                            pending_replacement = Some(TTLValue::ByteString(bytes));
                        }
                    }
                    if pending_replacement.is_none()
                        && BYTE_LIKE_TAGS.contains(&ttlv.tag.as_str())
                        && child.tag == ttlv.tag
                    {
                        if let Some(bytes) = bytes_from(child) {
                            pending_replacement = Some(TTLValue::ByteString(bytes));
                        }
                    }
                    let is_type_wrapper = (ttlv.tag == child.tag || ttlv.tag == "AttributeValue")
                        && ttlv.tag != "[ARRAY]";
                    if pending_replacement.is_none() && is_type_wrapper {
                        if ttlv.tag == child.tag && ttlv.tag == "ByteString" {
                            if let TTLValue::Structure(ref inner) = child.value {
                                let mut as_bytes: Option<Vec<u8>> =
                                    Some(Vec::with_capacity(inner.len()));
                                for e in inner {
                                    match e.value {
                                        TTLValue::Integer(v) if (0..=255).contains(&v) => {
                                            if let Some(ref mut b) = as_bytes {
                                                if let Ok(x) = u8::try_from(v) {
                                                    b.push(x);
                                                } else {
                                                    as_bytes = None;
                                                    break;
                                                }
                                            }
                                        }
                                        _ => {
                                            as_bytes = None;
                                            break;
                                        }
                                    }
                                }
                                if let Some(bytes) = as_bytes {
                                    pending_replacement = Some(TTLValue::ByteString(bytes));
                                }
                            }
                        }
                        if pending_replacement.is_none() {
                            pending_replacement = Some(child.value.clone());
                        }
                    }
                }

                if pending_replacement.is_none()
                    && !items_mut.is_empty()
                    && BYTE_LIKE_TAGS.contains(&ttlv.tag.as_str())
                {
                    let mut out: Vec<u8> = Vec::new();
                    let mut all_byte_like = true;
                    for ch in items_mut.iter() {
                        if let Some(bytes) = bytes_from(ch) {
                            out.extend_from_slice(&bytes);
                        } else {
                            all_byte_like = false;
                            break;
                        }
                    }
                    if all_byte_like {
                        pending_replacement = Some(TTLValue::ByteString(out));
                    }
                }
            }

            if let Some(new_val) = pending_replacement {
                ttlv.value = new_val;
                normalize_ttlv(ttlv);
            }
        }
        TTLValue::Integer(_) => {
            if ttlv.tag == "Interval" {
                if let TTLValue::Integer(v) = ttlv.value {
                    if let Ok(u) = u32::try_from(v) {
                        ttlv.value = TTLValue::Interval(u);
                    }
                }
            }
            if ttlv.tag == "DateTime" {
                if let TTLValue::Integer(v) = ttlv.value {
                    ttlv.value = TTLValue::DateTimeExtended(i128::from(v));
                }
            }
        }
        TTLValue::LongInteger(_) => {
            if ttlv.tag == "DateTimeExtended" {
                if let TTLValue::LongInteger(v) = ttlv.value {
                    ttlv.value = TTLValue::DateTimeExtended(i128::from(v));
                }
            }
            if ttlv.tag == "DateTime" {
                if let TTLValue::LongInteger(v) = ttlv.value {
                    ttlv.value = TTLValue::DateTimeExtended(i128::from(v));
                }
            }
        }
        _ => {}
    }
}
