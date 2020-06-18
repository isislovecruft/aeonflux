// -*- mode: rust; -*-
//
// This file is part of aeonflux.
// Copyright (c) 2020 The Brave Authors
// Copyright (c) 2018 Signal Foundation
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

macro_rules! impl_serde_with_to_bytes_and_from_bytes {
    ($t:tt, $expecting:expr) => {
        impl Serialize for $t {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
                where S: Serializer
            {
                serializer.serialize_bytes(&self.to_bytes()[..])
            }
        }

        impl<'de> Deserialize<'de> for $t {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                where D: Deserializer<'de>
            {
                struct AeonfluxVisitor;

                impl<'de> Visitor<'de> for AeonfluxVisitor {
                    type Value = $t;

                    fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                        formatter.write_str($expecting)
                    }

                    fn visit_bytes<E>(self, v: &[u8]) -> Result<$t, E>
                        where E: serde::de::Error
                    {
                        match $t::from_bytes(v) {
                            Ok(x)   => Ok(x),
                            Err(_x) => {
                                #[cfg(feature = "std")]
                                println!("Error while deserialising {}: {:?}", stringify!($t), _x);
                                Err(serde::de::Error::invalid_length(v.len(), &self))
                            },
                        }
                    }
                }
                deserializer.deserialize_bytes(AeonfluxVisitor)
            }
        }
    }
}
