// SPDX-FileCopyrightText: 2026 Andrei Kochergin <andrei@oumuamua.dev>
// SPDX-FileCopyrightText: 2026 Oumuamua Labs <info@oumuamua.dev>
// SPDX-License-Identifier: AGPL-3.0-only

use flatbuffers::FlatBufferBuilder;
use hekate_core::config::Config;
use hekate_core::errors::Result;

use crate::generated::program as fb;

pub fn serialize_config<'a>(
    fbb: &mut FlatBufferBuilder<'a>,
    config: &Config,
) -> flatbuffers::WIPOffset<fb::Config<'a>> {
    fb::Config::create(
        fbb,
        &fb::ConfigArgs {
            inv_rate: config.inv_rate as u32,
            num_queries: config.num_queries as u32,
            sumcheck_blinding_factor: config.sumcheck_blinding_factor as u32,
            ldt_support_size: config.ldt_support_size as u32,
            min_security_bits: config.min_security_bits as u32,
        },
    )
}

pub fn deserialize_config(fb_config: fb::Config<'_>) -> Result<Config> {
    Ok(Config {
        inv_rate: fb_config.inv_rate() as usize,
        num_queries: fb_config.num_queries() as usize,
        sumcheck_blinding_factor: fb_config.sumcheck_blinding_factor() as usize,
        ldt_support_size: fb_config.ldt_support_size() as usize,
        min_security_bits: fb_config.min_security_bits() as usize,
    })
}
