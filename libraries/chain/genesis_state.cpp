/**
 *  @file
 *  @copyright defined in evt/LICENSE.txt
 */
#include <evt/chain/genesis_state.hpp>
#include <evt/chain/contracts/types.hpp>
#include <fc/io/json.hpp>

namespace evt { namespace chain {

namespace __internal {

using namespace contracts;

group_def
get_evt_org() {

#ifndef MAINNET_BUILD
    const char* def = R"(
    {
        "name": ".everiToken",
        "key": "EVT00000000000000000000000000000000000000000000000000",
        "root": {
            "threshold": 1,
            "nodes": [
                { "weight": 1, "key": "EVT6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV" },
                { "weight": 1, "key": "EVT7edNeLHSdfmhMTUZd3o3pTBoyPRZ4fjrKU74FxJR9NgZgNZK6J" }
            ]
        }
    }
    )";
#else
    const char* def = R"(
    {
        "name": ".everiToken",
        "key": "EVT00000000000000000000000000000000000000000000000000",
        "root": {
            "threshold": 19,
            "nodes": [
                { "weight": 8, "key": "EVT6ZVMb3e69umQB4DQErvovx4fpy4ri2qMRmWnCjqCHRvzeWBYix" },
                { "weight": 7, "key": "EVT8C5q7W6tieUb1z5e9NV9ohWorWKfHykZp46nVaqabNm5xPSpVe" },
                { "weight": 5, "key": "EVT8PwjEmVji6xtNZdv8pNUuQyDavDyDcCQFDTZHDV4G6Vk9SMJUT" },
                { "weight": 4, "key": "EVT6J3hLMqwVMpeCcQh74LJhVs9f23HHjr4AZBUTd9GtTMc7dgGeP" },
                { "weight": 4, "key": "EVT8MSR6xwSoeDPAQDNZBTkDPvVjwEbuuiysMxdcMAz354WVaxCQu" }
            ]
        }
    }
    )";
#endif

    auto var = fc::json::from_string(def);
    return var.as<group_def>();
}

fungible_def
get_evt_sym(const genesis_state& genesis) {
    auto evt = fungible_def();
    evt.name = "EVT";
    evt.sym_name = "EVT";
    evt.sym = evt_sym();
    evt.creator = genesis.initial_key;
    evt.create_time = genesis.initial_timestamp;

    auto issue = permission_def();
    issue.name = N(issue);
    issue.threshold = 1;
    issue.authorizers.emplace_back(authorizer_weight(authorizer_ref(group_name(N128(.everiToken))), 1));

    auto transfer = permission_def();
    transfer.name = N(transfer);
    transfer.threshold = 1;
    transfer.authorizers.emplace_back(authorizer_weight(authorizer_ref(), 1));

    auto manage = permission_def();
    manage.name = N(manage);
    manage.threshold = 0;

    evt.issue    = issue;
    evt.transfer = transfer;
    evt.manage   = manage;

    evt.total_supply = asset(100'000'000'000'000L, evt.sym);
    return evt;
}

fungible_def
get_pevt_sym(const genesis_state& genesis) {
    auto pevt = fungible_def();
    pevt.name = "Pinned.EVT";
    pevt.sym_name = "PEVT";
    pevt.sym = pevt_sym();
    pevt.creator = genesis.initial_key;
    pevt.create_time = genesis.initial_timestamp;

    auto issue = permission_def();
    issue.name = N(issue);
    issue.threshold = 0;

    auto transfer = permission_def();
    transfer.name = N(transfer);
    transfer.threshold = 1;
    transfer.authorizers.emplace_back(authorizer_weight(authorizer_ref(), 1));

    auto manage = permission_def();
    manage.name = N(manage);
    manage.threshold = 0;

    pevt.issue    = issue;
    pevt.transfer = transfer;
    pevt.manage   = manage;

    pevt.total_supply = asset(0, pevt.sym);
    return pevt;
}

}  // namespace __internal

genesis_state::genesis_state() {
    using namespace __internal;

    initial_timestamp = fc::time_point::from_iso_string("2018-05-31T12:00:00");
    initial_key       = fc::variant(evt_root_key).as<public_key_type>();

    evt_org = get_evt_org();
    evt     = get_evt_sym(*this);
    pevt    = get_pevt_sym(*this);
}

chain::chain_id_type
genesis_state::compute_chain_id() const {
    digest_type::encoder enc;
    fc::raw::pack(enc, *this);
    return chain_id_type(enc.result());
}

}}  // namespace evt::chain