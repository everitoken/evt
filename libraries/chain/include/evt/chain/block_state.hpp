/**
 *  @file
 *  @copyright defined in evt/LICENSE.txt
 */
#pragma once
#include <evt/chain/block.hpp>
#include <evt/chain/block_header_state.hpp>
#include <evt/chain/transaction_metadata.hpp>

namespace evt { namespace chain {

struct block_state : public block_header_state {
    block_state(const block_header_state& prev,
                signed_block_ptr          b,
                bool                      skip_validate_signee);

    block_state(pending_block_header_state&&                             cur,
                signed_block_ptr&&                                       b,  // unsigned block
                vector<transaction_metadata_ptr>&&                       trx_metas,
                const std::function<signature_type(const digest_type&)>& signer);

    block_state(pending_block_header_state&&       cur,
                const signed_block_ptr&            b,  // signed block
                vector<transaction_metadata_ptr>&& trx_metas,
                bool                               skip_validate_signee);

    block_state() = default;

    bool is_valid() const { return validated; }

    /// weak_ptr prev_block_state....
    signed_block_ptr block;
    bool             validated = false;

    /// this data is redundant with the data stored in block, but facilitates
    /// recapturing transactions when we pop a block
    vector<transaction_metadata_ptr> trxs;
};

using block_state_ptr = std::shared_ptr<block_state>;

}}  // namespace evt::chain

FC_REFLECT_DERIVED(evt::chain::block_state, (evt::chain::block_header_state), (block)(validated));
