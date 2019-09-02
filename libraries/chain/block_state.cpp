#include <evt/chain/block_state.hpp>
#include <evt/chain/exceptions.hpp>

namespace evt { namespace chain {

block_state::block_state(const block_header_state& prev,
                         signed_block_ptr b,
                         bool skip_validate_signee)
    : block_header_state(prev.next(*b, skip_validate_signee))
    , block(std::move(b)) {}

block_state::block_state(pending_block_header_state&& cur,
                         signed_block_ptr&& b,
                         vector<transaction_metadata_ptr>&& trx_metas,
                         const std::function<signature_type(const digest_type&)>& signer)
    : block_header_state(std::move(cur).finish_next(*b, signer))
    , block(std::move(b))
    , trxs(std::move(trx_metas)) {}

block_state::block_state(pending_block_header_state&& cur,
                         const signed_block_ptr& b,
                         vector<transaction_metadata_ptr>&& trx_metas,
                         bool skip_validate_signee)
    : block_header_state(std::move(cur).finish_next(*b, skip_validate_signee))
    , block(b)
    , trxs(std::move(trx_metas)) {}

}}  // namespace evt::chain
