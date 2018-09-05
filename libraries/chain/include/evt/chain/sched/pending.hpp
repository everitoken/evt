/**
 *  @file
 *  @copyright defined in evt/LICENSE.txt
 */
#pragma once

#include <vector>
#include <chainbase/chainbase.hpp>
#include <fc/scoped_exit.hpp>
#include <evt/chain/controller.hpp>
#include <evt/chain/block.hpp>
#include <evt/chain/block_state.hpp>
#include <evt/chain/token_database.hpp>

namespace evt { namespace chain { namespace sched {

using chainbase::database;

class maybe_session {
public:
    maybe_session() = default;

    maybe_session(maybe_session&& other)
        : _session(move(other._session))
        , _token_session(move(other._token_session)) {}

    explicit maybe_session(database& db, token_database& token_db) {
        _session = db.start_undo_session(true);
        _token_session = token_db.new_savepoint_session(db.revision());
    }

    maybe_session(const maybe_session&) = delete;

public:
    void
    squash() {
        if(_session) {
            _session->squash();
        }
        if(_token_session) {
            _token_session->squash();
        }
    }

    void
    undo() {
        if(_session) {
            _session->undo();
        }
        if(_token_session) {
            _token_session->undo();
        }
    }

    void
    push() {
        if(_session) {
            _session->push();
        }
        if(_token_session) {
            _token_session->accept();
        }
    }

    maybe_session&
    operator=(maybe_session&& mv) {
        if(mv._session) {
            _session = move(*mv._session);
            mv._session.reset();
        }
        else {
            _session.reset();
        }

        if(mv._token_session) {
            _token_session = move(*mv._token_session);
            mv._token_session.reset();
        }
        else {
            _token_session.reset();
        }

        return *this;
    };

private:
    optional<database::session>       _session;
    optional<token_database::session> _token_session;
};

struct pending_state {
public:
    pending_state(maybe_session&& s)
        : _db_session(move(s)) {}

    pending_state(pending_state&& ps)
        : _db_session(move(ps._db_session)) {}

public:
    void
    push() {
        _db_session.push();
    }

public:
    maybe_session               _db_session;
    block_state_ptr             _pending_block_state;
    std::vector<action_receipt> _actions;

    controller::block_status _block_status = controller::block_status::incomplete;    
};

// The returned scoped_exit should not exceed the lifetime of the pending which existed when make_block_restore_point was called.
fc::scoped_exit<std::function<void()>>
make_block_restore_point() {
    auto orig_block_transactions_size = pending->_pending_block_state->block->transactions.size();
    auto orig_state_transactions_size = pending->_pending_block_state->trxs.size();
    auto orig_state_actions_size      = pending->_actions.size();

    std::function<void()> callback = [this,
                                      orig_block_transactions_size,
                                      orig_state_transactions_size,
                                      orig_state_actions_size]() {
        pending->_pending_block_state->block->transactions.resize(orig_block_transactions_size);
        pending->_pending_block_state->trxs.resize(orig_state_transactions_size);
        pending->_actions.resize(orig_state_actions_size);
    };

    return fc::make_scoped_exit(std::move(callback));
}

/**
*  Adds the transaction receipt to the pending block and returns it.
*/
template <typename T>
const transaction_receipt&
push_receipt(pending_state& pending, const T& trx, transaction_receipt_header::status_enum status, transaction_receipt_header::type_enum type) {
    pending->_pending_block_state->block->transactions.emplace_back(trx);
    
    auto& r  = pending->_pending_block_state->block->transactions.back();
    r.status = status;
    r.type   = type;
    
    return r;
}

// namespace evt::chain::sched
