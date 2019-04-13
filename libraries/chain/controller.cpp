/**
 *  @file
 *  @copyright defined in evt/LICENSE.txt
 */
#include <evt/chain/controller.hpp>

#include <chainbase/chainbase.hpp>
#include <fmt/format.h>

#include <fc/io/json.hpp>
#include <fc/scoped_exit.hpp>
#include <fc/variant_object.hpp>

#include <evt/chain/authority_checker.hpp>
#include <evt/chain/block_log.hpp>
#include <evt/chain/charge_manager.hpp>
#include <evt/chain/chain_snapshot.hpp>
#include <evt/chain/execution_context_impl.hpp>
#include <evt/chain/fork_database.hpp>
#include <evt/chain/snapshot.hpp>
#include <evt/chain/token_database.hpp>
#include <evt/chain/token_database_cache.hpp>
#include <evt/chain/token_database_snapshot.hpp>
#include <evt/chain/transaction_context.hpp>
#include <evt/chain/contracts/abi_serializer.hpp>
#include <evt/chain/contracts/evt_contract_abi.hpp>
#include <evt/chain/contracts/evt_org.hpp>

#include <evt/chain/block_summary_object.hpp>
#include <evt/chain/global_property_object.hpp>
#include <evt/chain/transaction_object.hpp>
#include <evt/chain/reversible_block_object.hpp>
#include <evt/chain/contracts/evt_link_object.hpp>

namespace evt { namespace chain {

using controller_index_set = index_set<
   global_property_multi_index,
   dynamic_global_property_multi_index,
   block_summary_multi_index,
   transaction_multi_index
>;

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
    operator =(maybe_session&& mv) {
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
    pending_state(maybe_session&& s)
        : _db_session(move(s)) {}

    pending_state(pending_state&& ps)
        : _db_session(move(ps._db_session)) {}

    maybe_session                   _db_session;
    block_state_ptr                 _pending_block_state;
    small_vector<action_receipt, 4> _actions;
    controller::block_status        _block_status = controller::block_status::incomplete;
    optional<block_id_type>         _producer_block_id;

    void
    push() {
        _db_session.push();
    }
};

struct controller_impl {
    controller&              self;
    chainbase::database      db;
    chainbase::database      reversible_blocks; ///< a special database to persist blocks that have successfully been applied but are still reversible
    block_log                blog;
    optional<pending_state>  pending;
    block_state_ptr          head;
    fork_database            fork_db;
    token_database           token_db;
    token_database_cache     token_db_cache;
    controller::config       conf;
    chain_id_type            chain_id;
    evt_execution_context    exec_ctx;


    bool                     replaying = false;
    optional<fc::time_point> replay_head_time;
    db_read_mode             read_mode = db_read_mode::SPECULATIVE;
    bool                     in_trx_requiring_checks = false; ///< if true, checks that are normally skipped on replay (e.g. auth checks) cannot be skipped
    bool                     trusted_producer_light_validation = false;
    uint32_t                 snapshot_head_block = 0;
    abi_serializer           system_api;

    /**
     *  Transactions that were undone by pop_block or abort_block, transactions
     *  are removed from this list if they are re-applied in other blocks. Producers
     *  can query this list when scheduling new transactions into blocks.
     */
    unapplied_transactions_type unapplied_transactions;

    void
    pop_block() {
        auto prev = fork_db.get_block(head->header.previous);
        EVT_ASSERT(prev, block_validate_exception, "attempt to pop beyond last irreversible block");

        if(const auto* b = reversible_blocks.find<reversible_block_object,by_num>(head->block_num)) {
            reversible_blocks.remove(*b);
        }

        if(read_mode == db_read_mode::SPECULATIVE) {
            EVT_ASSERT(head->block, block_validate_exception, "attempting to pop a block that was sparsely loaded from a snapshot");
            for(const auto& t : head->trxs) {
                unapplied_transactions[t->signed_id] = t;
            }
        }
        head = prev;
        db.undo();
        token_db.rollback_to_latest_savepoint();
    }

    controller_impl(const controller::config& cfg, controller& s)
        : self(s)
        , db(cfg.state_dir,
             cfg.read_only ? database::read_only : database::read_write,
             cfg.state_size)
        , reversible_blocks(cfg.blocks_dir / config::reversible_blocks_dir_name,
             cfg.read_only ? database::read_only : database::read_write,
             cfg.reversible_cache_size)
        , blog(cfg.blocks_dir)
        , fork_db(cfg.state_dir)
        , token_db(cfg.db_config)
        , token_db_cache(token_db, cfg.db_config.object_cache_size)
        , conf(cfg)
        , chain_id(cfg.genesis.compute_chain_id())
        , exec_ctx()
        , read_mode(cfg.read_mode)
        , system_api(contracts::evt_contract_abi(), cfg.max_serialization_time) {

        fork_db.irreversible.connect([&](auto b) {
            on_irreversible(b);
        });
    }

    ~controller_impl() {
        pending.reset();
        db.flush();
        reversible_blocks.flush();
    }

    /**
     *  Plugins / observers listening to signals emited (such as accepted_transaction) might trigger
     *  errors and throw exceptions. Unless those exceptions are caught it could impact consensus and/or
     *  cause a node to fork.
     *
     *  If it is ever desirable to let a signal handler bubble an exception out of this method
     *  a full audit of its uses needs to be undertaken.
     *
     */
    template <typename Signal, typename Arg>
    void
    emit(const Signal& s, Arg&& a) {
        try {
            s(std::forward<Arg>(a));
        }
        catch(boost::interprocess::bad_alloc& e) {
            wlog("bad alloc");
            throw e;
        }
        catch(controller_emit_signal_exception& e) {
            wlog("${details}", ("details", e.to_detail_string()));
            throw e;
        }
        catch(fc::exception& e) {
            wlog("${details}", ("details", e.to_detail_string()));
        }
        catch(...) {
            wlog("signal handler threw exception");
        }
    }

    void
    on_irreversible(const block_state_ptr& s) {
        if(!blog.head()) {
            blog.read_head();
        }

        const auto& log_head       = blog.head();
        auto        append_to_blog = false;
        if(!log_head) {
            if(s->block) {
                EVT_ASSERT(s->block_num == blog.first_block_num(), block_log_exception, "block log has no blocks and is appending the wrong first block.  Expected ${expected}, but received: ${actual}",
                           ("expected", fmt::format("{:n}", blog.first_block_num()))("actual", fmt::format("{:n}", s->block_num)));
                append_to_blog = true;
            }
            else {
                EVT_ASSERT(s->block_num == blog.first_block_num() - 1, block_log_exception, "block log has no blocks and is not properly set up to start after the snapshot");
            }
        }
        else {
            auto lh_block_num = log_head->block_num();
            if(s->block_num > lh_block_num) {
                EVT_ASSERT(s->block_num - 1 == lh_block_num, unlinkable_block_exception, "unlinkable block", ("s->block_num",fmt::format("{:n}", s->block_num))("lh_block_num",fmt::format("{:n}", lh_block_num)));
                EVT_ASSERT(s->block->previous == log_head->id(), unlinkable_block_exception, "irreversible doesn't link to block log head");
                append_to_blog = true;
            }
        }

        db.commit(s->block_num);
        token_db.pop_savepoints(s->block_num);

        if(append_to_blog) {
            blog.append(s->block);
        }

        const auto& ubi    = reversible_blocks.get_index<reversible_block_index, by_num>();
        auto        objitr = ubi.begin();
        while(objitr != ubi.end() && objitr->blocknum <= s->block_num) {
            reversible_blocks.remove(*objitr);
            objitr = ubi.begin();
        }

        // the "head" block when a snapshot is loaded is virtual and has no block data, all of its effects
        // should already have been loaded from the snapshot so, it cannot be applied
        if(s->block) {
            if(read_mode == db_read_mode::IRREVERSIBLE) {
                // when applying a snapshot, head may not be present
                // when not applying a snapshot, make sure this is the next block
                if(!head || s->block_num == head->block_num + 1) {
                    apply_block(s->block, controller::block_status::complete);
                    head = s;
                }
                else {
                    // otherwise, assert the one odd case where initializing a chain
                    // from genesis creates and applies the first block automatically.
                    // when syncing from another chain, this is pushed in again
                    EVT_ASSERT(!head || head->block_num == 1, block_validate_exception, "Attempting to re-apply an irreversible block that was not the implied genesis block");
                }

                fork_db.mark_in_current_chain(head, true);
                fork_db.set_validity(head, true);
            }
            emit(self.irreversible_block, s);
        }
    }

    void
    replay() {
        auto blog_head       = blog.read_head();
        auto blog_head_time  = blog_head->timestamp.to_time_point();
        replaying            = true;
        replay_head_time     = blog_head_time;
        auto start_block_num = head->block_num + 1;
        ilog("existing block log, attempting to replay from ${s} to ${n} blocks",
            ("s", fmt::format("{:n}", start_block_num))("n", fmt::format("{:n}", blog_head->block_num())));

        auto start = fc::time_point::now();
        while(auto next = blog.read_block_by_num(head->block_num + 1)) {
            replay_push_block(next, controller::block_status::irreversible);
            if(next->block_num() % 500 == 0) {
                ilog2_("{:n} of {:n}", next->block_num(), blog_head->block_num());
            }
        }
        std::cerr << "\n";
        ilog("${n} blocks replayed", ("n", fmt::format("{:n}", head->block_num - start_block_num)));

        // if the irreversible log is played without undo sessions enabled, we need to sync the
        // revision ordinal to the appropriate expected value here.
        if(self.skip_db_sessions(controller::block_status::irreversible))
            db.set_revision(head->block_num);

        int rev = 0;
        while(auto obj = reversible_blocks.find<reversible_block_object, by_num>(head->block_num + 1)) {
            ++rev;
            replay_push_block(obj->get_block(), controller::block_status::validated);
        }

        ilog("${n} reversible blocks replayed", ("n", fmt::format("{:n}", rev)));
        auto end = fc::time_point::now();
        ilog("replayed ${n} blocks in ${duration} seconds, ${mspb} ms/block",
            ("n", fmt::format("{:n}", head->block_num - start_block_num))
            ("duration", fmt::format("{:n}", (end - start).count() / 1000000))
            ("mspb", fmt::format("{:.3f}", ((end - start).count() / 1000.0) / (head->block_num - start_block_num)))
            );
        replaying = false;
        replay_head_time.reset();
    }


    void
    init(const snapshot_reader_ptr& snapshot) {
        token_db.open();

        bool report_integrity_hash = !!snapshot;
        if(snapshot) {
            EVT_ASSERT(!head, fork_database_exception, "");
            snapshot->validate();

            read_from_snapshot(snapshot);

            auto end = blog.read_head();
            if(!end) {
                blog.reset(conf.genesis, signed_block_ptr(), head->block_num + 1);
            }
            else if(end->block_num() > head->block_num) {
                replay();
            }
            else {
                EVT_ASSERT(end->block_num() == head->block_num, fork_database_exception,
                           "Block log is provided with snapshot but does not contain the head block from the snapshot");
            }
        }
        else {
            if(!head) {
                initialize_fork_db();  // set head to genesis state
                initialize_token_db();
            }

            auto end = blog.read_head();
            if(!end) {
                blog.reset(conf.genesis, head->block);
            }
            else if(end->block_num() > head->block_num) {
                replay();
                report_integrity_hash = true;
            }
        }

        const auto& ubi    = reversible_blocks.get_index<reversible_block_index, by_num>();
        auto        objitr = ubi.rbegin();
        if(objitr != ubi.rend()) {
            EVT_ASSERT(objitr->blocknum == head->block_num, fork_database_exception,
                       "reversible block database is inconsistent with fork database, replay blockchain",
                       ("head", head->block_num)("unconfimed", objitr->blocknum));
        }
        else {
            auto end = blog.read_head();
            EVT_ASSERT(!end || end->block_num() == head->block_num, fork_database_exception,
                       "fork database exists but reversible block database does not, replay blockchain",
                       ("blog_head", end->block_num())("head", head->block_num));
        }

        EVT_ASSERT(db.revision() >= head->block_num, fork_database_exception, "fork database is inconsistent with shared memory",
                   ("db", db.revision())("head", head->block_num));

        if(db.revision() > head->block_num) {
            wlog("warning: database revision (${db}) is greater than head block number (${head}), "
                 "attempting to undo pending changes",
                 ("db", db.revision())("head", head->block_num));
            EVT_ASSERT(token_db.savepoints_size() > 0, token_database_exception,
                "token database is inconsistent with fork database: don't have any savepoints to pop");
            EVT_ASSERT(token_db.latest_savepoint_seq() == db.revision(), token_database_exception,
                "token database(${seq}) is inconsistent with fork database(${db})",
                ("seq",token_db.latest_savepoint_seq())("db",db.revision()));
        }
        while(db.revision() > head->block_num) {
            db.undo();
            token_db.rollback_to_latest_savepoint();
        }

        if(report_integrity_hash) {
            const auto hash = calculate_integrity_hash();
            ilog("database initialized with hash: ${hash}", ("hash", hash));
        }
    }

    void
    add_indices() {
        reversible_blocks.add_index<reversible_block_index>(); 

        controller_index_set::add_indices(db);
    }

    void
    add_to_snapshot(const snapshot_writer_ptr& snapshot) const {
        snapshot->write_section<chain_snapshot_header>([this](auto& section) {
            section.add_row(chain_snapshot_header(), db);
        });

        snapshot->write_section<genesis_state>([this](auto& section) {
            section.add_row(conf.genesis, db);
        });

        snapshot->write_section<block_state>([this](auto& section) {
            section.template add_row<block_header_state>(*fork_db.head(), db);
        });

        controller_index_set::walk_indices([this, &snapshot](auto utils) {
            using value_t = typename decltype(utils)::index_t::value_type;

            snapshot->write_section<value_t>([this](auto& section) {
                decltype(utils)::walk(db, [this, &section](const auto& row) {
                    section.add_row(row, db);
                });
            });
        });

        token_database_snapshot::add_to_snapshot(snapshot, token_db);
    }

    void
    read_from_snapshot(const snapshot_reader_ptr& snapshot) {
        snapshot->read_section<chain_snapshot_header>([this](auto& section) {
            chain_snapshot_header header;
            section.read_row(header, db);
            header.validate();
        });

        snapshot->read_section<block_state>([this](auto& section) {
            block_header_state head_header_state;
            section.read_row(head_header_state, db);

            auto head_state = std::make_shared<block_state>(head_header_state);
            fork_db.set(head_state);
            fork_db.set_validity(head_state, true);
            fork_db.mark_in_current_chain(head_state, true);

            head                = head_state;
            snapshot_head_block = head->block_num;
        });

        controller_index_set::walk_indices([this, &snapshot](auto utils) {
            using value_t = typename decltype(utils)::index_t::value_type;

            snapshot->read_section<value_t>([this](auto& section) {
                bool more = !section.empty();
                while(more) {
                    decltype(utils)::create(db, [this, &section, &more](auto& row) {
                        more = section.read_row(row, db);
                    });
                }
            });
        });

        token_database_snapshot::read_from_snapshot(snapshot, token_db);
        db.set_revision(head->block_num);
    }

    sha256
    calculate_integrity_hash() const {
        auto enc = sha256::encoder();
        auto hash_writer = std::make_shared<integrity_hash_snapshot_writer>(enc);
        add_to_snapshot(hash_writer);
        hash_writer->finalize();

        return enc.result();
    }

    /**
    *  Sets fork database head to the genesis state.
    */
    void
    initialize_fork_db() {
        wlog(" Initializing new blockchain with genesis state");
        producer_schedule_type initial_schedule{0, {{config::system_account_name, conf.genesis.initial_key}}};

        block_header_state genheader;
        genheader.active_schedule       = initial_schedule;
        genheader.pending_schedule      = initial_schedule;
        genheader.pending_schedule_hash = fc::sha256::hash(initial_schedule);
        genheader.header.timestamp      = conf.genesis.initial_timestamp;
        genheader.header.action_mroot   = conf.genesis.compute_chain_id();
        genheader.id                    = genheader.header.id();
        genheader.block_num             = genheader.header.block_num();
        genheader.block_signing_key     = conf.genesis.initial_key;
        
        head        = std::make_shared<block_state>(genheader);
        head->block = std::make_shared<signed_block>(genheader.header);

        fork_db.set(head);
        db.set_revision(head->block_num);

        initialize_database();
    }

    void
    initialize_database() {
        // Initialize block summary index
        for(int i = 0; i < 0x10000; i++) {
            db.create<block_summary_object>([&](block_summary_object&) {});
        }

        const auto& tapos_block_summary = db.get<block_summary_object>(1);
        db.modify(tapos_block_summary, [&](auto& bs) {
            bs.block_id = head->id;
        });

        conf.genesis.initial_configuration.validate();
        db.create<global_property_object>([&](auto& gpo) {
            gpo.configuration = conf.genesis.initial_configuration;
        });
        db.create<dynamic_global_property_object>([](auto&) {});
    }

    void
    initialize_token_db() {
        initialize_evt_org(token_db, conf.genesis);
    }

    /**
     * @post regardless of the success of commit block there is no active pending block
     */
    void
    commit_block(bool add_to_fork_db) {
        auto reset_pending_on_exit = fc::make_scoped_exit([this] {
            pending.reset();
        });

        try {
            if(add_to_fork_db) {
                pending->_pending_block_state->validated = true;
                auto new_bsp = fork_db.add(pending->_pending_block_state, true);
                emit(self.accepted_block_header, pending->_pending_block_state);
                head = fork_db.head();
                EVT_ASSERT(new_bsp == head, fork_database_exception, "committed block did not become the new head in fork database");
            }

            if(!replaying) {
                reversible_blocks.create<reversible_block_object>([&](auto& ubo) {
                    ubo.blocknum = pending->_pending_block_state->block_num;
                    ubo.set_block(pending->_pending_block_state->block);
                });
            }

            emit(self.accepted_block, pending->_pending_block_state);
        }
        catch (...) {
            // dont bother resetting pending, instead abort the block
            reset_pending_on_exit.cancel();
            abort_block();
            throw;
        }

        // push the state for pending.
        pending->push();
    }

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
    push_receipt(const T& trx, transaction_receipt_header::status_enum status, transaction_receipt_header::type_enum type) {
        pending->_pending_block_state->block->transactions.emplace_back(trx);
        transaction_receipt& r = pending->_pending_block_state->block->transactions.back();
        r.status               = status;
        r.type                 = type;
        return r;
    }

    bool
    failure_is_subjective(const fc::exception& e) {
        auto code = e.code();
        return (code == deadline_exception::code_value);
    }

    void
    check_authorization(const public_keys_set& signed_keys, const transaction& trx) {
        auto& conf = db.get<global_property_object>().configuration;

        auto checker = authority_checker(self, exec_ctx, signed_keys, conf.max_authority_depth);
        for(const auto& act : trx.actions) {
            EVT_ASSERT(checker.satisfied(act), unsatisfied_authorization,
                       "${name} action in domain: ${domain} with key: ${key} authorized failed",
                       ("domain", act.domain)("key", act.key)("name", act.name));
        }
    }

    void
    check_authorization(const public_keys_set& signed_keys, const action& act) {
        auto& conf = db.get<global_property_object>().configuration;

        auto checker = authority_checker(self, exec_ctx, signed_keys, conf.max_authority_depth);
        EVT_ASSERT(checker.satisfied(act), unsatisfied_authorization,
                   "${name} action in domain: ${domain} with key: ${key} authorized failed",
                   ("domain", act.domain)("key", act.key)("name", act.name));
    }

    transaction_trace_ptr
    push_suspend_transaction(const transaction_metadata_ptr& trx, fc::time_point deadline) {
        try {
            auto reset_in_trx_requiring_checks = fc::make_scoped_exit([old_value=in_trx_requiring_checks, this] {
                in_trx_requiring_checks = old_value;
            });
            in_trx_requiring_checks = true;

            auto trx_context     = transaction_context(self, exec_ctx, trx);
            trx_context.deadline = deadline;

            auto trace = trx_context.trace;
            try {
                trx_context.init_for_suspend_trx();
                trx_context.exec();
                trx_context.finalize();

                auto restore = make_block_restore_point();

                trace->receipt = push_receipt(*trx->packed_trx,
                                              transaction_receipt::executed,
                                              transaction_receipt::suspend);

                fc::move_append(pending->_actions, move(trx_context.executed));

                emit(self.accepted_transaction, trx);
                emit(self.applied_transaction, trace);

                trx_context.squash();
                restore.cancel();
                return trace;
            }
            catch(const fc::exception& e) {
                trace->except     = e;
                trace->except_ptr = std::current_exception();
                trace->elapsed    = fc::time_point::now() - trx_context.start;
            }
            trx_context.undo();

            trace->elapsed = fc::time_point::now() - trx_context.start;

            if(failure_is_subjective(*trace->except)) {
                trace->receipt = push_receipt(*trx->packed_trx,
                                              transaction_receipt::soft_fail,
                                              transaction_receipt::suspend);
            }
            else {
                trace->receipt = push_receipt(*trx->packed_trx,
                                              transaction_receipt::hard_fail,
                                              transaction_receipt::suspend);
            }
            emit(self.accepted_transaction, trx);
            emit(self.applied_transaction, trace);
            return trace;
        }
        FC_CAPTURE_AND_RETHROW()
    } /// push_scheduled_transaction

    /**
     *  This is the entry point for new transactions to the block state. It will check authorization
     *  and insert a transaction receipt into the pending block.
     */
    transaction_trace_ptr
    push_transaction(const transaction_metadata_ptr& trx,
                     fc::time_point                  deadline) {
        EVT_ASSERT(deadline != fc::time_point(), transaction_exception, "deadline cannot be uninitialized");

        transaction_trace_ptr trace;
        try {
            auto& trn         = trx->packed_trx->get_signed_transaction();
            auto  trx_context = transaction_context(self, exec_ctx, trx);

            trx_context.deadline = deadline;
            trace                = trx_context.trace;

            try {
                if(trx->implicit) {
                    trx_context.init_for_implicit_trx();
                }
                else {
                    bool skip_recording = replay_head_time && (time_point(trn.expiration) <= *replay_head_time);
                    trx_context.init_for_input_trx(skip_recording);
                }

                if(!self.skip_auth_check() && !trx->implicit) {
                    const auto& keys = trx->recover_keys(chain_id);
                    check_authorization(keys, trn);
                }

                trx_context.exec();
                trx_context.finalize();  // Automatically rounds up network and CPU usage in trace and bills payers if successful

                auto restore = make_block_restore_point();

                if(!trx->implicit) {
                    trace->receipt = push_receipt(*trx->packed_trx,
                                                  transaction_receipt::executed,
                                                  transaction_receipt::input);
                    pending->_pending_block_state->trxs.emplace_back(trx);
                }
                else {
                    transaction_receipt_header r;
                    r.status       = transaction_receipt::executed;
                    trace->receipt = r;
                }

                fc::move_append(pending->_actions, move(trx_context.executed));

                // call the accept signal but only once for this transaction
                if(!trx->accepted) {
                    trx->accepted = true;
                    emit(self.accepted_transaction, trx);
                }

                emit(self.applied_transaction, trace);

                if(read_mode != db_read_mode::SPECULATIVE && pending->_block_status == controller::block_status::incomplete) {
                    //this may happen automatically in destructor, but I prefere make it more explicit
                    trx_context.undo();
                }
                else {
                    restore.cancel();
                    trx_context.squash();
                }

                if(!trx->implicit) {
                    unapplied_transactions.erase(trx->signed_id);
                }
                return trace;
            }
            catch(const fc::exception& e) {
                trace->except     = e;
                trace->except_ptr = std::current_exception();
            }
            if(!failure_is_subjective(*trace->except)) {
                unapplied_transactions.erase(trx->signed_id);
            }

            emit(self.accepted_transaction, trx);
            emit(self.applied_transaction, trace);

            return trace;
        }
        FC_CAPTURE_AND_RETHROW((trace))
    }  /// push_transaction

    void
    start_block(block_timestamp_type when, uint16_t confirm_block_count, controller::block_status s, const optional<block_id_type>& producer_block_id) {
        EVT_ASSERT(!pending.has_value(), block_validate_exception, "pending block already exists");

        auto guard_pending = fc::make_scoped_exit([this]() {
            pending.reset();
        });

        if(!self.skip_db_sessions(s)) {
            EVT_ASSERT(db.revision() == head->block_num, database_exception, "db revision is not on par with head block",
                ("db.revision()", db.revision())("controller_head_block", head->block_num)("fork_db_head_block", fork_db.head()->block_num) );

            pending.emplace(maybe_session(db, token_db));
        }
        else {
            pending.emplace(maybe_session());
        }

        pending->_block_status                          = s;
        pending->_producer_block_id                     = producer_block_id;
        pending->_pending_block_state                   = std::make_shared<block_state>(*head, when);  // promotes pending schedule (if any) to active
        pending->_pending_block_state->in_current_chain = true;

        pending->_pending_block_state->set_confirmed(confirm_block_count);

        auto was_pending_promoted = pending->_pending_block_state->maybe_promote_pending();

        //modify state in speculative block only if we are speculative reads mode (other wise we need clean state for head or irreversible reads)
        if(read_mode == db_read_mode::SPECULATIVE || pending->_block_status != controller::block_status::incomplete) {
            const auto& gpo = db.get<global_property_object>();
            if(gpo.proposed_schedule_block_num.has_value() &&                                                      // if there is a proposed schedule that was proposed in a block ...
               (*gpo.proposed_schedule_block_num <= pending->_pending_block_state->dpos_irreversible_blocknum) &&  // ... that has now become irreversible ...
               pending->_pending_block_state->pending_schedule.producers.size() == 0 &&                            // ... and there is room for a new pending schedule ...
               !was_pending_promoted                                                                               // ... and not just because it was promoted to active at the start of this block, then:
            ) {
                // Promote proposed schedule to pending schedule.
                if(!replaying) {
                    ilog("promoting proposed schedule (set in block ${proposed_num}) to pending; current block: ${n} lib: ${lib} schedule: ${schedule} ",
                         ("proposed_num", *gpo.proposed_schedule_block_num)
                         ("n", pending->_pending_block_state->block_num)
                         ("lib", pending->_pending_block_state->dpos_irreversible_blocknum)
                         ("schedule", static_cast<producer_schedule_type>(gpo.proposed_schedule)));
                }
                pending->_pending_block_state->set_new_producers(gpo.proposed_schedule);
                db.modify(gpo, [&](auto& gp) {
                    gp.proposed_schedule_block_num = optional<block_num_type>();
                    gp.proposed_schedule.clear();
                });
            }

            clear_expired_input_transactions();
        }
        guard_pending.cancel();
    }  // start_block

    void
    sign_block(const std::function<signature_type(const digest_type&)>& signer_callback) {
        auto p = pending->_pending_block_state;
        p->sign(signer_callback);

        static_cast<signed_block_header&>(*p->block) = p->header;
    }  /// sign_block

    void
    apply_block(const signed_block_ptr& b, controller::block_status s) {
        try {
            try {
                EVT_ASSERT(b->block_extensions.size() == 0, block_validate_exception, "no supported extensions");
                auto producer_block_id = b->id();
                start_block(b->timestamp, b->confirmed, s, producer_block_id);

                auto num_pending_receipts = pending->_pending_block_state->block->transactions.size();
                for(const auto& receipt : b->transactions) {
                    auto trace = transaction_trace_ptr();
                    if(receipt.type == transaction_receipt::input) {
                        auto& pt    = receipt.trx;
                        auto  mtrx  = std::make_shared<transaction_metadata>(std::make_shared<packed_transaction>(pt));
                        
                        trace = push_transaction(mtrx, fc::time_point::maximum());
                    }
                    else if(receipt.type == transaction_receipt::suspend) {
                        // suspend transaction is executed in its parent transaction
                        // so don't execute here
                        num_pending_receipts++;
                        continue;
                    }
                    else {
                        EVT_THROW(block_validate_exception, "encountered unexpected receipt type");
                    }

                    auto transaction_failed = trace && trace->except;
                    if(transaction_failed) {
                        edump((*trace));
                        throw *trace->except;
                    }
                    EVT_ASSERT(pending->_pending_block_state->block->transactions.size() > 0,
                               block_validate_exception, "expected a receipt",
                               ("block", *b)("expected_receipt", receipt)
                               );
                    EVT_ASSERT(pending->_pending_block_state->block->transactions.size() == num_pending_receipts + 1,
                               block_validate_exception, "expected receipt was not added",
                               ("block", *b)("expected_receipt", receipt)
                               );
                    auto& r = pending->_pending_block_state->block->transactions.back();
                    EVT_ASSERT(r == static_cast<const transaction_receipt_header&>(receipt),
                               block_validate_exception, "receipt does not match",
                              ("producer_receipt", receipt)("validator_receipt", pending->_pending_block_state->block->transactions.back())
                              );

                    num_pending_receipts++;
                }

                finalize_block();

                // this implicitly asserts that all header fields (less the signature) are identical
                EVT_ASSERT(producer_block_id == pending->_pending_block_state->header.id(),
                       block_validate_exception, "Block ID does not match",
                       ("producer_block_id",producer_block_id)("validator_block_id",pending->_pending_block_state->header.id()));

                // We need to fill out the pending block state's block because that gets serialized in the reversible block log
                // in the future we can optimize this by serializing the original and not the copy

                // we can always trust this signature because,
                //   - prior to apply_block, we call fork_db.add which does a signature check IFF the block is untrusted
                //   - OTHERWISE the block is trusted and therefore we trust that the signature is valid
                // Also, as ::sign_block does not lazily calculate the digest of the block, we can just short-circuit to save cycles
                pending->_pending_block_state->header.producer_signature = b->producer_signature;
                static_cast<signed_block_header&>(*pending->_pending_block_state->block) =  pending->_pending_block_state->header;

                commit_block(false);
                return;
            }
            catch(const fc::exception& e) {
                edump((e.to_detail_string()));
                abort_block();
                throw;
            }
        }
        FC_CAPTURE_AND_RETHROW()
    }  /// apply_block

    void
    push_block(const signed_block_ptr& b) {
        auto s = controller::block_status::complete;
        EVT_ASSERT(!pending.has_value(), block_validate_exception, "it is not valid to push a block when there is a pending block");

        auto reset_prod_light_validation = fc::make_scoped_exit([old_value=trusted_producer_light_validation, this]() {
            trusted_producer_light_validation = old_value;
        });

        try {
            EVT_ASSERT(b, block_validate_exception, "trying to push empty block");
            EVT_ASSERT(s != controller::block_status::incomplete, block_validate_exception, "invalid block status for a completed block");
            emit(self.pre_accepted_block, b);

            auto new_header_state = fork_db.add(b, false);

            if(conf.trusted_producers.count(b->producer)) {
                trusted_producer_light_validation = true;
            };
            emit(self.accepted_block_header, new_header_state);

            if(read_mode != db_read_mode::IRREVERSIBLE) {
                maybe_switch_forks(s);
            }
        }
        FC_LOG_AND_RETHROW()
    }

    void
    replay_push_block(const signed_block_ptr& b, controller::block_status s) {
        self.validate_db_available_size();
        self.validate_reversible_available_size();

        EVT_ASSERT(!pending.has_value(), block_validate_exception, "it is not valid to push a block when there is a pending block");

        try {
            EVT_ASSERT(b, block_validate_exception, "trying to push empty block");
            EVT_ASSERT(s != controller::block_status::incomplete, block_validate_exception, "invalid block status for a completed block");
            emit(self.pre_accepted_block, b);

            const bool skip_validate_signee = !conf.force_all_checks;
            auto new_header_state = fork_db.add(b, skip_validate_signee);

            emit(self.accepted_block_header, new_header_state);

            if(read_mode != db_read_mode::IRREVERSIBLE) {
                maybe_switch_forks(s);
            }

            // on replay irreversible is not emitted by fork database, so emit it explicitly here
            if(s == controller::block_status::irreversible) {
                emit(self.irreversible_block, new_header_state);
            }
        }
        FC_LOG_AND_RETHROW()
    }

    void
    maybe_switch_forks(controller::block_status s = controller::block_status::complete) {
        auto new_head = fork_db.head();

        if(new_head->header.previous == head->id) {
            try {
                apply_block(new_head->block, s);
                fork_db.mark_in_current_chain(new_head, true);
                fork_db.set_validity(new_head, true);
                head = new_head;
            }
            catch(const fc::exception& e) {
                fork_db.set_validity(new_head, false);  // Removes new_head from fork_db index, so no need to mark it as not in the current chain.
                throw;
            }
        }
        else if(new_head->id != head->id) {
            ilog("switching forks from ${current_head_id} (block number ${current_head_num}) to ${new_head_id} (block number ${new_head_num})",
                 ("current_head_id", head->id)("current_head_num", head->block_num)("new_head_id", new_head->id)("new_head_num", new_head->block_num));
            auto branches = fork_db.fetch_branch_from(new_head->id, head->id);

            for(auto itr = branches.second.begin(); itr != branches.second.end(); ++itr) {
                fork_db.mark_in_current_chain(*itr, false);
                pop_block();
            }
            EVT_ASSERT(self.head_block_id() == branches.second.back()->header.previous, fork_database_exception,
                      "loss of sync between fork_db and chainbase during fork switch");  // _should_ never fail

            for(auto ritr = branches.first.rbegin(); ritr != branches.first.rend(); ++ritr) {
                optional<fc::exception> except;
                try {
                    apply_block((*ritr)->block,  (*ritr)->validated ? controller::block_status::validated : controller::block_status::complete);
                    head = *ritr;
                    fork_db.mark_in_current_chain(*ritr, true);
                    (*ritr)->validated = true;
                }
                catch(const fc::exception& e) {
                    except = e;
                }
                if(except) {
                    elog("exception thrown while switching forks ${e}", ("e", except->to_detail_string()));

                    // ritr currently points to the block that threw
                    // if we mark it invalid it will automatically remove all forks built off it.
                    fork_db.set_validity(*ritr, false);

                    // pop all blocks from the bad fork
                    // ritr base is a forward itr to the last block successfully applied
                    auto applied_itr = ritr.base();
                    for(auto itr = applied_itr; itr != branches.first.end(); ++itr) {
                        fork_db.mark_in_current_chain(*itr, false);
                        pop_block();
                    }
                    EVT_ASSERT(self.head_block_id() == branches.second.back()->header.previous, fork_database_exception,
                              "loss of sync between fork_db and chainbase during fork switch reversal");  // _should_ never fail

                    // re-apply good blocks
                    for(auto ritr = branches.second.rbegin(); ritr != branches.second.rend(); ++ritr) {
                        apply_block((*ritr)->block, controller::block_status::validated /* we previously validated these blocks*/);
                        head = *ritr;
                        fork_db.mark_in_current_chain(*ritr, true);
                    }
                    throw *except;
                }  // end if exception
            }      /// end for each block in branch
            ilog("successfully switched fork to new head ${new_head_id}", ("new_head_id", new_head->id));
        }
    }  /// push_block

    void
    abort_block() {
        if(pending.has_value()) {
            if(read_mode == db_read_mode::SPECULATIVE) {
                for(const auto& t : pending->_pending_block_state->trxs) {
                    unapplied_transactions[t->signed_id] = t;
                }
            }
            pending.reset();
        }
    }

    bool
    should_enforce_runtime_limits() const {
        return false;
    }

    void
    set_action_merkle() {
        vector<digest_type> action_digests;
        action_digests.reserve(pending->_actions.size());
        for(const auto& a : pending->_actions) {
            action_digests.emplace_back(a.digest());
        }

        pending->_pending_block_state->header.action_mroot = merkle(move(action_digests));
    }

    void
    set_trx_merkle() {
        vector<digest_type> trx_digests;
        const auto&         trxs = pending->_pending_block_state->block->transactions;
        trx_digests.reserve(trxs.size());
        for(const auto& trx : trxs) {
            trx_digests.emplace_back(trx.digest());
        }

        pending->_pending_block_state->header.transaction_mroot = merkle(move(trx_digests));
    }

    void
    finalize_block() {
        EVT_ASSERT(pending.has_value(), block_validate_exception, "it is not valid to finalize when there is no pending block");
        try {
            set_action_merkle();
            set_trx_merkle();

            auto p = pending->_pending_block_state;
            p->id  = p->header.id();

            create_block_summary(p->id);
        }
        FC_CAPTURE_AND_RETHROW()
    }

    void
    create_block_summary(const block_id_type& id) {
        auto block_num = block_header::num_from_id(id);
        auto sid       = block_num & 0xffff;
        db.modify(db.get<block_summary_object, by_id>(sid), [&](block_summary_object& bso) {
            bso.block_id = id;
        });
    }

    void
    clear_expired_input_transactions() {
        //Look for expired transactions in the deduplication list, and remove them.
        auto&       transaction_idx = db.get_mutable_index<transaction_multi_index>();
        const auto& dedupe_index    = transaction_idx.indices().get<by_expiration>();
        auto        now             = self.pending_block_time();
        while((!dedupe_index.empty()) && (now > fc::time_point(dedupe_index.begin()->expiration))) {
            transaction_idx.remove(*dedupe_index.begin());
        }
    }

};  /// controller_impl

controller::controller(const controller::config& cfg)
    : my(new controller_impl(cfg, *this)) {
}

controller::~controller() {
    my->abort_block();
    //close fork_db here, because it can generate "irreversible" signal to this controller,
    //in case if read-mode == IRREVERSIBLE, we will apply latest irreversible block
    //for that we need 'my' to be valid pointer pointing to valid controller_impl.
    my->fork_db.close();
}

void
controller::add_indices() {
    my->add_indices();
}

void
controller::startup(const snapshot_reader_ptr& snapshot) {
    my->head = my->fork_db.head();
    if(snapshot) {
        ilog("Starting initialization from snapshot, this may take a significant amount of time");
    }
    else if(!my->head) {
        wlog("No head block in fork db, perhaps we need to replay");
    }

    try {
        my->init(snapshot);
    }
    catch(boost::interprocess::bad_alloc& e) {
        if(snapshot) {
            elog("db storage not configured to have enough storage for the provided snapshot, please increase and retry snapshot");
        }
        throw e;
    }
    if(snapshot) {
        ilog("Finished initialization from snapshot");
    }
}

chainbase::database&
controller::db() const {
    return my->db;
}

fork_database&
controller::fork_db() const {
    return my->fork_db;
}

token_database&
controller::token_db() const {
    return my->token_db;
}

token_database_cache&
controller::token_db_cache() const {
    return my->token_db_cache;
}

charge_manager
controller::get_charge_manager() const {
    return charge_manager(*this, my->exec_ctx);
}

execution_context&
controller::get_execution_context() const {
    return my->exec_ctx;
}

void
controller::start_block(block_timestamp_type when, uint16_t confirm_block_count) {
    validate_db_available_size();
    my->start_block(when, confirm_block_count, block_status::incomplete, optional<block_id_type>());
}

void
controller::finalize_block() {
    validate_db_available_size();
    my->finalize_block();
}

void
controller::sign_block(const std::function<signature_type(const digest_type&)>& signer_callback) {
    my->sign_block(signer_callback);
}

void
controller::commit_block() {
    validate_db_available_size();
    validate_reversible_available_size();
    my->commit_block(true);
}

void
controller::abort_block() {
    my->abort_block();
}

void
controller::push_block(const signed_block_ptr& b) {
    validate_db_available_size();
    validate_reversible_available_size();
    my->push_block(b);
}

transaction_trace_ptr
controller::push_transaction(const transaction_metadata_ptr& trx, fc::time_point deadline) {
    validate_db_available_size();
    EVT_ASSERT(get_read_mode() != chain::db_read_mode::READ_ONLY, transaction_type_exception, "push transaction not allowed in read-only mode");
    EVT_ASSERT(trx && !trx->implicit, transaction_type_exception, "Implicit transaction not allowed");
    return my->push_transaction(trx, deadline);
}

transaction_trace_ptr
controller::push_suspend_transaction(const transaction_metadata_ptr& trx, fc::time_point deadline) {
    validate_db_available_size();
    return my->push_suspend_transaction(trx, deadline);
}

void
controller::check_authorization(const public_keys_set& signed_keys, const transaction& trx) {
    return my->check_authorization(signed_keys, trx);
}

void
controller::check_authorization(const public_keys_set& signed_keys, const action& act) {
    return my->check_authorization(signed_keys, act);
}

uint32_t
controller::head_block_num() const {
    return my->head->block_num;
}

time_point
controller::head_block_time() const {
    return my->head->header.timestamp;
}

block_id_type
controller::head_block_id() const {
    return my->head->id;
}

account_name
controller::head_block_producer() const {
    return my->head->header.producer;
}

const block_header&
controller::head_block_header() const {
    return my->head->header;
}

block_state_ptr
controller::head_block_state() const {
    return my->head;
}

uint32_t
controller::fork_db_head_block_num() const {
   return my->fork_db.head()->block_num;
}

block_id_type
controller::fork_db_head_block_id() const {
   return my->fork_db.head()->id;
}

time_point
controller::fork_db_head_block_time() const {
   return my->fork_db.head()->header.timestamp;
}

account_name
controller::fork_db_head_block_producer() const {
   return my->fork_db.head()->header.producer;
}

block_state_ptr
controller::pending_block_state() const {
    if(my->pending.has_value())
        return my->pending->_pending_block_state;
    return block_state_ptr();
}
time_point
controller::pending_block_time() const {
    EVT_ASSERT(my->pending.has_value(), block_validate_exception, "no pending block");
    return my->pending->_pending_block_state->header.timestamp;
}

optional<block_id_type>
controller::pending_producer_block_id() const {
   EVT_ASSERT(my->pending.has_value(), block_validate_exception, "no pending block");
   return my->pending->_producer_block_id;
}

uint32_t
controller::last_irreversible_block_num() const {
    return std::max(std::max(my->head->bft_irreversible_blocknum, my->head->dpos_irreversible_blocknum), my->snapshot_head_block);
}

block_id_type
controller::last_irreversible_block_id() const {
    auto        lib_num             = last_irreversible_block_num();
    const auto& tapos_block_summary = db().get<block_summary_object>((uint16_t)lib_num);

    if(block_header::num_from_id(tapos_block_summary.block_id) == lib_num)
        return tapos_block_summary.block_id;

    return fetch_block_by_number(lib_num)->id();
}

const dynamic_global_property_object&
controller::get_dynamic_global_properties() const {
    return my->db.get<dynamic_global_property_object>();
}

const global_property_object&
controller::get_global_properties() const {
    return my->db.get<global_property_object>();
}

signed_block_ptr
controller::fetch_block_by_id(block_id_type id) const {
    auto state = my->fork_db.get_block(id);
    if(state && state->block) {
        return state->block;
    }
    auto bptr = fetch_block_by_number(block_header::num_from_id(id));
    if(bptr && bptr->id() == id) {
        return bptr;
    }
    return signed_block_ptr();
}

signed_block_ptr
controller::fetch_block_by_number(uint32_t block_num) const {
    try {
        auto blk_state = my->fork_db.get_block_in_current_chain_by_num(block_num);
        if(blk_state && blk_state->block) {
            return blk_state->block;
        }

        return my->blog.read_block_by_num(block_num);
    }
    FC_CAPTURE_AND_RETHROW((block_num))
}

block_state_ptr
controller::fetch_block_state_by_id(block_id_type id) const {
    auto state = my->fork_db.get_block(id);
    return state;
}

block_state_ptr
controller::fetch_block_state_by_number(uint32_t block_num) const { 
    try {
        auto blk_state = my->fork_db.get_block_in_current_chain_by_num(block_num);
        return blk_state;
    }
    FC_CAPTURE_AND_RETHROW((block_num))
}


block_id_type
controller::get_block_id_for_num(uint32_t block_num) const {
    try {
        auto blk_state = my->fork_db.get_block_in_current_chain_by_num(block_num);
        if(blk_state) {
            return blk_state->id;
        }

        auto signed_blk = my->blog.read_block_by_num(block_num);

        EVT_ASSERT(BOOST_LIKELY(signed_blk != nullptr), unknown_block_exception,
                   "Could not find block: ${block}", ("block", block_num));

        return signed_blk->id();
    }
    FC_CAPTURE_AND_RETHROW((block_num))
}

evt_link_object
controller::get_link_obj_for_link_id(const link_id_type& link_id) const {
    evt_link_object link_obj;

    auto str = std::string();
    try {
        my->token_db.read_token(token_type::evtlink, std::nullopt, link_id, str);
    }
    catch(token_database_exception&) {
        EVT_THROW2(evt_link_existed_exception, "Cannot find EvtLink with id: {}", fc::to_hex((char*)&link_id, sizeof(link_id)));
    }

    extract_db_value(str, link_obj);
    return link_obj;
}

uint32_t
controller::get_block_num_for_trx_id(const transaction_id_type& trx_id) const {
    if(const auto* t = my->db.find<transaction_object, by_trx_id>(trx_id)) {
        return t->block_num;
    }
    EVT_THROW(unknown_transaction_exception, "Transaction: ${t} is not existed", ("t",trx_id));
}

fc::sha256
controller::calculate_integrity_hash() const {
    try {
        return my->calculate_integrity_hash();
    }
    FC_LOG_AND_RETHROW()
}

void
controller::write_snapshot(const snapshot_writer_ptr& snapshot) const {
    EVT_ASSERT(!my->pending.has_value(), block_validate_exception, "cannot take a consistent snapshot with a pending block");
    return my->add_to_snapshot(snapshot);
}

void
controller::pop_block() {
    my->pop_block();
}

int64_t
controller::set_proposed_producers(vector<producer_key> producers) {
    const auto& gpo           = get_global_properties();
    auto        cur_block_num = head_block_num() + 1;

    if(gpo.proposed_schedule_block_num.has_value()) {
        if(*gpo.proposed_schedule_block_num != cur_block_num)
            return -1;  // there is already a proposed schedule set in a previous block, wait for it to become pending

        if(std::equal(producers.begin(), producers.end(),
                      gpo.proposed_schedule.producers.begin(), gpo.proposed_schedule.producers.end()))
            return -1;  // the proposed producer schedule does not change
    }

    producer_schedule_type sch;

    decltype(sch.producers.cend()) end;
    decltype(end)                  begin;

    if(my->pending->_pending_block_state->pending_schedule.producers.size() == 0) {
        const auto& active_sch = my->pending->_pending_block_state->active_schedule;
        begin                  = active_sch.producers.begin();
        end                    = active_sch.producers.end();
        sch.version            = active_sch.version + 1;
    }
    else {
        const auto& pending_sch = my->pending->_pending_block_state->pending_schedule;
        begin                   = pending_sch.producers.begin();
        end                     = pending_sch.producers.end();
        sch.version             = pending_sch.version + 1;
    }

    if(std::equal(producers.begin(), producers.end(), begin, end))
        return -1;  // the producer schedule would not change

    sch.producers = std::move(producers);

    auto version = sch.version;

    my->db.modify(gpo, [&](auto& gp) {
        gp.proposed_schedule_block_num = cur_block_num;
        gp.proposed_schedule           = std::move(sch);
    });
    return version;
}

void
controller::set_chain_config(const chain_config& config) {
    const auto& gpo = get_global_properties();
    my->db.modify(gpo, [&](auto& gp) {
        gp.configuration = config;
    });
}

const producer_schedule_type&
controller::active_producers() const {
    if(!(my->pending.has_value())) {
        return my->head->active_schedule;
    }
    return my->pending->_pending_block_state->active_schedule;
}

const producer_schedule_type&
controller::pending_producers() const {
    if(!(my->pending.has_value())) {
        return my->head->pending_schedule;
    }
    return my->pending->_pending_block_state->pending_schedule;
}

optional<producer_schedule_type>
controller::proposed_producers() const {
    const auto& gpo = get_global_properties();
    if(!gpo.proposed_schedule_block_num.has_value()) {
        return optional<producer_schedule_type>();
    }
    return gpo.proposed_schedule;
}

bool
controller::light_validation_allowed(bool replay_opts_disabled_by_policy) const {
    if(!my->pending.has_value() || my->in_trx_requiring_checks) {
        return false;
    }

    const auto pb_status = my->pending->_block_status;

    // in a pending irreversible or previously validated block and we have forcing all checks
    const bool consider_skipping_on_replay = (pb_status == block_status::irreversible || pb_status == block_status::validated) && !replay_opts_disabled_by_policy;

    // OR in a signed block and in light validation mode
    const bool consider_skipping_on_validate = (pb_status == block_status::complete &&
        (my->conf.block_validation_mode == validation_mode::LIGHT || my->trusted_producer_light_validation));

    return consider_skipping_on_replay || consider_skipping_on_validate;
}

bool
controller::skip_auth_check() const {
    return light_validation_allowed(my->conf.force_all_checks);
}

bool
controller::skip_db_sessions(block_status bs) const {
    bool consider_skipping = bs == block_status::irreversible;
    return consider_skipping
           && !my->conf.disable_replay_opts
           && !my->in_trx_requiring_checks;
}

bool
controller::skip_db_sessions() const {
    if(my->pending) {
        return skip_db_sessions(my->pending->_block_status);
    }
    else {
        return false;
    }
}

bool
controller::skip_trx_checks() const {
    return light_validation_allowed(my->conf.disable_replay_opts);
}

bool
controller::loadtest_mode() const {
    return my->conf.loadtest_mode;
}

bool
controller::charge_free_mode() const {
    return my->conf.charge_free_mode;
}

bool
controller::contracts_console() const {
    return my->conf.contracts_console;
}

db_read_mode
controller::get_read_mode() const {
   return my->read_mode;
}

validation_mode
controller::get_validation_mode() const {
    return my->conf.block_validation_mode;
}

const chain_id_type&
controller::get_chain_id() const {
    return my->chain_id;
}

const genesis_state&
controller::get_genesis_state() const {
    return my->conf.genesis;
}

const abi_serializer&
controller::get_abi_serializer() const {
    return my->system_api;
}

unapplied_transactions_type&
controller::get_unapplied_transactions() const {
    if(my->read_mode != db_read_mode::SPECULATIVE) {
        EVT_ASSERT(my->unapplied_transactions.empty(), transaction_exception,
            "not empty unapplied_transactions in non-speculative mode"); //should never happen
    }
    return my->unapplied_transactions;
}

bool
controller::is_producing_block() const {
   if(!my->pending.has_value()) return false;

   return (my->pending->_block_status == block_status::incomplete);
}

void
controller::validate_expiration(const transaction& trx) const {
    try {
        const auto& chain_configuration = get_global_properties().configuration;

        EVT_ASSERT(time_point(trx.expiration) >= pending_block_time(),
                   expired_tx_exception,
                   "transaction has expired, "
                   "expiration is ${trx.expiration} and pending block time is ${pending_block_time}",
                   ("trx.expiration", trx.expiration)("pending_block_time", pending_block_time()));
        EVT_ASSERT(time_point(trx.expiration) <= pending_block_time() + fc::seconds(chain_configuration.max_transaction_lifetime),
                   tx_exp_too_far_exception,
                   "Transaction expiration is too far in the future relative to the reference time of ${reference_time}, "
                   "expiration is ${trx.expiration} and the maximum transaction lifetime is ${max_til_exp} seconds",
                   ("trx.expiration", trx.expiration)("reference_time", pending_block_time())("max_til_exp", chain_configuration.max_transaction_lifetime));
    }
    FC_CAPTURE_AND_RETHROW((trx))
}

void
controller::validate_tapos(const transaction& trx) const {
    try {
        const auto& tapos_block_summary = db().get<block_summary_object>((uint16_t)trx.ref_block_num);

        //Verify TaPoS block summary has correct ID prefix, and that this block's time is not past the expiration
        EVT_ASSERT(trx.verify_reference_block(tapos_block_summary.block_id), invalid_ref_block_exception,
                   "Transaction's reference block did not match. Is this transaction from a different fork?",
                   ("tapos_summary", tapos_block_summary));
    }
    FC_CAPTURE_AND_RETHROW()
}

void
controller::validate_db_available_size() const {
   const auto free = db().get_segment_manager()->get_free_memory();
   const auto guard = my->conf.state_guard_size;
   EVT_ASSERT(free >= guard, database_guard_exception, "database free: ${f}, guard size: ${g}", ("f", free)("g",guard));
}

void
controller::validate_reversible_available_size() const {
   const auto free = my->reversible_blocks.get_segment_manager()->get_free_memory();
   const auto guard = my->conf.reversible_guard_size;
   EVT_ASSERT(free >= guard, reversible_guard_exception, "reversible free: ${f}, guard size: ${g}", ("f", free)("g",guard));
}

bool
controller::is_known_unexpired_transaction(const transaction_id_type& id) const {
    return db().find<transaction_object, by_trx_id>(id);
}

public_keys_set
controller::get_required_keys(const transaction& trx, const public_keys_set& candidate_keys) const {
    const static uint32_t max_authority_depth = my->conf.genesis.initial_configuration.max_authority_depth;
    auto checker = authority_checker(*this, my->exec_ctx, candidate_keys, max_authority_depth);

    for(const auto& act : trx.actions) {
        EVT_ASSERT(checker.satisfied(act), unsatisfied_authorization,
                   "${name} action in domain: ${domain} with key: ${key} authorized failed",
                   ("domain", act.domain)("key", act.key)("name", act.name));
    }

    auto keys = checker.used_keys();
    if(trx.payer.type() == address::public_key_t) {
        keys.emplace(trx.payer.get_public_key());
    }
    return keys;
}

public_keys_set
controller::get_suspend_required_keys(const transaction& trx, const public_keys_set& candidate_keys) const {
    const static uint32_t max_authority_depth = my->conf.genesis.initial_configuration.max_authority_depth;
    auto checker = authority_checker(*this, my->exec_ctx, candidate_keys, max_authority_depth);

    for(const auto& act : trx.actions) {
        checker.satisfied(act);
    }

    auto keys = checker.used_keys();
    if(trx.payer.type() == address::public_key_t) {
        keys.emplace(trx.payer.get_public_key());
    }
    return keys;
}

public_keys_set
controller::get_suspend_required_keys(const proposal_name& name, const public_keys_set& candidate_keys) const {
    suspend_def suspend;

    auto str = std::string();
    try {
        my->token_db.read_token(token_type::suspend, std::nullopt, name, str);
    }
    catch(token_database_exception&) {
        EVT_THROW2(unknown_lock_exception, "Cannot find suspend proposal: {}", name);
    }

    extract_db_value(str, suspend);
    return get_suspend_required_keys(suspend.trx, candidate_keys);
}

uint32_t
controller::get_charge(transaction&& trx, size_t signautres_num) const {   
    auto ptrx   = packed_transaction(std::move(trx),  {});
    auto charge = get_charge_manager();
    return charge.calculate(ptrx, signautres_num);
}

}}  // namespace evt::chain
