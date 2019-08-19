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
#include <evt/chain/protocol_feature_manager.hpp>
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
#include <evt/chain/protocol_state_object.hpp>
#include <evt/chain/transaction_object.hpp>
#include <evt/chain/reversible_block_object.hpp>
#include <evt/chain/contracts/evt_link_object.hpp>

namespace evt { namespace chain {

using controller_index_set = index_set<
   global_property_multi_index,
   protocol_state_multi_index
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

struct building_block {
    building_block(const block_header_state&  prev,
                   block_timestamp_type       when,
                   uint16_t                   num_prev_blocks_to_confirm,
                   const vector<digest_type>& new_protocol_feature_activations)
        : _pending_block_header_state(prev.next(when, num_prev_blocks_to_confirm))
        , _new_protocol_feature_activations(new_protocol_feature_activations) {}

    pending_block_header_state       _pending_block_header_state;
    optional<producer_schedule_type> _new_pending_producer_schedule;
    vector<digest_type>              _new_protocol_feature_activations;
    size_t                           _num_new_protocol_features_that_have_activated = 0;
    vector<transaction_metadata_ptr> _pending_trx_metas;
    vector<transaction_receipt>      _pending_trx_receipts;
    vector<action_receipt>           _actions;
};

struct assembled_block {
    block_id_type                    _id;
    pending_block_header_state       _pending_block_header_state;
    vector<transaction_metadata_ptr> _trx_metas;
    signed_block_ptr                 _unsigned_block;
};

struct completed_block {
    block_state_ptr _block_state;
};

using block_stage_type = fc::static_variant<building_block, assembled_block, completed_block>;

struct pending_state {
    pending_state(maybe_session&&            s,
                  const block_header_state&  prev,
                  block_timestamp_type       when,
                  uint16_t                   num_prev_blocks_to_confirm,
                  const vector<digest_type>& new_protocol_feature_activations)
        : _db_session(move(s))
        , _block_stage(building_block(prev, when, num_prev_blocks_to_confirm, new_protocol_feature_activations)) {}

    maybe_session            _db_session;
    block_stage_type         _block_stage;
    controller::block_status _block_status = controller::block_status::incomplete;
    optional<block_id_type>  _producer_block_id;

    /** @pre _block_stage cannot hold completed_block alternative */
    const pending_block_header_state&
    get_pending_block_header_state() const {
        if(_block_stage.contains<building_block>()) {
            return _block_stage.get<building_block>()._pending_block_header_state;
        }

        return _block_stage.get<assembled_block>()._pending_block_header_state;
    }

    const vector<transaction_receipt>&
    get_trx_receipts() const {
        if(_block_stage.contains<building_block>()) {
            return _block_stage.get<building_block>()._pending_trx_receipts;
        }

        if(_block_stage.contains<assembled_block>()) {
            return _block_stage.get<assembled_block>()._unsigned_block->transactions;
        }

        return _block_stage.get<completed_block>()._block_state->block->transactions;
    }

    const vector<transaction_metadata_ptr>&
    get_trx_metas() const {
        if(_block_stage.contains<building_block>()) {
            return _block_stage.get<building_block>()._pending_trx_metas;
        }

        if(_block_stage.contains<assembled_block>()) {
            return _block_stage.get<assembled_block>()._trx_metas;
        }

        return _block_stage.get<completed_block>()._block_state->trxs;
    }

    bool
    is_protocol_feature_activated(const digest_type& feature_digest) const {
        if(_block_stage.contains<building_block>()) {
            auto&       bb                 = _block_stage.get<building_block>();
            const auto& activated_features = bb._pending_block_header_state.prev_activated_protocol_features->protocol_features;

            if(activated_features.find(feature_digest) != activated_features.end()) {
                return true;
            }

            if(bb._num_new_protocol_features_that_have_activated == 0) {
                return false;
            }

            auto end = bb._new_protocol_feature_activations.begin() + bb._num_new_protocol_features_that_have_activated;
            return (std::find(bb._new_protocol_feature_activations.begin(), end, feature_digest) != end);
        }

        if(_block_stage.contains<assembled_block>()) {
            // Calling is_protocol_feature_activated during the assembled_block stage is not efficient.
            // We should avoid doing it.
            // In fact for now it isn't even implemented.
            EVT_THROW(misc_exception,
                      "checking if protocol feature is activated in the assembled_block stage is not yet supported");
            // TODO: implement this
        }

        const auto& activated_features = _block_stage.get<completed_block>()._block_state->activated_protocol_features->protocol_features;
        return (activated_features.find(feature_digest) != activated_features.end());
    }

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
    protocol_feature_manager protocol_features;
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

    unordered_map<builtin_protocol_feature_t, std::function<void(controller_impl&)>, enum_hash<builtin_protocol_feature_t>> protocol_feature_activation_handlers;

    /**
     *  Transactions that were undone by pop_block or abort_block, transactions
     *  are removed from this list if they are re-applied in other blocks. Producers
     *  can query this list when scheduling new transactions into blocks.
     */
    unapplied_transactions_type unapplied_transactions;

    void
    pop_block() {
        auto prev = fork_db.get_block(head->header.previous);
        if(!prev) {
            EVT_ASSERT(fork_db.root()->id == head->header.previous, block_validate_exception, "attempt to pop beyond last irreversible block");
            prev = fork_db.root();
        }

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
        protocol_features.popped_blocks_to(prev->block_num);
    }

    template<builtin_protocol_feature_t F>
    void on_activation();

    template<builtin_protocol_feature_t F>
    inline void
    set_activation_handler() {
        auto res = protocol_feature_activation_handlers.emplace(F, &controller_impl::on_activation<F>);
        EVT_ASSERT(res.second, misc_exception, "attempting to set activation handler twice");
    }

    inline void
    trigger_activation_handler(builtin_protocol_feature_t f) {
        auto itr = protocol_feature_activation_handlers.find(f);
        if(itr == protocol_feature_activation_handlers.end()){
            return;
        }
        else {
            (itr->second)(*this);
        }
    }

    controller_impl(const controller::config& cfg, controller& s, protocol_feature_set&& pfs)
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
        , protocol_features(std::move(pfs))
        , conf(cfg)
        , chain_id(cfg.genesis.compute_chain_id())
        , exec_ctx(s)
        , read_mode(cfg.read_mode)
        , system_api(contracts::evt_contract_abi(), cfg.max_serialization_time) {

        fork_db.open([this](block_timestamp_type         timestamp,
                            const flat_set<digest_type>& cur_features,
                            const vector<digest_type>&   new_features) {
            check_protocol_features(timestamp, cur_features, new_features);
        });

        set_activation_handler<builtin_protocol_feature_t::preactivate_feature>();
        set_activation_handler<builtin_protocol_feature_t::replace_deferred>();
        set_activation_handler<builtin_protocol_feature_t::get_sender>();
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
    log_irreversible() {
        EVT_ASSERT(fork_db.root(), fork_database_exception, "fork database not properly initialized");

        const auto& log_head = blog.head();

        auto lib_num = log_head ? log_head->block_num() : (blog.first_block_num() - 1);

        auto root_id = fork_db.root()->id;

        if(log_head) {
            EVT_ASSERT(root_id == log_head->id(), fork_database_exception, "fork database root does not match block log head");
        }
        else {
            EVT_ASSERT(fork_db.root()->block_num == lib_num, fork_database_exception,
                       "empty block log expects the first appended block to build off a block that is not the fork database root");
        }

        auto fork_head = (read_mode == db_read_mode::IRREVERSIBLE) ? fork_db.pending_head() : fork_db.head();

        if(fork_head->dpos_irreversible_blocknum <= lib_num) {
            return;
        }

        const auto branch = fork_db.fetch_branch(fork_head->id, fork_head->dpos_irreversible_blocknum);
        try {
            const auto& rbi = reversible_blocks.get_index<reversible_block_index, by_num>();

            for(auto bitr = branch.rbegin(); bitr != branch.rend(); ++bitr) {
                if(read_mode == db_read_mode::IRREVERSIBLE) {
                    apply_block(*bitr, controller::block_status::complete);
                    head = (*bitr);
                    fork_db.mark_valid(head);
                }

                emit(self.irreversible_block, *bitr);

                db.commit((*bitr)->block_num);
                token_db.pop_savepoints((*bitr)->block_num);

                root_id = (*bitr)->id;

                blog.append((*bitr)->block);

                auto rbitr = rbi.begin();
                while(rbitr != rbi.end() && rbitr->blocknum <= (*bitr)->block_num) {
                    reversible_blocks.remove(*rbitr);
                    rbitr = rbi.begin();
                }
            }
        }
        catch(fc::exception&) {
            if(root_id != fork_db.root()->id) {
                fork_db.advance_root(root_id);
            }
            throw;
        }

        //db.commit( fork_head->dpos_irreversible_blocknum ); // redundant

        if(root_id != fork_db.root()->id) {
            fork_db.advance_root(root_id);
        }
    }

    /**
     *  Sets fork database head to the genesis state.
     */
    void
    initialize_blockchain_state() {
        wlog("Initializing new blockchain with genesis state");
        producer_schedule_type initial_schedule{0, {{config::system_account_name, conf.genesis.initial_key}}};

        block_header_state genheader;
        genheader.active_schedule                = initial_schedule;
        genheader.pending_schedule.schedule      = initial_schedule;
        genheader.pending_schedule.schedule_hash = fc::sha256::hash(initial_schedule);
        genheader.header.timestamp               = conf.genesis.initial_timestamp;
        genheader.header.action_mroot            = conf.genesis.compute_chain_id();
        genheader.id                             = genheader.header.id();
        genheader.block_num                      = genheader.header.block_num();
        genheader.block_signing_key              = conf.genesis.initial_key;

        head = std::make_shared<block_state>();
        static_cast<block_header_state&>(*head) = genheader;
        head->activated_protocol_features = std::make_shared<protocol_feature_activation_set>();
        head->block = std::make_shared<signed_block>(genheader.header);
        db.set_revision( head->block_num );
        initialize_database();
    }

    void
    replay() {
        auto blog_head       = blog.head();
        auto blog_head_time  = blog_head -> timestamp.to_time_point();
        replay_head_time     = blog_head_time;
        auto start_block_num = head -> block_num + 1;
        auto start           = fc::time_point::now();

        std::exception_ptr except_ptr;

        if(start_block_num <= blog_head->block_num()) {
            ilog("existing block log, attempting to replay from ${s} to ${n} blocks",
                 ("s", fmt::format("{:n}", start_block_num))("n", fmt::format("{:n}", blog_head->block_num())));
            try {
                while(auto next = blog.read_block_by_num(head->block_num + 1)) {
                    replay_push_block(next, controller::block_status::irreversible);
                    if(next->block_num() % 500 == 0) {
                        ilog("${n} of ${head}", ("n", fmt::format("{:n}", next->block_num()))("head", fmt::format("{:n}", blog_head->block_num())));
                        if(shutdown()) {
                            break;
                        }
                    }
                }
            }
            catch(const database_guard_exception& e) {
                except_ptr = std::current_exception();
            }
            ilog("${n} irreversible blocks replayed", ("n", fmt::format("{:n}", 1 + head->block_num - start_block_num)));

            auto pending_head = fork_db.pending_head();
            if(pending_head->block_num < head->block_num || head->block_num < fork_db.root()->block_num) {
                ilog("resetting fork database with new last irreversible block as the new root: ${id}",
                     ("id", head->id));
                fork_db.reset(*head);
            }
            else if(head->block_num != fork_db.root()->block_num) {
                auto new_root = fork_db.search_on_branch(pending_head->id, head->block_num);
                EVT_ASSERT(new_root, fork_database_exception, "unexpected error: could not find new LIB in fork database");
                ilog("advancing fork database root to new last irreversible block within existing fork database: ${id}",
                     ("id", new_root->id));
                fork_db.mark_valid(new_root);
                fork_db.advance_root(new_root->id);
            }

            // if the irreverible log is played without undo sessions enabled, we need to sync the
            // revision ordinal to the appropriate expected value here.
            if(self.skip_db_sessions(controller::block_status::irreversible)) {
                db.set_revision(head->block_num);
            }
        }
        else {
            ilog("no irreversible blocks need to be replayed");
        }

        if(!except_ptr && !shutdown()) {
            int rev = 0;
            while(auto obj = reversible_blocks.find<reversible_block_object, by_num>(head->block_num + 1)) {
                ++rev;
                replay_push_block(obj->get_block(), controller::block_status::validated);
            }
            ilog("${n} reversible blocks replayed", ("n", fmt::format("{:n}", rev)));
        }

        auto end = fc::time_point::now();
        ilog("replayed ${n} blocks in ${duration} seconds, ${mspb} ms/block",
            ("n", fmt::format("{:n}", head->block_num + 1 - start_block_num))
            ("duration", fmt::format("{:n}", (end - start).count() / 1000000))
            ("mspb", fmt::format("{:.3f}", ((end - start).count() / 1000.0) / (head->block_num - start_block_num))));
        replay_head_time.reset();

        if(except_ptr) {
            std::rethrow_exception(except_ptr);
        }
    }

    void
    init(const snapshot_reader_ptr& snapshot) {
        token_db.open();

        // Setup state if necessary (or in the default case stay with already loaded state):
        uint32_t lib_num = 1u;
        if(snapshot) {
            snapshot->validate();
            if(blog.head()) {
                lib_num = blog.head()->block_num();
                read_from_snapshot(snapshot, blog.first_block_num(), lib_num);
            }
            else {
                read_from_snapshot(snapshot, 0, std::numeric_limits<uint32_t>::max());
                lib_num = head->block_num;
                blog.reset(conf.genesis, signed_block_ptr(), lib_num + 1);
            }
        }
        else {
            if(db.revision() < 1 || !fork_db.head()) {
                if(fork_db.head()) {
                    if(read_mode == db_read_mode::IRREVERSIBLE && fork_db.head()->id != fork_db.root()->id) {
                        fork_db.rollback_head_to_root();
                    }
                    wlog("No existing chain state. Initializing fresh blockchain state.");
                }
                else {
                    EVT_ASSERT(db.revision() < 1, database_exception,
                               "No existing fork database despite existing chain state. Replay required.");
                    wlog("No existing chain state or fork database. Initializing fresh blockchain state and resetting fork database.");
                }
                initialize_blockchain_state();  // sets head to genesis state
                initialize_token_db();

                if(!fork_db.head()) {
                    fork_db.reset(*head);
                }

                if(blog.head()) {
                    EVT_ASSERT(blog.first_block_num() == 1, block_log_exception,
                               "block log does not start with genesis block");
                    lib_num = blog.head()->block_num();
                }
                else {
                    blog.reset(conf.genesis, head->block);
                }
            }
            else {
                lib_num              = fork_db.root()->block_num;
                auto first_block_num = blog.first_block_num();
                if(blog.head()) {
                    EVT_ASSERT(first_block_num <= lib_num && lib_num <= blog.head()->block_num(),
                               block_log_exception,
                               "block log does not contain last irreversible block",
                               ("block_log_first_num", first_block_num)("block_log_last_num", blog.head()->block_num())("fork_db_lib", lib_num));
                    lib_num = blog.head()->block_num();
                }
                else {
                    lib_num = fork_db.root()->block_num;
                    if(first_block_num != (lib_num + 1)) {
                        blog.reset(conf.genesis, signed_block_ptr(), lib_num + 1);
                    }
                }

                if(read_mode == db_read_mode::IRREVERSIBLE && fork_db.head()->id != fork_db.root()->id) {
                    fork_db.rollback_head_to_root();
                }
                head = fork_db.head();
            }
        }

        // At this point head != nullptr && fork_db.head() != nullptr && fork_db.root() != nullptr.
        // Furthermore, fork_db.root()->block_num <= lib_num.
        // Also, even though blog.head() may still be nullptr, blog.first_block_num() is guaranteed to be lib_num + 1.

        EVT_ASSERT(db.revision() >= head->block_num, fork_database_exception,
                   "fork database head is inconsistent with state",
                   ("db", db.revision())("head", head->block_num));

        if(db.revision() > head->block_num) {
            wlog("database revision (${db}) is greater than head block number (${head}), "
                 "attempting to undo pending changes",
                 ("db", db.revision())("head", head->block_num));
        }
        while(db.revision() > head->block_num) {
            db.undo();
        }

        // setup execution context
        initialize_execution_context();

        // setup protocols
        protocol_features.init(db);

        const auto& rbi            = reversible_blocks.get_index<reversible_block_index, by_num>();
        auto        last_block_num = lib_num;

        if(read_mode == db_read_mode::IRREVERSIBLE) {
            // ensure there are no reversible blocks
            auto itr = rbi.begin();
            if(itr != rbi.end()) {
                wlog("read_mode has changed to irreversible: erasing reversible blocks");
            }
            for(; itr != rbi.end(); itr = rbi.begin()) {
                reversible_blocks.remove(*itr);
            }
        }
        else {
            auto itr = rbi.begin();
            for(; itr != rbi.end() && itr->blocknum <= lib_num; itr = rbi.begin()) {
                reversible_blocks.remove(*itr);
            }

            EVT_ASSERT(itr == rbi.end() || itr->blocknum == lib_num + 1, reversible_blocks_exception,
                       "gap exists between last irreversible block and first reversible block",
                       ("lib", lib_num)("first_reversible_block_num", itr->blocknum));

            auto ritr = rbi.rbegin();

            if(ritr != rbi.rend()) {
                last_block_num = ritr->blocknum;
            }

            EVT_ASSERT(head->block_num <= last_block_num, reversible_blocks_exception,
                       "head block (${head_num}) is greater than the last locally stored block (${last_block_num})",
                       ("head_num", head->block_num)("last_block_num", last_block_num));

            auto pending_head = fork_db.pending_head();

            if(ritr != rbi.rend()
               && lib_num < pending_head->block_num
               && pending_head->block_num <= last_block_num) {
                auto rbitr = rbi.find(pending_head->block_num);
                EVT_ASSERT(rbitr != rbi.end(), reversible_blocks_exception, "pending head block not found in reversible blocks");
                auto rev_id = rbitr->get_block_id();
                EVT_ASSERT(rev_id == pending_head->id,
                           reversible_blocks_exception,
                           "mismatch in block id of pending head block ${num} in reversible blocks database: "
                           "expected: ${expected}, actual: ${actual}",
                           ("num", pending_head->block_num)("expected", pending_head->id)("actual", rev_id));
            }
            else if(ritr != rbi.rend() && last_block_num < pending_head->block_num) {
                const auto b = fork_db.search_on_branch(pending_head->id, last_block_num);
                FC_ASSERT(b, "unexpected violation of invariants");
                auto rev_id = ritr->get_block_id();
                EVT_ASSERT(rev_id == b->id,
                           reversible_blocks_exception,
                           "mismatch in block id of last block (${num}) in reversible blocks database: "
                           "expected: ${expected}, actual: ${actual}",
                           ("num", last_block_num)("expected", b->id)("actual", rev_id));
            }
            // else no checks needed since fork_db will be completely reset on replay anyway
        }

        bool report_integrity_hash = !!snapshot || (lib_num > head->block_num);

        if(last_block_num > head->block_num) {
            replay(shutdown);  // replay any irreversible and reversible blocks ahead of current head
        }

        if(shutdown()) {
            return;
        }

        if(read_mode != db_read_mode::IRREVERSIBLE
           && fork_db.pending_head()->id != fork_db.head()->id
           && fork_db.head()->id == fork_db.root()->id) {
            wlog("read_mode has changed from irreversible: applying best branch from fork database");

            for(auto pending_head = fork_db.pending_head();
                pending_head->id != fork_db.head()->id;
                pending_head = fork_db.pending_head()) {
                wlog("applying branch from fork database ending with block: ${id}", ("id", pending_head->id));
                maybe_switch_forks(pending_head, controller::block_status::complete);
            }
        }

        if(report_integrity_hash) {
            const auto hash = calculate_integrity_hash();
            ilog("database initialized with hash: ${hash}", ("hash", hash));
        }

        // add workaround to evt & pevt in evt-3.3.2
        update_evt_org(token_db, conf.genesis);
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
    read_from_snapshot(const snapshot_reader_ptr& snapshot, uint32_t blog_start, uint32_t blog_end) {
        snapshot->read_section<chain_snapshot_header>([this](auto& section) {
            chain_snapshot_header header;
            section.read_row(header, db);
            header.validate();
        });

        snapshot->read_section<block_state>([this, blog_start, blog_end](auto& section) {
            block_header_state head_header_state;
            section.read_row(head_header_state, db);

            snapshot_head_block = head_header_state.block_num;
            EVT_ASSERT(blog_start <= (snapshot_head_block + 1) && snapshot_head_block <= blog_end,
                       block_log_exception,
                       "Block log is provided with snapshot but does not contain the head block from the snapshot nor a block right after it",
                       ("snapshot_head_block", snapshot_head_block)
                       ("block_log_first_num", blog_start)
                       ("block_log_last_num", blog_end)
            );

            fork_db.reset( head_header_state );
            head = fork_db.head();
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

    void
    initialize_execution_context() {
        exec_ctx.initialize();
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

        db.create<protocol_state_object>([&](auto& pso) {
            pso.num_supported_key_types = 2;
            for(const auto& i : genesis_intrinsics) {
                add_intrinsic_to_whitelist(pso.whitelisted_intrinsics, i);
            }
        });

        db.create<dynamic_global_property_object>([](auto&) {});
    }

    void
    initialize_token_db() {
        initialize_evt_org(token_db, conf.genesis);
    }

    // The returned scoped_exit should not exceed the lifetime of the pending which existed when make_block_restore_point was called.
    fc::scoped_exit<std::function<void()>>
    make_block_restore_point() {
        auto& bb = pending->_block_stage.get<building_block>();
        auto orig_block_transactions_size = bb._pending_trx_receipts.size();
        auto orig_state_transactions_size = bb._pending_trx_metas.size();
        auto orig_state_actions_size      = bb._actions.size();

        std::function<void()> callback = [this,
                                          orig_block_transactions_size,
                                          orig_state_transactions_size,
                                          orig_state_actions_size]() {
            auto& bb = pending->_block_stage.get<building_block>();
            bb._pending_trx_receipts.resize(orig_block_transactions_size);
            bb._pending_trx_metas.resize(orig_state_transactions_size);
            bb._actions.resize(orig_state_actions_size);
        };

        return fc::make_scoped_exit(std::move(callback));
    }

    /**
     *  Adds the transaction receipt to the pending block and returns it.
     */
    template <typename T>
    const transaction_receipt&
    push_receipt(const T& trx, transaction_receipt_header::status_enum status, transaction_receipt_header::type_enum type) {
        auto& receipts = pending->_block_stage.get<building_block>()._pending_trx_receipts;
        receipts.emplace_back(trx);

        transaction_receipt& r = receipts.back();
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

                fc::move_append(pending->_block_stage.get<building_block>()._actions, move(trx_context.executed));

                emit(self.accepted_transaction, trx);
                emit(self.applied_transaction, std::tie(trace, trx));

                trx_context.squash();
                restore.cancel();
                return trace;
            }
            catch(const disallowed_transaction_extensions_bad_block_exception&) {
                throw;
            }
            catch(const protocol_feature_bad_block_exception&) {
                throw;
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
            emit(self.applied_transaction, std::tie(trace, trx));
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
                    pending->_block_stage.get<building_block>()._pending_trx_metas.emplace_back(trx);
                }
                else {
                    transaction_receipt_header r;
                    r.status       = transaction_receipt::executed;
                    trace->receipt = r;
                }

                fc::move_append(pending->_block_stage.get<building_block>()._actions, move(trx_context.executed));

                // call the accept signal but only once for this transaction
                if(!trx->accepted) {
                    trx->accepted = true;
                    emit(self.accepted_transaction, trx);
                }

                emit(self.applied_transaction, std::tie(trace, trn));

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
            catch(const disallowed_transaction_extensions_bad_block_exception&) {
                throw;
            }
            catch(const protocol_feature_bad_block_exception&) {
                throw;
            }
            catch(const fc::exception& e) {
                trace->except     = e;
                trace->except_ptr = std::current_exception();
            }
            if(!failure_is_subjective(*trace->except)) {
                unapplied_transactions.erase(trx->signed_id);
            }

            emit(self.accepted_transaction, trx);
            emit(self.applied_transaction, std::tie(trace, trn));

            return trace;
        }
        FC_CAPTURE_AND_RETHROW((trace))
    }  /// push_transaction

    void
    start_block(block_timestamp_type when,
                uint16_t confirm_block_count,
                controller::block_status s,
                const vector<digest_type>& new_protocol_feature_activations,
                const optional<block_id_type>& producer_block_id) {
        EVT_ASSERT(!pending.has_value(), block_validate_exception, "pending block already exists");

        auto guard_pending = fc::make_scoped_exit([this, head_block_num=head->block_num]() {
            protocol_features.popped_blocks_to(head_block_num);
            pending.reset();
        });

        if(!self.skip_db_sessions(s)) {
            EVT_ASSERT(db.revision() == head->block_num, database_exception, "db revision is not on par with head block",
                ("db.revision()", db.revision())("controller_head_block", head->block_num)("fork_db_head_block", fork_db.head()->block_num) );

             pending.emplace(maybe_session(db, token_db), *head, when, confirm_block_count, new_protocol_feature_activations);
        }
        else {
            pending.emplace(maybe_session(), *head, when, confirm_block_count, new_protocol_feature_activations);
        }

        pending->_block_status = s;
        pending->_producer_block_id = producer_block_id;

        auto&       bb   = pending -> _block_stage.get<building_block>();
        const auto& pbhs = bb._pending_block_header_state;

        // modify state of speculative block only if we are in speculative read mode (otherwise we need clean state for head or read-only modes)
        if(read_mode == db_read_mode::SPECULATIVE || pending->_block_status != controller::block_status::incomplete) {
            const auto& pso = db.get<protocol_state_object>();

            auto num_preactivated_protocol_features = pso.preactivated_protocol_features.size();
            bool handled_all_preactivated_features  = (num_preactivated_protocol_features == 0);

            if(new_protocol_feature_activations.size() > 0) {
                flat_map<digest_type, bool> activated_protocol_features;
                activated_protocol_features.reserve(std::max(num_preactivated_protocol_features,
                                                             new_protocol_feature_activations.size()));
                for(const auto& feature_digest : pso.preactivated_protocol_features) {
                    activated_protocol_features.emplace(feature_digest, false);
                }

                size_t num_preactivated_features_that_have_activated = 0;

                const auto& pfs = protocol_features.get_protocol_feature_set();
                for(const auto& feature_digest : new_protocol_feature_activations) {
                    const auto& f = pfs.get_protocol_feature(feature_digest);

                    auto res = activated_protocol_features.emplace(feature_digest, true);
                    if(res.second) {
                        // feature_digest was not preactivated
                        EVT_ASSERT(!f.preactivation_required, protocol_feature_exception,
                                   "attempted to activate protocol feature without prior required preactivation: ${digest}",
                                   ("digest", feature_digest));
                    }
                    else {
                        EVT_ASSERT(!res.first->second, block_validate_exception,
                                   "attempted duplicate activation within a single block: ${digest}",
                                   ("digest", feature_digest));
                        // feature_digest was preactivated
                        res.first->second = true;
                        ++num_preactivated_features_that_have_activated;
                    }

                    if(f.builtin_feature) {
                        trigger_activation_handler(*f.builtin_feature);
                    }

                    protocol_features.activate_feature(feature_digest, pbhs.block_num);

                    ++bb._num_new_protocol_features_that_have_activated;
                }

                if(num_preactivated_features_that_have_activated == num_preactivated_protocol_features) {
                    handled_all_preactivated_features = true;
                }
            }

            EVT_ASSERT(handled_all_preactivated_features, block_validate_exception,
                       "There are pre-activated protocol features that were not activated at the start of this block");

            if(new_protocol_feature_activations.size() > 0) {
                db.modify(pso, [&](auto& ps) {
                    ps.preactivated_protocol_features.clear();

                    ps.activated_protocol_features.reserve(ps.activated_protocol_features.size()
                                                           + new_protocol_feature_activations.size());
                    for(const auto& feature_digest : new_protocol_feature_activations) {
                        ps.activated_protocol_features.emplace_back(feature_digest, pbhs.block_num);
                    }
                });
            }

            const auto& gpo = db.get<global_property_object>();

            if(gpo.proposed_schedule_block_num.valid() &&                                // if there is a proposed schedule that was proposed in a block ...
               (*gpo.proposed_schedule_block_num <= pbhs.dpos_irreversible_blocknum) &&  // ... that has now become irreversible ...
               pbhs.prev_pending_schedule.schedule.producers.size() == 0                 // ... and there was room for a new pending schedule prior to any possible promotion
            ) {
                // Promote proposed schedule to pending schedule.
                if(!replay_head_time) {
                    ilog("promoting proposed schedule (set in block ${proposed_num}) to pending; current block: ${n} lib: ${lib} schedule: ${schedule} ",
                         ("proposed_num", *gpo.proposed_schedule_block_num)("n", pbhs.block_num)("lib", pbhs.dpos_irreversible_blocknum)("schedule", static_cast<producer_schedule_type>(gpo.proposed_schedule)));
                }

                EVT_ASSERT(gpo.proposed_schedule.version == pbhs.active_schedule_version + 1,
                           producer_schedule_exception, "wrong producer schedule version specified");

                pending->_block_stage.get<building_block>()._new_pending_producer_schedule = gpo.proposed_schedule;
                db.modify(gpo, [&](auto& gp) {
                    gp.proposed_schedule_block_num = optional<block_num_type>();
                    gp.proposed_schedule.clear();
                });
            }

            try {
                auto onbtrx                        = std::make_shared<transaction_metadata>(get_on_block_transaction());
                onbtrx->implicit                   = true;
                auto reset_in_trx_requiring_checks = fc::make_scoped_exit([old_value = in_trx_requiring_checks, this]() {
                    in_trx_requiring_checks = old_value;
                });
                in_trx_requiring_checks            = true;
                push_transaction(onbtrx, fc::time_point::maximum(), self.get_global_properties().configuration.min_transaction_cpu_usage, true);
            }
            catch(const boost::interprocess::bad_alloc& e) {
                elog("on block transaction failed due to a bad allocation");
                throw;
            }
            catch(const fc::exception& e) {
                wlog("on block transaction failed, but shouldn't impact block generation, system contract needs update");
                edump((e.to_detail_string()));
            }
            catch(...) {
            }

            clear_expired_input_transactions();
            update_producers_authority();
        }

        guard_pending.cancel();
    }  // start_block


    void
    finalize_block() {
        EVT_ASSERT(pending, block_validate_exception, "it is not valid to finalize when there is no pending block");
        EVT_ASSERT(pending->_block_stage.contains<building_block>(), block_validate_exception, "already called finalize_block");

        try {
            auto& pbhs = pending->get_pending_block_header_state();
            auto& bb   = pending->_block_stage.get<building_block>();

            // Create (unsigned) block:
            auto block_ptr = std::make_shared<signed_block>(pbhs.make_block_header(
                calculate_trx_merkle(),
                calculate_action_merkle(),
                std::move(bb._new_pending_producer_schedule),
                std::move(bb._new_protocol_feature_activations)));

            block_ptr->transactions = std::move(bb._pending_trx_receipts);

            auto id = block_ptr->id();

            // Update TaPoS table:
            create_block_summary(id);

            /*
              ilog( "finalized block ${n} (${id}) at ${t} by ${p} (${signing_key}); schedule_version: ${v} lib: ${lib} #dtrxs: ${ndtrxs} ${np}",
                    ("n",pbhs.block_num)
                    ("id",id)
                    ("t",pbhs.timestamp)
                    ("p",pbhs.producer)
                    ("signing_key", pbhs.block_signing_key)
                    ("v",pbhs.active_schedule_version)
                    ("lib",pbhs.dpos_irreversible_blocknum)
                    ("ndtrxs",db.get_index<generated_transaction_multi_index,by_trx_id>().size())
                    ("np",block_ptr->new_producers)
              );
            */

            pending->_block_stage = assembled_block{
                id,
                std::move(bb._pending_block_header_state),
                std::move(bb._pending_trx_metas),
                std::move(block_ptr)};
        }
        FC_CAPTURE_AND_RETHROW()
    }  /// finalize_block

    /**
     * @post regardless of the success of commit block there is no active pending block
     */
    void
    commit_block(bool add_to_fork_db) {
        auto reset_pending_on_exit = fc::make_scoped_exit([this] {
            pending.reset();
        });

        try {
            EVT_ASSERT(pending->_block_stage.contains<completed_block>(), block_validate_exception,
                       "cannot call commit_block until pending block is completed");

            auto bsp = pending->_block_stage.get<completed_block>()._block_state;

            if(add_to_fork_db) {
                fork_db.add(bsp);
                fork_db.mark_valid(bsp);
                emit(self.accepted_block_header, bsp);
                head = fork_db.head();
                EVT_ASSERT(bsp == head, fork_database_exception, "committed block did not become the new head in fork database");
            }

            if(!replay_head_time && read_mode != db_read_mode::IRREVERSIBLE) {
                reversible_blocks.create<reversible_block_object>([&](auto& ubo) {
                    ubo.blocknum = bsp->block_num;
                    ubo.set_block(bsp->block);
                });
            }

            if(add_to_fork_db) {
                log_irreversible();
            }

            emit(self.accepted_block, bsp);
        }
        catch(...) {
            // dont bother resetting pending, instead abort the block
            reset_pending_on_exit.cancel();
            abort_block();
            throw;
        }

        // push the state for pending.
        pending->push();
    }

    /**
     *  This method is called from other threads. The controller_impl should outlive those threads.
     *  However, to avoid race conditions, it means that the behavior of this function should not change
     *  after controller_impl construction.

     *  This should not be an issue since the purpose of this function is to ensure all of the protocol features
     *  in the supplied vector are recognized by the software, and the set of recognized protocol features is
     *  determined at startup and cannot be changed without a restart.
     */
    void
    check_protocol_features(block_timestamp_type         timestamp,
                            const flat_set<digest_type>& currently_activated_protocol_features,
                            const vector<digest_type>&   new_protocol_features) {
        const auto& pfs = protocol_features.get_protocol_feature_set();

        for(auto itr = new_protocol_features.begin(); itr != new_protocol_features.end(); ++itr) {
            const auto& f = *itr;

            auto status = pfs.is_recognized(f, timestamp);
            switch(status) {
            case protocol_feature_set::recognized_t::unrecognized: {
                EVT_THROW(protocol_feature_exception,
                          "protocol feature with digest '${digest}' is unrecognized", ("digest", f));
                break;
            }
            case protocol_feature_set::recognized_t::disabled: {
                EVT_THROW(protocol_feature_exception,
                          "protocol feature with digest '${digest}' is disabled", ("digest", f));
                break;
            }
            case protocol_feature_set::recognized_t::too_early: {
                EVT_THROW(protocol_feature_exception,
                          "${timestamp} is too early for the earliest allowed activation time of the protocol feature with digest '${digest}'", ("digest", f)("timestamp", timestamp));
                break;
            }
            case protocol_feature_set::recognized_t::ready: {
                break;
            }
            default: {
                EVT_THROW(protocol_feature_exception, "unexpected recognized_t status");
                break;
            }
            }  // switch

            EVT_ASSERT(currently_activated_protocol_features.find(f) == currently_activated_protocol_features.end(),
                       protocol_feature_exception,
                       "protocol feature with digest '${digest}' has already been activated",
                       ("digest", f));

            auto dependency_checker = [&currently_activated_protocol_features, &new_protocol_features, &itr](const digest_type& f) -> bool {
                if(currently_activated_protocol_features.find(f) != currently_activated_protocol_features.end()) {
                    return true;
                }

                return (std::find(new_protocol_features.begin(), itr, f) != itr);
            };

            EVT_ASSERT(pfs.validate_dependencies(f, dependency_checker), protocol_feature_exception,
                       "not all dependencies of protocol feature with digest '${digest}' have been activated",
                       ("digest", f));
        }
    }

    void
    apply_block(const block_state_ptr& bsp, controller::block_status s) {
        try {
            try {
                const signed_block_ptr& b = bsp->block;
                const auto& new_protocol_feature_activations = bsp->get_new_protocol_feature_activations();

                EVT_ASSERT(b->block_extensions.size() == 0, block_validate_exception, "no supported block extensions");
                auto producer_block_id = b->id();
                start_block(b->timestamp, b->confirmed, new_protocol_feature_activations, s, producer_block_id);

                std::vector<transaction_metadata_ptr> packed_transactions;
                packed_transactions.reserve(b->transactions.size());
                for(const auto& receipt : b->transactions) {
                    if(receipt.trx.contains<packed_transaction>()) {
                        auto& pt   = receipt.trx.get<packed_transaction>();
                        auto  mtrx = std::make_shared<transaction_metadata>(std::make_shared<packed_transaction>(pt));
                        if(!self.skip_auth_check()) {
                            transaction_metadata::start_recover_keys(mtrx, thread_pool.get_executor(), chain_id, microseconds::maximum());
                        }
                        packed_transactions.emplace_back(std::move(mtrx));
                    }
                }

                transaction_trace_ptr trace;

                size_t packed_idx = 0;
                for(const auto& receipt : b->transactions) {
                    const auto& trx_receipts         = pending->_block_stage.get<building_block>()._pending_trx_receipts;
                    auto        num_pending_receipts = trx_receipts.size();
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

                    bool transaction_failed   = trace && trace->except;
                    bool transaction_can_fail = receipt.status == transaction_receipt_header::hard_fail && receipt.trx.contains<transaction_id_type>();
                    if(transaction_failed && !transaction_can_fail) {
                        edump((*trace));
                        throw *trace->except;
                    }

                    EVT_ASSERT(trx_receipts.size() > 0,
                               block_validate_exception, "expected a receipt",
                               ("block", *b)("expected_receipt", receipt));
                    EVT_ASSERT(trx_receipts.size() == num_pending_receipts + 1,
                               block_validate_exception, "expected receipt was not added",
                               ("block", *b)("expected_receipt", receipt));
                    const transaction_receipt_header& r = trx_receipts.back();
                    EVT_ASSERT(r == static_cast<const transaction_receipt_header&>(receipt),
                               block_validate_exception, "receipt does not match",
                               ("producer_receipt", receipt)("validator_receipt", trx_receipts.back()));
                }

                finalize_block();

                auto& ab = pending->_block_stage.get<assembled_block>();

                // this implicitly asserts that all header fields (less the signature) are identical
                EVT_ASSERT(producer_block_id == ab._id, block_validate_exception, "Block ID does not match",
                           ("producer_block_id", producer_block_id)("validator_block_id", ab._id));

                auto bsp = std::make_shared<block_state>(
                    std::move(ab._pending_block_header_state),
                    b,
                    std::move(ab._trx_metas),
                    [](block_timestamp_type         timestamp,
                       const flat_set<digest_type>& cur_features,
                       const vector<digest_type>&   new_features) {},  // validation of any new protocol features should have already occurred prior to apply_block
                    true                                             // signature should have already been verified (assuming untrusted) prior to apply_block
                );

                pending->_block_stage = completed_block{bsp};

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

    block_state_ptr
    create_block_state(const signed_block_ptr& b) {
        EVT_ASSERT(b, block_validate_exception, "null block");

        auto id = b->id();

        // no reason for a block_state if fork_db already knows about block
        auto existing = fork_db.get_block(id);
        EVT_ASSERT(!existing, fork_database_exception, "we already know about this block: ${id}", ("id", id));

        auto prev = fork_db.get_block_header(b->previous);
        EVT_ASSERT(prev, unlinkable_block_exception,
                   "unlinkable block ${id}", ("id", id)("previous", b->previous));

        const bool skip_validate_signee = false;
        return std::make_shared<block_state>(
            *prev,
            move(b),
            [control](block_timestamp_type         timestamp,
                      const flat_set<digest_type>& cur_features,
                      const vector<digest_type>&   new_features) { control->check_protocol_features(timestamp, cur_features, new_features); },
            skip_validate_signee);
    }

    void
    push_block(const signed_block_ptr& b) {
        auto s = controller::block_status::complete;
        EVT_ASSERT(!pending.has_value(), block_validate_exception, "it is not valid to push a block when there is a pending block");

        auto reset_prod_light_validation = fc::make_scoped_exit([old_value=trusted_producer_light_validation, this]() {
            trusted_producer_light_validation = old_value;
        });

        try {
            auto bsp = create_block_state(b);
            emit(self.pre_accepted_block, b);

            fork_db.add(bsp);

            if(conf.trusted_producers.count(b->producer)) {
                trusted_producer_light_validation = true;
            };
            emit(self.accepted_block_header, bsp);

            if(read_mode != db_read_mode::IRREVERSIBLE) {
                maybe_switch_forks(fork_db.pending_head(), s);
            }
            else {
                log_irreversible();
            }
        }
        FC_LOG_AND_RETHROW()
    }

    void
    replay_push_block(const signed_block_ptr& b, controller::block_status s) {
        self.validate_db_available_size();
        self.validate_reversible_available_size();

        EVT_ASSERT(!pending, block_validate_exception, "it is not valid to push a block when there is a pending block");

        try {
            EVT_ASSERT(b, block_validate_exception, "trying to push empty block");
            EVT_ASSERT((s == controller::block_status::irreversible || s == controller::block_status::validated),
                       block_validate_exception, "invalid block status for replay");
            emit(self.pre_accepted_block, b);
            const bool skip_validate_signee = !conf.force_all_checks;

            auto bsp = std::make_shared<block_state>(
                *head,
                b,
                [this](block_timestamp_type         timestamp,
                       const flat_set<digest_type>& cur_features,
                       const vector<digest_type>&   new_features) { check_protocol_features(timestamp, cur_features, new_features); },
                skip_validate_signee);

            if(s != controller::block_status::irreversible) {
                fork_db.add(bsp, true);
            }

            emit(self.accepted_block_header, bsp);

            if(s == controller::block_status::irreversible) {
                apply_block(bsp, s);
                head = bsp;

                // On replay, log_irreversible is not called and so no irreversible_block signal is emittted.
                // So emit it explicitly here.
                emit(self.irreversible_block, bsp);

                if(!self.skip_db_sessions(s)) {
                    db.commit(bsp->block_num);
                }
            }
            else {
                EVT_ASSERT(read_mode != db_read_mode::IRREVERSIBLE, block_validate_exception,
                           "invariant failure: cannot replay reversible blocks while in irreversible mode");
                maybe_switch_forks(bsp, s);
            }
        }
        FC_LOG_AND_RETHROW()
    }

    void
    maybe_switch_forks(const block_state_ptr& new_head, controller::block_status s) {
        bool head_changed = true;
        if(new_head->header.previous == head->id) {
            try {
                apply_block(new_head, s);
                fork_db.mark_valid(new_head);
                head = new_head;
            }
            catch(const fc::exception& e) {
                fork_db.remove(new_head->id);
                throw;
            }
        }
        else if(new_head->id != head->id) {
            auto old_head = head;
            ilog("switching forks from ${current_head_id} (block number ${current_head_num}) to ${new_head_id} (block number ${new_head_num})",
                 ("current_head_id", head->id)("current_head_num", head->block_num)("new_head_id", new_head->id)("new_head_num", new_head->block_num));
            auto branches = fork_db.fetch_branch_from(new_head->id, head->id);

            if(branches.second.size() > 0) {
                for(auto itr = branches.second.begin(); itr != branches.second.end(); ++itr) {
                    pop_block();
                }
                EVT_ASSERT(self.head_block_id() == branches.second.back()->header.previous, fork_database_exception,
                           "loss of sync between fork_db and chainbase during fork switch");  // _should_ never fail
            }

            for(auto ritr = branches.first.rbegin(); ritr != branches.first.rend(); ++ritr) {
                optional<fc::exception> except;
                try {
                    apply_block(*ritr, (*ritr)->is_valid() ? controller::block_status::validated
                                                           : controller::block_status::complete);
                    fork_db.mark_valid(*ritr);
                    head = *ritr;
                }
                catch(const fc::exception& e) {
                    except = e;
                }
                if(except) {
                    elog("exception thrown while switching forks ${e}", ("e", except->to_detail_string()));

                    // ritr currently points to the block that threw
                    // Remove the block that threw and all forks built off it.
                    fork_db.remove((*ritr)->id);

                    // pop all blocks from the bad fork
                    // ritr base is a forward itr to the last block successfully applied
                    auto applied_itr = ritr.base();
                    for(auto itr = applied_itr; itr != branches.first.end(); ++itr) {
                        pop_block();
                    }
                    EVT_ASSERT(self.head_block_id() == branches.second.back()->header.previous, fork_database_exception,
                               "loss of sync between fork_db and chainbase during fork switch reversal");  // _should_ never fail

                    // re-apply good blocks
                    for(auto ritr = branches.second.rbegin(); ritr != branches.second.rend(); ++ritr) {
                        apply_block(*ritr, controller::block_status::validated /* we previously validated these blocks*/);
                        head = *ritr;
                    }
                    throw *except;
                }  // end if exception
            }      /// end for each block in branch

            ilog("successfully switched fork to new head ${new_head_id}", ("new_head_id", new_head->id));
        }
        else {
            head_changed = false;
        }

        if(head_changed)
            log_irreversible();
    }  /// push_block

    void
    abort_block() {
        if(pending) {
            if(read_mode == db_read_mode::SPECULATIVE) {
                for(const auto& t : pending->get_trx_metas())
                    unapplied_transactions[t->signed_id] = t;
            }
            pending.reset();
            protocol_features.popped_blocks_to(head->block_num);
        }
    }

    checksum256_type
    calculate_action_merkle() {
        vector<digest_type> action_digests;
        const auto&         actions = pending->_block_stage.get<building_block>()._actions;
        action_digests.reserve(actions.size());
        for(const auto& a : actions) {
            action_digests.emplace_back(a.digest());
        }

        return merkle(move(action_digests));
    }

    checksum256_type
    calculate_trx_merkle() {
        vector<digest_type> trx_digests;
        const auto&         trxs = pending->_block_stage.get<building_block>()._pending_trx_receipts;
        trx_digests.reserve(trxs.size());
        for(const auto& a : trxs) {
            trx_digests.emplace_back(a.digest());
        }

        return merkle(move(trx_digests));
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

    void
    check_and_update_staking_ctx() {
        EVT_ASSERT(pending.has_value(), block_validate_exception, "it is not valid to check and update staking context when there is no pending block");

        const auto& gpo  = db.get<global_property_object>();
        const auto& conf = gpo.staking_configuration;
        const auto& ctx  = gpo.staking_ctx;
        if(pending->_pending_block_state->block_num == ctx.period_start_num + conf.cycles_per_period * conf.blocks_per_cycle) {
            db.modify(gpo, [&](auto& gp) {
                gp.staking_ctx.period_version   = gp.staking_ctx.period_version + 1;
                gp.staking_ctx.period_start_num = pending->_pending_block_state->block_num;
            });
        }
    }

};  /// controller_impl

const protocol_feature_manager&
controller::get_protocol_feature_manager() const {
    return my->protocol_features;
}

controller::controller(const controller::config& cfg)
    : my(new controller_impl(cfg, *this, protocol_feature_set{})) {}

controller::controller(const config& cfg, protocol_feature_set&& pfs)
    : my(new controller_impl(cfg, *this, std::move(pfs))) {}

controller::~controller() {
    my->abort_block();
    /* Shouldn't be needed anymore.
    //close fork_db here, because it can generate "irreversible" signal to this controller,
    //in case if read-mode == IRREVERSIBLE, we will apply latest irreversible block
    //for that we need 'my' to be valid pointer pointing to valid controller_impl.
    my->fork_db.close();
    */
}

void
controller::add_indices() {
    my->add_indices();
}

void
controller::startup(const snapshot_reader_ptr& snapshot) {
    if(snapshot) {
        ilog("Starting initialization from snapshot, this may take a significant amount of time");
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
controller::preactivate_feature(const digest_type& feature_digest) {
    const auto& pfs      = my->protocol_features.get_protocol_feature_set();
    auto        cur_time = pending_block_time();

    auto status = pfs.is_recognized(feature_digest, cur_time);
    switch(status) {
    case protocol_feature_set::recognized_t::unrecognized: {
        if(is_producing_block()) {
            EVT_THROW(subjective_block_production_exception,
                      "protocol feature with digest '${digest}' is unrecognized", ("digest", feature_digest));
        }
        else {
            EVT_THROW(protocol_feature_bad_block_exception,
                      "protocol feature with digest '${digest}' is unrecognized", ("digest", feature_digest));
        }
        break;
    }
    case protocol_feature_set::recognized_t::disabled: {
        if(is_producing_block()) {
            EVT_THROW(subjective_block_production_exception,
                      "protocol feature with digest '${digest}' is disabled", ("digest", feature_digest));
        }
        else {
            EVT_THROW(protocol_feature_bad_block_exception,
                      "protocol feature with digest '${digest}' is disabled", ("digest", feature_digest));
        }
        break;
    }
    case protocol_feature_set::recognized_t::too_early: {
        if(is_producing_block()) {
            EVT_THROW(subjective_block_production_exception,
                      "${timestamp} is too early for the earliest allowed activation time of the protocol feature with digest '${digest}'", ("digest", feature_digest)("timestamp", cur_time));
        }
        else {
            EVT_THROW(protocol_feature_bad_block_exception,
                      "${timestamp} is too early for the earliest allowed activation time of the protocol feature with digest '${digest}'", ("digest", feature_digest)("timestamp", cur_time));
        }
        break;
    }
    case protocol_feature_set::recognized_t::ready: {
        break;
    }
    default: {
        if(is_producing_block()) {
            EVT_THROW(subjective_block_production_exception, "unexpected recognized_t status");
        }
        else {
            EVT_THROW(protocol_feature_bad_block_exception, "unexpected recognized_t status");
        }
        break;
    }
    }  // switch

    // The above failures depend on subjective information.
    // Because of deferred transactions, this complicates things considerably.

    // If producing a block, we throw a subjective failure if the feature is not properly recognized in order
    // to try to avoid retiring into a block a deferred transacton driven by subjective information.

    // But it is still possible for a producer to retire a deferred transaction that deals with this subjective
    // information. If they recognized the feature, they would retire it successfully, but a validator that
    // does not recognize the feature should reject the entire block (not just fail the deferred transaction).
    // Even if they don't recognize the feature, the producer could change their evtd code to treat it like an
    // objective failure thus leading the deferred transaction to retire with soft_fail or hard_fail.
    // In this case, validators that don't recognize the feature would reject the whole block immediately, and
    // validators that do recognize the feature would likely lead to a different retire status which would
    // ultimately cause a validation failure and thus rejection of the block.
    // In either case, it results in rejection of the block which is the desired behavior in this scenario.

    // If the feature is properly recognized by producer and validator, we have dealt with the subjectivity and
    // now only consider the remaining failure modes which are deterministic and objective.
    // Thus the exceptions that can be thrown below can be regular objective exceptions
    // that do not cause immediate rejection of the block.

    EVT_ASSERT(!is_protocol_feature_activated(feature_digest),
               protocol_feature_exception,
               "protocol feature with digest '${digest}' is already activated",
               ("digest", feature_digest));

    const auto& pso = my->db.get<protocol_state_object>();

    EVT_ASSERT(std::find(pso.preactivated_protocol_features.begin(),
                         pso.preactivated_protocol_features.end(),
                         feature_digest)
                   == pso.preactivated_protocol_features.end(),
               protocol_feature_exception,
               "protocol feature with digest '${digest}' is already pre-activated",
               ("digest", feature_digest));

    auto dependency_checker = [&](const digest_type& d) -> bool {
        if(is_protocol_feature_activated(d))
            return true;

        return (std::find(pso.preactivated_protocol_features.begin(),
                          pso.preactivated_protocol_features.end(),
                          d)
                != pso.preactivated_protocol_features.end());
    };

    EVT_ASSERT(pfs.validate_dependencies(feature_digest, dependency_checker),
               protocol_feature_exception,
               "not all dependencies of protocol feature with digest '${digest}' have been activated or pre-activated",
               ("digest", feature_digest));

    my->db.modify(pso, [&](auto& ps) {
        ps.preactivated_protocol_features.push_back(feature_digest);
    });
}

vector<digest_type>
controller::get_preactivated_protocol_features() const {
    const auto& pso = my->db.get<protocol_state_object>();

    if(pso.preactivated_protocol_features.size() == 0) {
        return {};
    }

    vector<digest_type> preactivated_protocol_features;

    for(const auto& f : pso.preactivated_protocol_features) {
        preactivated_protocol_features.emplace_back(f);
    }

    return preactivated_protocol_features;
}

void
controller::validate_protocol_features(const vector<digest_type>& features_to_activate) const {
    my->check_protocol_features(my->head->header.timestamp,
                                my->head->activated_protocol_features->protocol_features,
                                features_to_activate);
}

void
controller::start_block(block_timestamp_type when, uint16_t confirm_block_count) {
    validate_db_available_size();

    EVT_ASSERT(!my->pending, block_validate_exception, "pending block already exists");

    vector<digest_type> new_protocol_feature_activations;

    const auto& pso = my->db.get<protocol_state_object>();
    if(pso.preactivated_protocol_features.size() > 0) {
        for(const auto& f : pso.preactivated_protocol_features) {
            new_protocol_feature_activations.emplace_back(f);
        }
    }

    if(new_protocol_feature_activations.size() > 0) {
        validate_protocol_features(new_protocol_feature_activations);
    }

    my->start_block(when, confirm_block_count, new_protocol_feature_activations,
                    block_status::incomplete, optional<block_id_type>());
}

void
controller::start_block(block_timestamp_type       when,
                        uint16_t                   confirm_block_count,
                        const vector<digest_type>& new_protocol_feature_activations) {
    validate_db_available_size();

    if(new_protocol_feature_activations.size() > 0) {
        validate_protocol_features(new_protocol_feature_activations);
    }

    my->start_block(when, confirm_block_count, new_protocol_feature_activations,
                    block_status::incomplete, optional<block_id_type>());
}

block_state_ptr
controller::finalize_block(const std::function<signature_type(const digest_type&)>& signer_callback) {
    validate_db_available_size();

    my->finalize_block();

    auto& ab = my->pending->_block_stage.get<assembled_block>();

    auto bsp = std::make_shared<block_state>(
        std::move(ab._pending_block_header_state),
        std::move(ab._unsigned_block),
        std::move(ab._trx_metas),
        [](block_timestamp_type         timestamp,
           const flat_set<digest_type>& cur_features,
           const vector<digest_type>&   new_features) {},
        signer_callback);

    my->pending->_block_stage = completed_block{bsp};

    return bsp;
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

uint32_t
controller::fork_db_pending_head_block_num() const {
    return my->fork_db.pending_head()->block_num;
}

block_id_type
controller::fork_db_pending_head_block_id() const {
    return my->fork_db.pending_head()->id;
}

time_point
controller::fork_db_pending_head_block_time() const {
    return my->fork_db.pending_head()->header.timestamp;
}

account_name
controller::fork_db_pending_head_block_producer() const {
    return my->fork_db.pending_head()->header.producer;
}

time_point
controller::pending_block_time() const {
    EVT_ASSERT(my->pending, block_validate_exception, "no pending block");

    if(my->pending->_block_stage.contains<completed_block>()) {
        return my->pending->_block_stage.get<completed_block>()._block_state->header.timestamp;
    }

    return my->pending->get_pending_block_header_state().timestamp;
}

account_name
controller::pending_block_producer() const {
    EVT_ASSERT(my->pending, block_validate_exception, "no pending block");

    if(my->pending->_block_stage.contains<completed_block>()) {
        return my->pending->_block_stage.get<completed_block>()._block_state->header.producer;
    }

    return my->pending->get_pending_block_header_state().producer;
}

public_key_type
controller::pending_block_signing_key() const {
    EVT_ASSERT(my->pending, block_validate_exception, "no pending block");

    if(my->pending->_block_stage.contains<completed_block>()) {
        return my->pending->_block_stage.get<completed_block>()._block_state->block_signing_key;
    }

    return my->pending->get_pending_block_header_state().block_signing_key;
}

optional<block_id_type>
controller::pending_producer_block_id() const {
    EVT_ASSERT(my->pending, block_validate_exception, "no pending block");
    return my->pending->_producer_block_id;
}

const vector<transaction_receipt>&
controller::get_pending_trx_receipts() const {
    EVT_ASSERT(my->pending, block_validate_exception, "no pending block");
    return my->pending->get_trx_receipts();
}

uint32_t
controller::last_irreversible_block_num() const {
    return my->fork_db.root()->block_num;
}

block_id_type
controller::last_irreversible_block_id() const {
    auto        lib_num             = last_irreversible_block_num();
    const auto& tapos_block_summary = db().get<block_summary_object>((uint16_t)lib_num);

    if(block_header::num_from_id(tapos_block_summary.block_id) == lib_num) {
        return tapos_block_summary.block_id;
    }

    auto signed_blk = my->blog.read_block_by_num(lib_num);

    EVT_ASSERT(BOOST_LIKELY(signed_blk != nullptr), unknown_block_exception,
               "Could not find block: ${block}", ("block", lib_num));

    return signed_blk->id();
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
        auto blk_state = fetch_block_state_by_number(block_num);
        if(blk_state) {
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
        const auto& rev_blocks = my->reversible_blocks.get_index<reversible_block_index, by_num>();
        auto        objitr     = rev_blocks.find(block_num);

        if(objitr == rev_blocks.end()) {
            if(my->read_mode == db_read_mode::IRREVERSIBLE) {
                return my->fork_db.search_on_branch(my->fork_db.pending_head()->id, block_num);
            }
            else {
                return block_state_ptr();
            }
        }

        return my->fork_db.get_block(objitr->get_block_id());
    }
    FC_CAPTURE_AND_RETHROW((block_num))
}

block_id_type
controller::get_block_id_for_num(uint32_t block_num) const {
    try {
        const auto& blog_head = my->blog.head();

        bool find_in_blog = (blog_head && block_num <= blog_head->block_num());

        if(!find_in_blog) {
            if(my->read_mode != db_read_mode::IRREVERSIBLE) {
                const auto& rev_blocks = my->reversible_blocks.get_index<reversible_block_index, by_num>();
                auto        objitr     = rev_blocks.find(block_num);
                if(objitr != rev_blocks.end()) {
                    return objitr->get_block_id();
                }
            }
            else {
                auto bsp = my->fork_db.search_on_branch(my->fork_db.pending_head()->id, block_num);
                if(bsp) {
                    return bsp->id;
                }
            }
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

    if(producers.size() == 0 && is_builtin_activated(builtin_protocol_feature_t::disallow_empty_producer_schedule)) {
        return -1;
    }

    if(gpo.proposed_schedule_block_num.has_value()) {
        if(*gpo.proposed_schedule_block_num != cur_block_num) {
            return -1;  // there is already a proposed schedule set in a previous block, wait for it to become pending
        }

        if(std::equal(producers.begin(), producers.end(),
                      gpo.proposed_schedule.producers.begin(), gpo.proposed_schedule.producers.end())) {
            return -1;  // the proposed producer schedule does not change
        }
    }

    producer_schedule_type sch;

    decltype(sch.producers.cend()) end;
    decltype(end)                  begin;

    const auto& pending_sch = pending_producers();

    if(pending_sch.producers.size() == 0) {
        const auto& active_sch = active_producers();
        begin                  = active_sch.producers.begin();
        end                    = active_sch.producers.end();
        sch.version            = active_sch.version + 1;
    }
    else {
        begin       = pending_sch.producers.begin();
        end         = pending_sch.producers.end();
        sch.version = pending_sch.version + 1;
    }

    if(std::equal(producers.begin(), producers.end(), begin, end)) {
        return -1;  // the producer schedule would not change
    }

    sch.producers = std::move(producers);

    auto version = sch.version;

    ilog("proposed producer schedule with version ${v}", ("v", version));
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

void
controller::set_action_versions(vector<action_ver> vers) {
    const auto& gpo = get_global_properties();
    my->db.modify(gpo, [&](auto& gp) {
        gp.action_vers.clear();
        for(auto& av : vers) {
            gp.action_vers.push_back(av);
        }
    });
}

void
controller::set_action_version(name action, int version) {
    const auto& gpo = get_global_properties();
    my->db.modify(gpo, [&](auto& gp) {
        for(auto& av : gp.action_vers) {
            if(av.act == action) {
                av.ver = version;
            }
        }
    });
}

void
controller::set_initial_staking_period() {
    const auto& gpo = get_global_properties();
    my->db.modify(gpo, [&](auto& gp) {
        gp.staking_ctx.period_version   = 1;
        gp.staking_ctx.period_start_num = pending_block_state()->block_num;
    });
}

const producer_schedule_type&
controller::active_producers() const {
    if(!(my->pending)) {
        return my->head->active_schedule;
    }

    if(my->pending->_block_stage.contains<completed_block>()) {
        return my->pending->_block_stage.get<completed_block>()._block_state->active_schedule;
    }

    return my->pending->get_pending_block_header_state().active_schedule;
}

const producer_schedule_type&
controller::pending_producers() const {
    if(!(my->pending)) {
        return my->head->pending_schedule.schedule;
    }

    if(my->pending->_block_stage.contains<completed_block>()) {
        return my->pending->_block_stage.get<completed_block>()._block_state->pending_schedule.schedule;
    }

    if(my->pending->_block_stage.contains<assembled_block>()) {
        const auto& np = my->pending->_block_stage.get<assembled_block>()._unsigned_block->new_producers;
        if(np) {
            return *np;
        }
    }

    const auto& bb = my->pending->_block_stage.get<building_block>();

    if(bb._new_pending_producer_schedule) {
        return *bb._new_pending_producer_schedule;
    }

    return bb._pending_block_header_state.prev_pending_schedule.schedule;
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
controller::is_building_block() const {
    return my->pending.valid();
}

bool
controller::is_producing_block() const {
    if(!my->pending.has_value()) {
        return false;
    }

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
controller::is_protocol_feature_activated(const digest_type& feature_digest) const {
    if(my->pending) {
        return my->pending->is_protocol_feature_activated(feature_digest);
    }

    const auto& activated_features = my->head->activated_protocol_features->protocol_features;
    return (activated_features.find(feature_digest) != activated_features.end());
}

bool
controller::is_builtin_activated(builtin_protocol_feature_t f) const {
    uint32_t current_block_num = head_block_num();

    if(my->pending) {
        ++current_block_num;
    }

    return my->protocol_features.is_builtin_activated(f, current_block_num);
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
