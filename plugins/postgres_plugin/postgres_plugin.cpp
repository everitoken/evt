/**
 *  @file
 *  @copyright defined in evt/LICENSE.txt
 */
#include <evt/postgres_plugin/postgres_plugin.hpp>

#include <functional>
#include <queue>
#include <optional>
#include <tuple>
#include <thread>

#if __has_include(<condition>)
#include <condition>
using std::condition_variable_any;
#else
#include <boost/thread/condition.hpp>
using boost::condition_variable_any;
#endif

#include <fc/io/json.hpp>
#include <fc/variant.hpp>
#include <fc/time.hpp>
#include <fmt/format.h>

#include <evt/chain/config.hpp>
#include <evt/chain/controller.hpp>
#include <evt/chain/exceptions.hpp>
#include <evt/chain/execution_context.hpp>
#include <evt/chain/execution_context_impl.hpp>
#include <evt/chain/genesis_state.hpp>
#include <evt/chain/plugin_interface.hpp>
#include <evt/chain/snapshot.hpp>
#include <evt/chain/transaction.hpp>
#include <evt/chain/types.hpp>
#include <evt/chain/token_database.hpp>
#include <evt/chain/token_database_cache.hpp>
#include <evt/chain/contracts/abi_serializer.hpp>
#include <evt/chain/contracts/evt_contract_abi.hpp>
#include <evt/utilities/spinlock.hpp>

#include <evt/postgres_plugin/evt_pg.hpp>
#include <evt/postgres_plugin/copy_context.hpp>
#include <evt/postgres_plugin/trx_context.hpp>

namespace evt {

using namespace chain;
using namespace chain::contracts;
using namespace chain::plugin_interface;

using evt::utilities::spinlock;
using evt::utilities::spinlock_guard;

static appbase::abstract_plugin& _postgres_plugin = app().register_plugin<postgres_plugin>();

class postgres_plugin_impl {
private:
    using inblock_ptr = std::tuple<block_state_ptr, bool>; // true for irreversible block

public:
    postgres_plugin_impl(const controller& control)
        : control_(control)
        , exec_ctx_(dynamic_cast<const evt_execution_context&>(control.get_execution_context())) {}
    ~postgres_plugin_impl();

public:
    void consume_queues();

    void applied_block(const block_state_ptr&);
    void applied_irreversible_block(const block_state_ptr&);
    void applied_transaction(const transaction_trace_ptr&);

    void process_block(const block_state_ptr, std::deque<transaction_trace_ptr>& traces, copy_context& cctx, trx_context& tctx);
    void _process_block(const block_state_ptr, std::deque<transaction_trace_ptr>& traces, copy_context& cctx, trx_context& tctx);
    void process_irreversible_block(const block_state_ptr, std::deque<transaction_trace_ptr>& traces, copy_context& cctx, trx_context& tctx);
    
    void process_action(const action&, trx_context& tctx);

    void verify_last_block(const std::string& prev_block_id);
    void verify_no_blocks();

    void init(bool init_db);
    void wipe_database();

public:
    pg          db_;
    std::string connstr_;

    const controller&            control_;
    const evt_execution_context& exec_ctx_;

    bool     configured_          = false;
    uint32_t last_sync_block_num_ = 0;
    uint32_t part_limit_ = 0, part_num_ = 0;

    size_t processed_  = 0;
    size_t queue_size_ = 0;

    std::deque<inblock_ptr>           block_state_queue_;
    std::deque<transaction_trace_ptr> transaction_trace_queue_;

    spinlock                    lock_;
    condition_variable_any      cond_;
    std::thread                 consume_thread_;
    std::atomic_bool            done_ = false;

    std::optional<boost::signals2::scoped_connection> accepted_block_connection_;
    std::optional<boost::signals2::scoped_connection> irreversible_block_connection_;
    std::optional<boost::signals2::scoped_connection> applied_transaction_connection_;
};

namespace __internal {

template <typename Q, typename V>
inline void
queueb(Q& bqueue, V&& v, spinlock& lock, condition_variable_any& cv, size_t queue_size) {
    lock.lock();

    auto sleep_time = 0ul;

    while(bqueue.size() > queue_size) {
        lock.unlock();
        cv.notify_one();

        sleep_time += 100;
        std::this_thread::sleep_for(std::chrono::milliseconds(sleep_time));

        lock.lock();
    }
    bqueue.emplace_back(std::forward<V>(v));
    lock.unlock();
    cv.notify_one();
}

template <typename Q, typename V>
inline void
queuet(Q& tqueue, V&& v, spinlock& lock, condition_variable_any& cv) {
    lock.lock();
    tqueue.emplace_back(std::forward<V>(v));
    lock.unlock();
    cv.notify_one();
}

}  // namespace __internal

void
postgres_plugin_impl::applied_irreversible_block(const block_state_ptr& bsp) {
    evt::__internal::queueb(block_state_queue_, std::make_tuple(bsp, true), lock_, cond_, queue_size_);
}

void
postgres_plugin_impl::applied_block(const block_state_ptr& bsp) {
    evt::__internal::queueb(block_state_queue_, std::make_tuple(bsp, false), lock_, cond_, queue_size_);
}

void
postgres_plugin_impl::applied_transaction(const transaction_trace_ptr& ttp) {
    if(!ttp->receipt.has_value() || (ttp->receipt->status != transaction_receipt_header::executed &&
        ttp->receipt->status != transaction_receipt_header::soft_fail)) {
        return;
    }
    evt::__internal::queuet(transaction_trace_queue_, ttp, lock_, cond_);
}

void
postgres_plugin_impl::consume_queues() {
    using namespace evt::__internal;

    try {
        while(true) {
            lock_.lock();
            while(block_state_queue_.empty() && !done_) {
                cond_.wait(lock_);
            }

            auto bqueue = std::move(block_state_queue_);
            auto traces = std::move(transaction_trace_queue_);

            lock_.unlock();

            const int BlockPtr       = 0;
            const int IsIrreversible = 1;

            // warn if queue size greater than 75%
            if(bqueue.size() > (queue_size_ * 0.75)) {
                wlog("queue size: ${q}, head block num: ${b}", ("q", fmt::format("{:n}",bqueue.size()))("b",fmt::format("{:n}",std::get<BlockPtr>(bqueue.front())->block_num)));
            }
            else if(done_) {
                ilog("draining queue, size: ${q}", ("q", fmt::format("{:n}",bqueue.size())));
                break;
            }

            auto cctx = db_.new_copy_context();
            auto tctx = db_.new_trx_context();
            auto back = std::get<BlockPtr>(bqueue.back()); 
            // process block states
            while(true) {
                if(bqueue.empty()) {
                    break;
                }

                auto& b = bqueue.front();
                if(std::get<IsIrreversible>(b)) {
                    process_irreversible_block(std::get<BlockPtr>(b), traces, cctx, tctx);
                }
                else {
                    process_block(std::get<BlockPtr>(b), traces, cctx, tctx);
                }

                bqueue.pop_front();
            }
            // update last sync block in postgres
            db_.upd_stat(tctx, "last_sync_block_id", back->id.str());

            cctx.commit();
            tctx.commit();

            if(!traces.empty()) {
                spinlock_guard lock(lock_);
                transaction_trace_queue_.insert(transaction_trace_queue_.begin(), traces.begin(), traces.end());
            }
        }
        ilog("postgres_plugin consume thread shutdown gracefully");
    }
    catch(fc::exception& e) {
        elog("FC Exception while consuming block ${e}", ("e", e.to_string()));
    }
    catch(std::exception& e) {
        elog("STD Exception while consuming block ${e}", ("e", e.what()));
    }
    catch(...) {
        elog("Unknown exception while consuming block");
    }
}

void
postgres_plugin_impl::verify_last_block(const std::string& prev_block_id) {
    auto last_block_id = std::string();
    if(!db_.get_latest_block_id(last_block_id)) {
        EVT_THROW(postgres_plugin_exception, "No blocks found in database");
    }

    EVT_ASSERT(prev_block_id == last_block_id, postgres_plugin_exception,
        "Did not find expected block ${pid}, instead found ${id}", ("pid", prev_block_id)("id", last_block_id));
}

void
postgres_plugin_impl::verify_no_blocks() {
    if(!db_.is_table_empty("blocks")) {
        EVT_THROW(postgres_plugin_exception, "Existing blocks found in database");
    }
}

void
postgres_plugin_impl::process_irreversible_block(const block_state_ptr block, std::deque<transaction_trace_ptr>& traces, copy_context& cctx, trx_context& tctx) {
    try {
        if(block->block_num == 1) {
            // genesis block will not trigger on_block event
            // add it manually
            _process_block(block, traces, cctx, tctx);
        }
        db_.set_block_irreversible(tctx, block->id.str());
    }
    catch(fc::exception& e) {
        elog("Exception while processing irreversible block ${e}", ("e", e.to_string()));
    }
    catch(std::exception& e) {
        elog("Exception while processing irreversible block ${e}", ("e", e.what()));
    }
    catch(...) {
        elog("Unknown exception while processing irreversible block");
    }
}

void
postgres_plugin_impl::process_block(const block_state_ptr block, std::deque<transaction_trace_ptr>& traces, copy_context& cctx, trx_context& tctx) {
    try {
        _process_block(block, traces, cctx, tctx);
    }
    catch(postgres_sync_exception&) {
        throw;
    }
    catch(fc::exception& e) {
        elog("Exception while processing block ${e}", ("e", e.to_string()));
    }
    catch(std::exception& e) {
        elog("Exception while processing block ${e}", ("e", e.what()));
    }
    catch(...) {
        elog("Unknown exception while processing block");
    }
}

#define case_act(act_name, func_name)                        \
    case N(act_name): {                                      \
        db_.func_name(tctx, act.data_as<const act_name&>()); \
        break;                                               \
    }

#define READ_DB_TOKEN(TYPE, PREFIX, KEY, VPTR, EXCEPTION, FORMAT, ...) \
    try {                                                              \
        using vtype = typename decltype(VPTR)::element_type;           \
        VPTR = cache.template read_token<vtype>(TYPE, PREFIX, KEY);    \
    }                                                                  \
    catch(token_database_exception&) {                                 \
        EVT_THROW2(EXCEPTION, FORMAT, __VA_ARGS__);                    \
    }

void
postgres_plugin_impl::process_action(const action& act, trx_context& tctx) {
    switch((uint64_t)act.name) {
    case_act(newdomain,    add_domain);
    case_act(updatedomain, upd_domain);
    case_act(issuetoken,   add_tokens);
    case_act(transfer,     upd_token);
    case_act(destroytoken, del_token);
    case_act(newgroup,     add_group);
    case_act(updategroup,  upd_group);
    case N(newfungible): {
        exec_ctx_.invoke_action<newfungible>(act, [&](const auto& nf) {
            auto& cache = control_.token_db_cache();
            auto  ft    = make_empty_cache_ptr<fungible_def>();
            READ_DB_TOKEN(token_type::fungible, std::nullopt, nf.sym.id(), ft, unknown_fungible_exception,
                "Cannot find FT with sym id: {}", nf.sym.id());

            db_.add_fungible(tctx, *ft); 
        });
        break;
    }
    case N(updfungible): {
        auto ver = exec_ctx_.get_current_version(N(updfungible));
        if(ver == 1) {
            db_.upd_fungible(tctx, act.data_as<updfungible>());
        }
        else if(ver == 2) {
            db_.upd_fungible(tctx, act.data_as<updfungible_v2>());
        }
        break;
    }
    case N(addmeta): {
        db_.add_meta(tctx, act);
        break;
    }
    case N(everipass): {
        exec_ctx_.invoke_action<everipass>(act, [&](const auto& ep) {
            auto  link  = ep.link;
            auto  flags = link.get_header();
            auto& d     = *link.get_segment(evt_link::domain).strv;
            auto& t     = *link.get_segment(evt_link::token).strv;

            if(flags & evt_link::destroy) {
                auto dt   = destroytoken();
                dt.domain = d;
                dt.name   = t;

                db_.del_token(tctx, dt);
            }
        });
        break;
    }
    }; // switch
}

void
postgres_plugin_impl::_process_block(const block_state_ptr block, std::deque<transaction_trace_ptr>& traces, copy_context& cctx, trx_context& tctx) {
    using namespace evt::__internal;

    auto id = block->id.str();
    if(block->block_num <= last_sync_block_num_) {
        EVT_ASSERT(db_.exists_block(id), postgres_sync_exception,
            "Block is not existed in postgres database, please use --clear-postgres option to clear states");
        return;
    }

    if(processed_ == 0) {
        if(block->block_num <= 2) {
            // verify on start we have no previous blocks
            verify_no_blocks();
        }
        else {
            // verify on restart we have previous block
            verify_last_block(block->header.previous.str());
        }
    }

    auto actx      = add_context(cctx, control_.get_chain_id(), control_.get_abi_serializer(), control_.get_execution_context());
    actx.block_id  = id;
    actx.block_num = (int)block->block_num;
    actx.ts        = (std::string)block->header.timestamp.to_time_point();

    db_.add_block(actx, block);

    // transactions
    auto trx_num = 0;
    for(const auto& trx : block->block->transactions) {
        auto& strx       = trx.trx.get_signed_transaction();
        auto  trx_id     = strx.id();
        auto  str_trx_id = strx.id().str();
        auto  elapsed    = 0;
        auto  charge     = 0;

        if(trx.status == transaction_receipt_header::executed && !strx.actions.empty()) {
            auto it = traces.begin();
            while(it != traces.end()) {
                auto trace = *it;
                traces.pop_front();

                if(trace->id == trx_id) {
                    elapsed = (int)trace->elapsed.count();
                    charge  = (int)trace->charge;

                    if(trace->action_traces.empty()) {
                        break;
                    }

                    tctx.set_trx_id(str_trx_id);

                    auto act_num = 0;
                    for(auto& act_trace : trace->action_traces) {
                        db_.add_action(actx, act_trace, str_trx_id, act_num);
                        process_action(act_trace.act, tctx);
                        if(!act_trace.new_ft_holders.empty()) {
                            db_.add_ft_holders(tctx, act_trace.new_ft_holders);
                        }
                        act_num++;
                    }
                    break;
                }
                it++;
            }
        }

        db_.add_trx(actx, trx, strx, trx_num, elapsed, charge);
        ++trx_num;
    }

    ++processed_;
}

void
postgres_plugin_impl::wipe_database() {
    ilog("wipe database");
    db_.drop_all_tables();
    db_.drop_all_sequences();
}

void
postgres_plugin_impl::init(bool init_db) {
    if(!init_db) {
        try {
            db_.prepare_stmts();
            db_.check_version();
            db_.check_last_sync_block();

            last_sync_block_num_ = block_header::num_from_id(block_id_type(db_.last_sync_block_id()));
        }
        EVT_RETHROW_EXCEPTIONS(evt::postgres_plugin_exception,
            "Check integrity of postgres database failed, please use --clear-postgres to clear database");
    }

    auto& chain_plug = app().get_plugin<chain_plugin>();
    auto& chain      = chain_plug.chain();

    accepted_block_connection_.emplace(chain.accepted_block.connect([&](const chain::block_state_ptr& bs) {
        applied_block(bs);
    }));

    irreversible_block_connection_.emplace(chain.irreversible_block.connect([&](const chain::block_state_ptr& bs) {
        applied_irreversible_block(bs);
    }));

    applied_transaction_connection_.emplace(chain.applied_transaction.connect([&](const chain::transaction_trace_ptr& t) {
        applied_transaction(t);
    }));

    if(init_db) {
        db_.init_pathman();

        db_.prepare_tables();
        db_.prepare_stmts();
        db_.prepare_stats();
        
        if(part_limit_ != 0) {
            db_.create_partitions("public.blocks", part_limit_, part_num_);
            db_.create_partitions("public.transactions", part_limit_, part_num_);
        }

        // HACK: Add EVT and PEVT manually
        auto tctx = db_.new_trx_context();

        auto gs = chain::genesis_state();
        db_.add_fungible(tctx, gs.evt);
        db_.add_fungible(tctx, gs.pevt);

        auto ng  = newgroup();
        ng.name  = N128(.everiToken);
        ng.group = gs.evt_org;
        db_.add_group(tctx, ng);

        tctx.commit();
    }
}

postgres_plugin_impl::~postgres_plugin_impl() {
    if(!configured_) {
        return;
    }
    try {
        done_ = true;
        cond_.notify_one();

        consume_thread_.join();
        db_.close();
    }
    catch(std::exception& e) {
        elog("Exception on postgres_plugin shutdown of consume thread: ${e}", ("e", e.what()));
    }
}

postgres_plugin::postgres_plugin() {}

postgres_plugin::~postgres_plugin() {}

bool
postgres_plugin::enabled() const {
    return my_->configured_;
}

const std::string&
postgres_plugin::connstr() const {
    return my_->connstr_;
}

void
postgres_plugin::read_from_snapshot(const std::shared_ptr<chain::snapshot_reader>& snapshot) {
    my_->db_.restore(snapshot);
}

void
postgres_plugin::write_snapshot(const std::shared_ptr<chain::snapshot_writer>& snapshot) const {
    my_->db_.backup(snapshot);
}

void
postgres_plugin::set_program_options(options_description& cli, options_description& cfg) {
    cfg.add_options()
        ("postgres-queue-size,q", bpo::value<uint>()->default_value(5120), "The queue size between evtd and postgres plugin thread.")
        ("postgres-uri,p", bpo::value<std::string>(), 
            "PostgreSQL connection string, see: https://www.postgresql.org/docs/11/libpq-connect.html#LIBPQ-CONNSTRING for more detail.")
        ("clear-postgres", bpo::bool_switch()->default_value(false), "clear postgres database, use --delete-all-blocks option will force set this option")
        ("postgres-partition-limit", bpo::value<uint>()->default_value(30000000), "The partition limit")
        ("postgres-partition-num", bpo::value<uint>()->default_value(10), "The number of partitions")
        ;
}

void
postgres_plugin::plugin_initialize(const variables_map& options) {
    my_ = std::make_unique<postgres_plugin_impl>(app().get_plugin<chain_plugin>().chain());

    if(options.count("postgres-uri")) {
        ilog("initializing postgres_plugin");
        my_->configured_ = true;

        bool delete_state = false;
        if(options.at("delete-all-blocks").as<bool>()) {
            ilog("Deleted all blocks: wiping postgres database on startup");
            delete_state = true;
        }
        if(options.at("clear-postgres").as<bool>()) {
            if(options.at("replay-blockchain").as<bool>() || options.at("hard-replay-blockchain").as<bool>()) {
                ilog("Replay requested: wiping postgres database on startup");
                delete_state = true;
            }
            EVT_ASSERT(delete_state, postgres_plugin_exception,
                "--clear-postgres option should be used with --(hard-)replay-blockchain");
        }

        if(options.count("postgres-partition-limit")) {
            my_->part_limit_ = options.at("postgres-partition-limit").as<uint>();
            if(my_->part_limit_ == 0) {
                ilog("Partitions will not be created");
            }
        }

        if(options.count("postgres-partition-num")) {
            my_->part_num_ = options.at("postgres-partition-num").as<uint>();
        }

        if(options.count("postgres-queue-size")) {
            my_->queue_size_ = options.at("postgres-queue-size").as<uint>();
        }

        auto uri = options.at("postgres-uri").as<std::string>();
        ilog("connecting to ${u}", ("u", uri));
        
        my_->db_.connect(uri);
        my_->connstr_ = uri;

        if(delete_state) {
            my_->wipe_database();
        }

        if(options.count("snapshot")) {
            auto snapshot_path = options.at("snapshot").as<bfs::path>();
            EVT_ASSERT(fc::exists(snapshot_path), plugin_config_exception,
                       "Cannot load snapshot, ${name} does not exist", ("name", snapshot_path.generic_string()));

            // recover genesis information from the snapshot
            auto infile = std::ifstream(snapshot_path.generic_string(), (std::ios::in | std::ios::binary));
            auto reader = std::make_shared<istream_snapshot_reader>(infile);
            reader->validate();

            if(reader->has_section("pg-blocks")) {
                EVT_ASSERT(delete_state, postgres_plugin_exception, "Snapshot can only be used to initialize an empty database, please use --delete-all-blcoks or --clear-postgres option.");
                my_->db_.restore(reader);
                delete_state = false;
            }
            else {
                wlog("Snapshot don't have postgres data, don't restore postgres");
            }

            infile.close();
        }

        my_->init(delete_state);

        my_->consume_thread_ = std::thread([this] { my_->consume_queues(); });
    }
    else {
        wlog("evt::postgres_plugin configured, but no --postgres-uri specified.");
        wlog("postgres_plugin disabled.");
    }
}

void
postgres_plugin::plugin_startup() {}

void
postgres_plugin::plugin_shutdown() {
    my_->accepted_block_connection_.reset();
    my_->irreversible_block_connection_.reset();
    my_->applied_transaction_connection_.reset();
    my_.reset();
}

}  // namespace evt
