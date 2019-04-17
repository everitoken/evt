#include <evt/testing/tester.hpp>

#include <boost/algorithm/string/predicate.hpp>
#include <boost/test/unit_test.hpp>

#include <evt/chain/token_database.hpp>

using namespace evt::chain::contracts;

namespace evt { namespace testing {

bool
expect_assert_message(const fc::exception& ex, string expected) {
    BOOST_TEST_MESSAGE("LOG : "
                       << "expected: " << expected << ", actual: " << ex.get_log().at(0).get_message());
    return (ex.get_log().at(0).get_message().find(expected) != std::string::npos);
}

fc::variant_object
filter_fields(const fc::variant_object& filter, const fc::variant_object& value) {
    fc::mutable_variant_object res;
    for(auto& entry : filter) {
        auto it = value.find(entry.key());
        res(it->key(), it->value());
    }
    return res;
}

base_tester::base_tester() {}

bool
base_tester::is_same_chain(base_tester& other) {
    return control->head_block_id() == other.control->head_block_id();
}

void
base_tester::init(bool push_genesis) {
    cfg.blocks_dir             = tempdir.path() / config::default_blocks_dir_name;
    cfg.state_dir              = tempdir.path() / config::default_state_dir_name;
    cfg.db_config.db_path      = tempdir.path() / config::default_token_database_dir_name;
    cfg.contracts_console      = true;
    cfg.loadtest_mode          = false;
    cfg.charge_free_mode       = false;
    cfg.max_serialization_time = std::chrono::hours(1);

    cfg.genesis.initial_timestamp = fc::time_point::from_iso_string("2020-01-01T00:00:00.000");
    cfg.genesis.initial_key       = get_public_key("evt");

    open(nullptr);

    if(push_genesis) {
        push_genesis_block();
    }
}

void
base_tester::init(controller::config config, const snapshot_reader_ptr& snapshot) {
    cfg = config;
    open(snapshot);
}

void
base_tester::close() {
    control.reset();
    chain_transactions.clear();
}

void
base_tester::open(const snapshot_reader_ptr& snapshot) {
    control.reset(new controller(cfg));
    control->add_indices();
    control->startup(snapshot);
    chain_transactions.clear();
    control->accepted_block.connect([this](const block_state_ptr& block_state) {
        FC_ASSERT(block_state->block);
        for(const auto& receipt : block_state->block->transactions) {
            chain_transactions[receipt.trx.id()] = transaction_receipt(receipt.trx);
        }
    });
}

signed_block_ptr
base_tester::push_block(signed_block_ptr b) {
    control->abort_block();
    control->push_block(b);

    auto itr = last_produced_block.find(b->producer);
    if(itr == last_produced_block.end() || block_header::num_from_id(b->id()) > block_header::num_from_id(itr->second)) {
        last_produced_block[b->producer] = b->id();
    }

    return b;
}

signed_block_ptr
base_tester::_produce_block(fc::microseconds skip_time, bool skip_pending_trxs, uint32_t skip_flag) {
    auto head      = control->head_block_state();
    auto head_time = control->head_block_time();
    auto next_time = head_time + skip_time;

    if(!control->pending_block_state() || control->pending_block_state()->header.timestamp != next_time) {
        _start_block(next_time);
    }

    auto producer = control->head_block_state()->get_scheduled_producer(next_time);
    auto priv_key = private_key_type();
    // Check if signing private key exist in the list
    auto private_key_itr = block_signing_private_keys.find(producer.block_signing_key);
    if(private_key_itr == block_signing_private_keys.end()) {
        // If it's not found, default to active k1 key
        priv_key = get_private_key((std::string)producer.producer_name);
    }
    else {
        priv_key = private_key_itr->second;
    }
    
    if(!skip_pending_trxs) {
        auto unapplied_trxs = control->get_unapplied_transactions();
        for(const auto& trx : unapplied_trxs) {
            auto trace = control->push_transaction(trx.second, fc::time_point::maximum());
            if(trace->except) {
                trace->except->dynamic_rethrow_exception();
            }
        }
    }

    control->finalize_block();
    control->sign_block([&](digest_type d) {
        return priv_key.sign(d);
    });

    control->commit_block();
    last_produced_block[control->head_block_state()->header.producer] = control->head_block_state()->id;

    _start_block(next_time + fc::microseconds(config::block_interval_us));
    return control->head_block_state()->block;
}

void
base_tester::_start_block(fc::time_point block_time) {
    auto head_block_number = control->head_block_num();
    auto producer          = control->head_block_state()->get_scheduled_producer(block_time);

    auto last_produced_block_num = control->last_irreversible_block_num();
    auto itr                     = last_produced_block.find(producer.producer_name);
    if(itr != last_produced_block.end()) {
        last_produced_block_num = std::max(control->last_irreversible_block_num(), block_header::num_from_id(itr->second));
    }

    control->abort_block();
    control->start_block(block_time, head_block_number - last_produced_block_num);
}

void
base_tester::produce_blocks(uint32_t n, bool empty) {
    if(empty) {
        for(uint32_t i = 0; i < n; ++i)
            produce_empty_block();
    }
    else {
        for(uint32_t i = 0; i < n; ++i)
            produce_block();
    }
}

void
base_tester::produce_blocks_until_end_of_round() {
    uint64_t blocks_per_round;
    while(true) {
        blocks_per_round = control->active_producers().producers.size() * config::producer_repetitions;
        produce_block();
        if(control->head_block_num() % blocks_per_round == (blocks_per_round - 1))
            break;
    }
}

void
base_tester::produce_blocks_for_n_rounds(const uint32_t num_of_rounds) {
    for(uint32_t i = 0; i < num_of_rounds; i++) {
        produce_blocks_until_end_of_round();
    }
}

void
base_tester::produce_min_num_of_blocks_to_spend_time_wo_inactive_prod(const fc::microseconds target_elapsed_time) {
    fc::microseconds elapsed_time;
    while(elapsed_time < target_elapsed_time) {
        for(uint32_t i = 0; i < control->head_block_state()->active_schedule.producers.size(); i++) {
            const auto time_to_skip = fc::milliseconds(config::producer_repetitions * config::block_interval_ms);
            produce_block(time_to_skip);
            elapsed_time += time_to_skip;
        }
        // if it is more than 24 hours, producer will be marked as inactive
        const auto time_to_skip = fc::seconds(23 * 60 * 60);
        produce_block(time_to_skip);
        elapsed_time += time_to_skip;
    }
}

void
base_tester::set_transaction_headers(signed_transaction& trx, const address& payer, uint32_t max_charge, uint32_t expiration) const {
    trx.expiration = control->head_block_time() + fc::seconds(expiration);
    trx.payer      = payer;
    trx.max_charge = max_charge;
    trx.set_reference_block(control->head_block_id());
}

transaction_trace_ptr
base_tester::push_transaction(packed_transaction& trx,
                              fc::time_point      deadline) {
    try {
        if(!control->pending_block_state()) {
            _start_block(control->head_block_time() + fc::microseconds(config::block_interval_us));
        }
        auto mtrx = std::make_shared<transaction_metadata>(std::make_shared<packed_transaction>(trx));
        auto r    = control->push_transaction(mtrx, deadline);

        if(r->except_ptr) {
            std::rethrow_exception(r->except_ptr);
        }
        if(r->except) {
            throw *r->except;
        }
        return r;
    }
    FC_CAPTURE_AND_RETHROW((transaction_header(trx.get_transaction())))
}

transaction_trace_ptr
base_tester::push_transaction(signed_transaction& trx,
                              fc::time_point      deadline) {
    try {
        if(!control->pending_block_state()) {
            _start_block(control->head_block_time() + fc::microseconds(config::block_interval_us));
        }
        auto c = packed_transaction::none;

        if(fc::raw::pack_size(trx) > 1000) {
            c = packed_transaction::zlib;
        }

        auto mtrx = std::make_shared<transaction_metadata>(trx, c);
        auto r    = control->push_transaction(mtrx, deadline);
        
        if(r->except_ptr) {
            std::rethrow_exception(r->except_ptr);
        }
        if(r->except) {
            throw *r->except;
        }
        return r;
    }
    FC_CAPTURE_AND_RETHROW((transaction_header(trx)))
}

transaction_trace_ptr
base_tester::push_action(action&& act, const std::vector<name>& auths, const address& payer, uint32_t max_charge) {
    try {
        signed_transaction trx;
        trx.actions.emplace_back(std::move(act));
        set_transaction_headers(trx, payer, max_charge);
        if(!auths.empty()) {
            for(auto& au : auths) {
                trx.sign(get_private_key(au), control->get_chain_id());
            }
        }
        return push_transaction(trx);
    }
    FC_CAPTURE_AND_RETHROW((act)(auths)(payer)(max_charge))
}

transaction_trace_ptr
base_tester::push_action(const action_name&       acttype,
                         const domain_name&       domain,
                         const domain_key&        key,
                         const variant_object&    data,
                         const std::vector<name>& auths,
                         const address&           payer,
                         uint32_t                 max_charge,
                         uint32_t                 expiration)
{
    try {
        auto trx = signed_transaction();
        trx.actions.emplace_back(get_action(acttype, domain, key, data));
        set_transaction_headers(trx, payer, max_charge, expiration);
        for(const auto& auth : auths) {
            trx.sign(get_private_key(auth), control->get_chain_id());
        }

        return push_transaction(trx);
    }
    FC_CAPTURE_AND_RETHROW((acttype)(domain)(key)(data)(auths)(payer)(max_charge)(expiration))
}

action
base_tester::get_action(action_name acttype, const domain_name& domain, const domain_key& key, const variant_object& data) const {
    try {
        auto& abi      = control->get_abi_serializer();
        auto& exec_ctx = control->get_execution_context();
        auto  type     = exec_ctx.get_acttype_name(acttype);
        FC_ASSERT(!type.empty(), "unknown action type ${a}", ("a", acttype));

        action act;
        act.name   = acttype;
        act.domain = domain;
        act.key    = key;
        act.data   = abi.variant_to_binary(type, data, exec_ctx);
        
        return act;
    }
    FC_CAPTURE_AND_RETHROW()
}

bool
base_tester::chain_has_transaction(const transaction_id_type& txid) const {
    return chain_transactions.count(txid) != 0;
}

const transaction_receipt&
base_tester::get_transaction_receipt(const transaction_id_type& txid) const {
    return chain_transactions.at(txid);
}

vector<uint8_t>
base_tester::to_uint8_vector(const string& s) {
    vector<uint8_t> v(s.size());
    copy(s.begin(), s.end(), v.begin());
    return v;
};

vector<uint8_t>
base_tester::to_uint8_vector(uint64_t x) {
    vector<uint8_t> v(sizeof(x));
    *reinterpret_cast<uint64_t*>(v.data()) = x;
    return v;
};

uint64_t
base_tester::to_uint64(fc::variant x) {
    vector<uint8_t> blob;
    fc::from_variant<uint8_t>(x, blob);
    FC_ASSERT(8 == blob.size());
    return *reinterpret_cast<uint64_t*>(blob.data());
}

string
base_tester::to_string(fc::variant x) {
    vector<uint8_t> v;
    fc::from_variant<uint8_t>(x, v);
    string s(v.size(), 0);
    copy(v.begin(), v.end(), s.begin());
    return s;
}

void
base_tester::sync_with(base_tester& other) {
    // Already in sync?
    if(control->head_block_id() == other.control->head_block_id())
        return;
    // If other has a longer chain than we do, sync it to us first
    if(control->head_block_num() < other.control->head_block_num())
        return other.sync_with(*this);

    auto sync_dbs = [](base_tester& a, base_tester& b) {
        for(auto i = 1u; i <= a.control->head_block_num(); ++i) {
            auto block = a.control->fetch_block_by_number(i);
            if(block) {  //&& !b.control->is_known_block(block->id()) ) {
                b.control->abort_block();
                b.control->push_block(block);  //, evt::chain::validation_steps::created_block);
            }
        }
    };

    sync_dbs(*this, other);
    sync_dbs(other, *this);
}

void
base_tester::push_genesis_block() {
    //produce_block();
}

void
base_tester::add_money(const address& addr, const asset& number) {
    auto& tokendb = control->token_db();

    auto s = tokendb.new_savepoint_session();

    auto str  = std::string();
    auto prop = property();
    prop.sym  = number.sym();
    
    if(tokendb.read_asset(addr, number.symbol_id(), str, true)) {
        extract_db_value(str, prop);
    }

    prop.amount += number.amount();

    auto dv = make_db_value(prop);
    tokendb.put_asset(addr, number.symbol_id(), dv.as_string_view());

    s.accept();
    tokendb.pop_back_savepoint();
}

bool
fc_exception_message_is::operator()(const fc::exception& ex) {
    auto message = ex.get_log().at(0).get_message();
    bool match   = (message == expected);
    if(!match) {
        BOOST_TEST_MESSAGE("LOG: expected: " << expected << ", actual: " << message);
    }
    return match;
}

bool
fc_exception_message_starts_with::operator()(const fc::exception& ex) {
    auto message = ex.get_log().at(0).get_message();
    bool match   = boost::algorithm::starts_with(message, expected);
    if(!match) {
        BOOST_TEST_MESSAGE("LOG: expected: " << expected << ", actual: " << message);
    }
    return match;
}

bool
fc_assert_exception_message_is::operator()(const fc::assert_exception& ex) {
    auto message = ex.get_log().at(0).get_message();
    bool match   = false;
    auto pos     = message.find(": ");
    if(pos != std::string::npos) {
        message = message.substr(pos + 2);
        match   = (message == expected);
    }
    if(!match) {
        BOOST_TEST_MESSAGE("LOG: expected: " << expected << ", actual: " << message);
    }
    return match;
}

bool
fc_assert_exception_message_starts_with::operator()(const fc::assert_exception& ex) {
    auto message = ex.get_log().at(0).get_message();
    bool match   = false;
    auto pos     = message.find(": ");
    if(pos != std::string::npos) {
        message = message.substr(pos + 2);
        match   = boost::algorithm::starts_with(message, expected);
    }
    if(!match) {
        BOOST_TEST_MESSAGE("LOG: expected: " << expected << ", actual: " << message);
    }
    return match;
}

}}  // namespace evt::testing

std::ostream&
operator<<(std::ostream& osm, const fc::variant& v) {
    //fc::json::to_stream( osm, v );
    osm << fc::json::to_pretty_string(v);
    return osm;
}

std::ostream&
operator<<(std::ostream& osm, const fc::variant_object& v) {
    osm << fc::variant(v);
    return osm;
}

std::ostream&
operator<<(std::ostream& osm, const fc::variant_object::entry& e) {
    osm << "{ " << e.key() << ": " << e.value() << " }";
    return osm;
}
