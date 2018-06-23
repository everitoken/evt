/**
 *  @file
 *  @copyright defined in evt/LICENSE.txt
 */
#include <boost/foreach.hpp>
#include <evt/chain/exceptions.hpp>
#include <evt/chain/token_database.hpp>
#include <fc/filesystem.hpp>
#include <fc/io/datastream.hpp>
#include <fc/io/raw.hpp>
#include <rocksdb/db.h>
#include <rocksdb/merge_operator.h>
#include <rocksdb/slice_transform.h>
#include <rocksdb/table.h>

namespace evt { namespace chain {

using namespace evt::chain;

namespace __internal {

template <typename T, int N = sizeof(T)>
struct db_key {
    db_key(const char* prefix, const T& t)
        : prefix(prefix)
        , slice((const char*)this, 16 + N) {
        static_assert(sizeof(name128) == 16, "Not valid prefix size");
        memcpy(data, &t, N);
    }

    db_key(name128 prefix, const T& t)
        : prefix(prefix)
        , slice((const char*)this, 16 + N) {
        memcpy(data, &t, N);
    }

    const rocksdb::Slice&
    as_slice() const {
        return slice;
    }

    name128 prefix;
    char    data[N];

    rocksdb::Slice slice;
};

db_key<domain_name>
get_domain_key(const domain_name& name) {
    return db_key<domain_name>("domain", name);
}

db_key<token_name>
get_token_key(const domain_name& domain, const token_name& name) {
    return db_key<token_name>(domain, name);
}

db_key<group_name>
get_group_key(const group_name& name) {
    return db_key<group_name>("group", name);
}

db_key<account_name>
get_account_key(const account_name& account) {
    return db_key<account_name>("account", account);
}

db_key<proposal_name>
get_delay_key(const proposal_name& delay) {
    return db_key<proposal_name>("delay", delay);
}

template <typename T>
std::string
get_value(const T& v) {
    std::string value;
    auto        size = fc::raw::pack_size(v);
    value.resize(size);
    auto ds = fc::datastream<char*>((char*)value.data(), size);
    fc::raw::pack(ds, v);
    return value;
}

template <typename T, typename V>
T
read_value(const V& value) {
    T    v;
    auto ds = fc::datastream<const char*>(value.data(), value.size());
    fc::raw::unpack(ds, v);
    return v;
}

enum dbaction_type {
    none = 0,
    kNewDomain,
    kIssueToken,
    kAddGroup,
    kNewAccount,
    kUpdateDomain,
    kUpdateGroup,
    kUpdateToken,
    kUpdateAccount,
    kNewDelay,
    kUpdateDelay
};

struct sp_newdomain {
    domain_name name;
};

struct sp_issuetoken {
    domain_name domain;
    size_t      size;
    token_name  names[0];
};

struct sp_addgroup {
    group_name name;
};

struct sp_newaccount {
    account_name name;
};

struct sp_updatedomain {
    domain_name name;
};

struct sp_updategroup {
    group_name name;
};

struct sp_updatetoken {
    domain_name domain;
    token_name  name;
};

struct sp_updateaccount {
    account_name name;
};

struct sp_newdelay {
    proposal_name name;
};

struct sp_updatedelay {
    proposal_name name;
};

}  // namespace __internal

token_database::token_database(const fc::path& dbpath)
    : db_(nullptr) {
    initialize(dbpath);
}

token_database::~token_database() {
    if(db_ != nullptr) {
        delete db_;
        db_ = nullptr;
    }
}

int
token_database::initialize(const fc::path& dbpath) {
    using namespace rocksdb;
    using namespace __internal;

    assert(db_ == nullptr);
    Options options;
    options.create_if_missing      = true;
    options.compression            = CompressionType::kLZ4Compression;
    options.bottommost_compression = CompressionType::kZSTD;
    options.table_factory.reset(NewPlainTableFactory());
    options.prefix_extractor.reset(NewFixedPrefixTransform(sizeof(uint128_t)));

    if(!fc::exists(dbpath)) {
        fc::create_directories(dbpath);
    }

    auto native_path = dbpath.to_native_ansi_path();
    auto status = DB::Open(options, native_path, &db_);
    if(!status.ok()) {
        EVT_THROW(tokendb_rocksdb_fail, "Rocksdb internal error: ${err}", ("err", status.getState()));
    }

    return 0;
}

int
token_database::add_domain(const domain_def& domain) {
    using namespace __internal;
    if(exists_domain(domain.name)) {
        EVT_THROW(tokendb_domain_existed, "Domain is already existed: ${name}", ("name", (std::string)domain.name));
    }
    auto key    = get_domain_key(domain.name);
    auto value  = get_value(domain);
    auto status = db_->Put(write_opts_, key.as_slice(), value);
    if(!status.ok()) {
        EVT_THROW(tokendb_rocksdb_fail, "Rocksdb internal error: ${err}", ("err", status.getState()));
    }
    if(should_record()) {
        auto act  = (sp_newdomain*)malloc(sizeof(sp_newdomain));
        act->name = domain.name;
        record(kNewDomain, act);
    }
    return 0;
}

int
token_database::exists_domain(const domain_name& name) const {
    using namespace __internal;
    auto        key = get_domain_key(name);
    std::string value;
    auto        status = db_->Get(read_opts_, key.as_slice(), &value);
    return status.ok();
}

int
token_database::issue_tokens(const issuetoken& issue) {
    using namespace __internal;
    if(!exists_domain(issue.domain)) {
        EVT_THROW(tokendb_domain_not_found, "Cannot find domain: ${name}", ("name", (std::string)issue.domain));
    }
    rocksdb::WriteBatch batch;
    for(auto name : issue.names) {
        auto key   = get_token_key(issue.domain, name);
        auto value = get_value(token_def(issue.domain, name, issue.owner));
        batch.Put(key.as_slice(), value);
    }
    auto status = db_->Write(write_opts_, &batch);
    if(!status.ok()) {
        EVT_THROW(tokendb_rocksdb_fail, "Rocksdb internal error: ${err}", ("err", status.getState()));
    }
    if(should_record()) {
        auto act    = (sp_issuetoken*)malloc(sizeof(sp_issuetoken) + sizeof(token_name) * issue.names.size());
        act->domain = issue.domain;
        act->size   = issue.names.size();
        memcpy(act->names, &issue.names[0], sizeof(token_name) * act->size);
        record(kIssueToken, act);
    }
    return 0;
}

int
token_database::exists_token(const domain_name& domain, const token_name& name) const {
    using namespace __internal;
    auto        key = get_token_key(domain, name);
    std::string value;
    auto        status = db_->Get(read_opts_, key.as_slice(), &value);
    return status.ok();
}

int
token_database::add_group(const group_def& group) {
    using namespace __internal;
    if(exists_group(group.name())) {
        EVT_THROW(tokendb_group_existed, "Group is already existed: ${name}", ("name", group.name()));
    }
    auto key    = get_group_key(group.name());
    auto value  = get_value(group);
    auto status = db_->Put(write_opts_, key.as_slice(), value);
    if(!status.ok()) {
        EVT_THROW(tokendb_rocksdb_fail, "Rocksdb internal error: ${err}", ("err", status.getState()));
    }
    if(should_record()) {
        auto act  = (sp_addgroup*)malloc(sizeof(sp_addgroup));
        act->name = group.name();
        record(kAddGroup, act);
    }
    return 0;
}

int
token_database::exists_group(const group_name& name) const {
    using namespace __internal;
    auto        key = get_group_key(name);
    std::string value;
    auto        status = db_->Get(read_opts_, key.as_slice(), &value);
    return status.ok();
}

int
token_database::add_account(const account_def& account) {
    using namespace __internal;
    if(exists_account(account.name)) {
        EVT_THROW(tokendb_account_existed, "Account is already existed: ${name}", ("name", (std::string)account.name));
    }
    auto key    = get_account_key(account.name);
    auto value  = get_value(account);
    auto status = db_->Put(write_opts_, key.as_slice(), value);
    if(!status.ok()) {
        EVT_THROW(tokendb_rocksdb_fail, "Rocksdb internal error: ${err}", ("err", status.getState()));
    }
    if(should_record()) {
        auto act  = (sp_newaccount*)malloc(sizeof(sp_newaccount));
        act->name = account.name;
        record(kNewAccount, act);
    }
    return 0;
}

int
token_database::exists_account(const account_name& name) const {
    using namespace __internal;
    auto        key = get_account_key(name);
    std::string value;
    auto        status = db_->Get(read_opts_, key.as_slice(), &value);
    return status.ok();
}

int
token_database::add_delay(const delay_def& delay) {
    using namespace __internal;
    if(exists_delay(delay.name)) {
        EVT_THROW(tokendb_delay_existed, "Delay is already existed: ${name}", ("name", (std::string)delay.name));
    }
    auto key    = get_delay_key(delay.name);
    auto value  = get_value(delay);
    auto status = db_->Put(write_opts_, key.as_slice(), value);
    if(!status.ok()) {
        EVT_THROW(tokendb_rocksdb_fail, "Rocksdb internal error: ${err}", ("err", status.getState()));
    }
    if(should_record()) {
        auto act  = (sp_newdelay*)malloc(sizeof(sp_newdelay));
        act->name = delay.name;
        record(kNewDelay, act);
    }
    return 0;
}

int
token_database::exists_delay(const proposal_name& name) const {
    using namespace __internal;
    auto        key = get_delay_key(name);
    std::string value;
    auto        status = db_->Get(read_opts_, key.as_slice(), &value);
    return status.ok();
}

int
token_database::read_domain(const domain_name& name, domain_def& domain) const {
    using namespace __internal;
    std::string value;
    auto        key    = get_domain_key(name);
    auto        status = db_->Get(read_opts_, key.as_slice(), &value);
    if(!status.ok()) {
        EVT_THROW(tokendb_domain_not_found, "Cannot find domain: ${name}", ("name", (std::string)name));
    }
    domain = read_value<domain_def>(value);
    return 0;
}

int
token_database::read_token(const domain_name& domain, const token_name& name, token_def& token) const {
    using namespace __internal;
    std::string value;
    auto        key    = get_token_key(domain, name);
    auto        status = db_->Get(read_opts_, key.as_slice(), &value);
    if(!status.ok()) {
        EVT_THROW(tokendb_token_not_found, "Cannot find token: ${domain}-${name}",
                  ("domain", (std::string)domain)("name", (std::string)name));
    }
    token = read_value<token_def>(value);
    return 0;
}

int
token_database::read_group(const group_name& id, group_def& group) const {
    using namespace __internal;
    std::string value;
    auto        key    = get_group_key(id);
    auto        status = db_->Get(read_opts_, key.as_slice(), &value);
    if(!status.ok()) {
        EVT_THROW(tokendb_group_not_found, "Cannot find group: ${id}", ("id", id));
    }
    group = read_value<group_def>(value);
    return 0;
}

int
token_database::read_account(const account_name& name, account_def& account) const {
    using namespace __internal;
    std::string value;
    auto        key    = get_account_key(name);
    auto        status = db_->Get(read_opts_, key.as_slice(), &value);
    if(!status.ok()) {
        EVT_THROW(tokendb_account_not_found, "Cannot find account: ${name}", ("name", (std::string)name));
    }
    account = read_value<account_def>(value);
    return 0;
}

int
token_database::read_delay(const proposal_name& name, delay_def& delay) const {
    using namespace __internal;
    std::string value;
    auto        key    = get_delay_key(name);
    auto        status = db_->Get(read_opts_, key.as_slice(), &value);
    if(!status.ok()) {
        EVT_THROW(tokendb_delay_not_found, "Cannot find delay: ${name}", ("name", (std::string)name));
    }
    delay = read_value<delay_def>(value);
    return 0;
}

int
token_database::update_domain(const domain_def& domain) {
    using namespace __internal;
    auto key    = get_domain_key(domain.name);
    auto value  = get_value(domain);
    auto status = db_->Put(write_opts_, key.as_slice(), value);
    if(!status.ok()) {
        EVT_THROW(tokendb_rocksdb_fail, "Rocksdb internal error: ${err}", ("err", status.getState()));
    }
    if(should_record()) {
        auto act  = (sp_updatedomain*)malloc(sizeof(sp_updatedomain));
        act->name = domain.name;
        record(kUpdateDomain, act);
    }
    return 0;
}

int
token_database::update_group(const group& group) {
    using namespace __internal;
    auto key    = get_group_key(group.name());
    auto value  = get_value(group);
    auto status = db_->Put(write_opts_, key.as_slice(), value);
    if(!status.ok()) {
        EVT_THROW(tokendb_rocksdb_fail, "Rocksdb internal error: ${err}", ("err", status.getState()));
    }
    if(should_record()) {
        auto act  = (sp_updategroup*)malloc(sizeof(sp_updategroup));
        act->name = group.name();
        record(kUpdateGroup, act);
    }
    return 0;
}

int
token_database::update_token(const token_def& token) {
    using namespace __internal;
    auto key    = get_token_key(token.domain, token.name);
    auto value  = get_value(token);
    auto status = db_->Put(write_opts_, key.as_slice(), value);
    if(!status.ok()) {
        EVT_THROW(tokendb_rocksdb_fail, "Rocksdb internal error: ${err}", ("err", status.getState()));
    }
    if(should_record()) {
        auto act    = (sp_updatetoken*)malloc(sizeof(sp_updatetoken));
        act->domain = token.domain;
        act->name   = token.name;
        record(kUpdateToken, act);
    }
    return 0;
}

int
token_database::update_account(const account_def& account) {
    using namespace __internal;
    auto key    = get_account_key(account.name);
    auto value  = get_value(account);
    auto status = db_->Put(write_opts_, key.as_slice(), value);
    if(!status.ok()) {
        EVT_THROW(tokendb_rocksdb_fail, "Rocksdb internal error: ${err}", ("err", status.getState()));
    }
    if(should_record()) {
        auto act  = (sp_updateaccount*)malloc(sizeof(sp_updateaccount));
        act->name = account.name;
        record(kUpdateAccount, act);
    }
    return 0;
}

int
token_database::update_delay(const delay_def& delay) {
    using namespace __internal;
    auto key    = get_delay_key(delay.name);
    auto value  = get_value(delay);
    auto status = db_->Put(write_opts_, key.as_slice(), value);
    if(!status.ok()) {
        EVT_THROW(tokendb_rocksdb_fail, "Rocksdb internal error: ${err}", ("err", status.getState()));
    }
    if(should_record()) {
        auto act  = (sp_updatedelay*)malloc(sizeof(sp_updatedelay));
        act->name = delay.name;
        record(kUpdateDelay, act);
    }
    return 0;
}

int
token_database::record(int type, void* data) {
    if(!should_record()) {
        return 0;
    }
    savepoints_.back().actions.emplace_back(dbaction{.type = type, .data = data});
    return 0;
}

token_database::session
token_database::new_savepoint_session(int seq) {
    add_savepoint(seq);
    return session(*this, seq);
}

int
token_database::add_savepoint(int32_t seq) {
    if(!savepoints_.empty()) {
        if(savepoints_.back().seq >= seq) {
            EVT_THROW(tokendb_seq_not_valid, "Seq is not valid, prev: ${prev}, curr: ${curr}",
                      ("prev", savepoints_.back().seq)("curr", seq));
        }
    }
    savepoints_.emplace_back(savepoint{.seq = seq, .rb_snapshot = (const void*)db_->GetSnapshot(), .actions = {}});
    return 0;
}

int
token_database::free_savepoint(savepoint& cp) {
    for(auto& act : cp.actions) {
        free(act.data);
    }
    db_->ReleaseSnapshot((const rocksdb::Snapshot*)cp.rb_snapshot);
    return 0;
}

int
token_database::pop_savepoints(int32_t until) {
    if(savepoints_.empty()) {
        EVT_THROW(tokendb_no_savepoint, "There's no savepoints anymore");
    }
    while(!savepoints_.empty() && savepoints_.front().seq < until) {
        auto it = std::move(savepoints_.front());
        savepoints_.pop_front();
        free_savepoint(it);
    }
    return 0;
}

int
token_database::rollback_to_latest_savepoint() {
    using namespace __internal;

    if(savepoints_.empty()) {
        EVT_THROW(tokendb_no_savepoint, "There's no savepoints anymore");
    }
    auto& cp = savepoints_.back();
    if(cp.actions.size() > 0) {
        auto snapshot_read_opts_     = read_opts_;
        snapshot_read_opts_.snapshot = (const rocksdb::Snapshot*)cp.rb_snapshot;
        rocksdb::WriteBatch batch;
        for(auto it = --cp.actions.end(); it >= cp.actions.begin(); it--) {
            switch(it->type) {
            case kNewDomain: {
                auto act = (sp_newdomain*)it->data;
                auto key = get_domain_key(act->name);
                batch.Delete(key.as_slice());
                break;
            }
            case kIssueToken: {
                auto act = (sp_issuetoken*)it->data;
                for(size_t i = 0; i < act->size; i++) {
                    auto key = get_token_key(act->domain, act->names[i]);
                    batch.Delete(key.as_slice());
                }
                break;
            }
            case kAddGroup: {
                auto act = (sp_addgroup*)it->data;
                auto key = get_group_key(act->name);
                batch.Delete(key.as_slice());
                break;
            }
            case kNewAccount: {
                auto act = (sp_newaccount*)it->data;
                auto key = get_account_key(act->name);
                batch.Delete(key.as_slice());
                break;
            }
            case kUpdateDomain: {
                auto        act = (sp_updatedomain*)it->data;
                auto        key = get_domain_key(act->name);
                std::string old_value;
                auto        status = db_->Get(snapshot_read_opts_, key.as_slice(), &old_value);
                if(!status.ok()) {
                    // key may not existed in latest snapshot, remove it
                    FC_ASSERT(status.code() == rocksdb::Status::kNotFound, "Not expected rocksdb code: ${status}",
                              ("status", status.getState()));
                    batch.Delete(key.as_slice());
                    break;
                }
                batch.Put(key.as_slice(), old_value);
                break;
            }
            case kUpdateGroup: {
                auto        act = (sp_updategroup*)it->data;
                auto        key = get_group_key(act->name);
                std::string old_value;
                auto        status = db_->Get(snapshot_read_opts_, key.as_slice(), &old_value);
                if(!status.ok()) {
                    // key may not existed in latest snapshot, remove it
                    FC_ASSERT(status.code() == rocksdb::Status::kNotFound, "Not expected rocksdb code: ${status}",
                              ("status", status.getState()));
                    batch.Delete(key.as_slice());
                    break;
                }
                batch.Put(key.as_slice(), old_value);
                break;
            }
            case kUpdateToken: {
                auto        act = (sp_updatetoken*)it->data;
                auto        key = get_token_key(act->domain, act->name);
                std::string old_value;
                auto        status = db_->Get(snapshot_read_opts_, key.as_slice(), &old_value);
                if(!status.ok()) {
                    // key may not existed in latest snapshot, remove it
                    FC_ASSERT(status.code() == rocksdb::Status::kNotFound, "Not expected rocksdb code: ${status}",
                              ("status", status.getState()));
                    batch.Delete(key.as_slice());
                    break;
                }
                batch.Put(key.as_slice(), old_value);
                break;
            }
            case kUpdateAccount: {
                auto        act = (sp_updateaccount*)it->data;
                auto        key = get_account_key(act->name);
                std::string old_value;
                auto        status = db_->Get(snapshot_read_opts_, key.as_slice(), &old_value);
                if(!status.ok()) {
                    // key may not existed in latest snapshot, remove it
                    FC_ASSERT(status.code() == rocksdb::Status::kNotFound, "Not expected rocksdb code: ${status}",
                              ("status", status.getState()));
                    batch.Delete(key.as_slice());
                    break;
                }
                batch.Put(key.as_slice(), old_value);
                break;
            }
            case kUpdateDelay: {
                auto        act = (sp_updatedelay*)it->data;
                auto        key = get_delay_key(act->name);
                std::string old_value;
                auto        status = db_->Get(snapshot_read_opts_, key.as_slice(), &old_value);
                if(!status.ok()) {
                    // key may not existed in latest snapshot, remove it
                    FC_ASSERT(status.code() == rocksdb::Status::kNotFound, "Not expected rocksdb code: ${status}",
                              ("status", status.getState()));
                    batch.Delete(key.as_slice());
                    break;
                }
                batch.Put(key.as_slice(), old_value);
                break;
            }
            default: {
                FC_ASSERT(false, "Unexpected action type: ${type}", ("type", it->type));
                break;
            }
            }  // switch
            free(it->data);
        }  // for
        auto sync_write_opts = write_opts_;
        sync_write_opts.sync = true;
        db_->Write(sync_write_opts, &batch);
    }  // if

    db_->ReleaseSnapshot((const rocksdb::Snapshot*)cp.rb_snapshot);
    savepoints_.pop_back();
    return 0;
}

}}  // namespace evt::chain
