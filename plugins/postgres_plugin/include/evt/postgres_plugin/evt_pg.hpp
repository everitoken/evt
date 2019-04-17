/**
 *  @file
 *  @copyright defined in evt/LICENSE.txt
 */
#pragma once
#include <functional>
#include <istream>
#include <ostream>
#include <string>
#include <string_view>
#include <boost/noncopyable.hpp>
#include <evt/chain/block_state.hpp>
#include <evt/chain/execution_context.hpp>
#include <evt/chain/transaction.hpp>
#include <evt/chain/contracts/types.hpp>

struct pg_conn;

namespace evt {
namespace chain {
class snapshot_writer;
class snapshot_reader;

namespace contracts {
struct abi_serializer;
}  // namespace contracts
}  // namespace chain

using namespace evt::chain::contracts;

#define PG_OK   1
#define PG_FAIL 0

using action_t     = chain::action;
using act_trace_t  = chain::action_trace;
using abi_t        = chain::contracts::abi_serializer;
using exec_ctx_t   = chain::execution_context;
using block_ptr    = chain::block_state_ptr;
using chain_id_t   = chain::chain_id_type;
using trx_recept_t = chain::transaction_receipt;
using trx_t        = chain::signed_transaction;
using ft_holders_t = chain::small_vector_base<chain::ft_holder>;

struct copy_context;
struct trx_context;

struct add_context : boost::noncopyable {
public:
    add_context(copy_context& cctx, const chain_id_t& chain_id, const abi_t& abi, const exec_ctx_t& exec_ctx)
        : cctx(cctx), chain_id(chain_id), abi(abi), exec_ctx(exec_ctx) {}

public:
    copy_context&     cctx;
    std::string_view  block_id;
    int               block_num;
    std::string       ts;
    const chain_id_t& chain_id;
    const abi_t&      abi;
    const exec_ctx_t& exec_ctx;
};

class pg : boost::noncopyable {
public:
    pg() : conn_(nullptr), prepared_stmts_(0) {}

public:
    int connect(const std::string& conn);
    int close();

public:
    int init_pathman();
    int create_partitions(const std::string& table, uint interval, uint part_nums);
    int drop_partitions(const std::string& table);

public:
    int create_db(const std::string& db);
    int drop_db(const std::string& db);
    int exists_db(const std::string& db);
    int is_table_empty(const std::string& table);
    int drop_table(const std::string& table);
    int drop_sequence(const std::string& seq);
    int drop_all_tables();
    int drop_all_sequences();
    int prepare_tables();
    int prepare_stmts();
    int prepare_stats();

public:
    int backup(const std::shared_ptr<chain::snapshot_writer>& snapshot) const;
    int restore(const std::shared_ptr<chain::snapshot_reader>& snapshot);

public:
    int check_version();
    int check_last_sync_block();

    void set_last_sync_block_id(const std::string& id) { last_sync_block_id_ = id; }
    std::string last_sync_block_id() const { return last_sync_block_id_; }

public:
    copy_context new_copy_context();
    void commit_copy_context(copy_context&);

    trx_context new_trx_context();
    void commit_trx_context(trx_context&);

public:
    static int add_block(add_context&, const block_ptr);
    static int add_trx(add_context&, const trx_recept_t&, const trx_t&, int seq_num, int elapsed, int charge);
    static int add_action(add_context&, const act_trace_t&, const std::string& trx_id, int seq_num);
    
    int get_latest_block_id(std::string& block_id) const;
    int set_block_irreversible(trx_context&, const std::string& block_id);
    int exists_block(const std::string& block_id) const;

    int add_stat(trx_context&, const std::string& key, const std::string& value);
    int upd_stat(trx_context&, const std::string& key, const std::string& value);
    int read_stat(const std::string& key, std::string& value) const;

    int add_domain(trx_context&, const newdomain&);
    int upd_domain(trx_context&, const updatedomain&);

    int add_tokens(trx_context&, const issuetoken&);
    int upd_token(trx_context&, const transfer&);
    int del_token(trx_context&, const destroytoken&);

    int add_group(trx_context&, const newgroup&);
    int upd_group(trx_context&, const updategroup&);

    int add_fungible(trx_context&, const fungible_def&);
    int upd_fungible(trx_context&, const updfungible&);
    int upd_fungible(trx_context&, const updfungible_v2&);

    int add_meta(trx_context&, const action_t&);

    int add_ft_holders(trx_context&, const ft_holders_t&);

private:
    int block_copy_to(const std::string& table, const std::string& data);

private:
    pg_conn*    conn_;
    std::string last_sync_block_id_;
    int         prepared_stmts_;
};

}  // namespace evt
