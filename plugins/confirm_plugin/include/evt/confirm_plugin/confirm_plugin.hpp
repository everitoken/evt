/**
 *  @file
 *  @copyright defined in evt/LICENSE.txt
 */
#pragma once
#include <evt/http_plugin/http_plugin.hpp>
#include <evt/chain_plugin/chain_plugin.hpp>
#include <evt/chain/types.hpp>

#include <appbase/application.hpp>

namespace evt {
using evt::chain::transaction_id_type;
using namespace appbase;

class confirm_plugin : public plugin<confirm_plugin> {
public:
    enum class confirm_mode {
        bypass = 0,     // return directly
        relax,
        medium,
        strict
    };

    struct confirm_transaction_params {
        transaction_id_type id;
        block_num_type      block_num;
        confirm_mode        mode;
        uint32_t            rounds;
    };

public:
    APPBASE_PLUGIN_REQUIRES((chain_plugin)(http_plugin))

    confirm_plugin();
    virtual ~confirm_plugin();

    virtual void set_program_options(options_description&, options_description&) override;

    void plugin_initialize(const variables_map&);
    void plugin_startup();
    void plugin_shutdown();

private:
    std::shared_ptr<class confirm_plugin_impl> my_;
};

}  // namespace evt

FC_REFLECT_ENUM(evt::confirm_plugin::confirm_mode, (bypass)(strict)(medium)(relax));
FC_REFLECT(evt::confirm_plugin::confirm_transaction_params, (id)(block_num)(mode)(number));
