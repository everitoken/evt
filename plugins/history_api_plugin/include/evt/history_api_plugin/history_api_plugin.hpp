/**
 *  @file
 *  @copyright defined in evt/LICENSE.txt
 */
#pragma once
#include <evt/history_plugin/history_plugin.hpp>
#include <evt/http_plugin/http_plugin.hpp>

#include <appbase/application.hpp>
#include <evt/chain/controller.hpp>

namespace evt {
using evt::chain::controller;
using std::unique_ptr;
using namespace appbase;

class history_api_plugin : public plugin<history_api_plugin> {
public:
    APPBASE_PLUGIN_REQUIRES((chain_plugin)(http_plugin)(history_plugin))

    history_api_plugin();
    virtual ~history_api_plugin();

    virtual void set_program_options(options_description&, options_description&) override;

    void plugin_initialize(const variables_map&);
    void plugin_startup();
    void plugin_shutdown();

private:
    unique_ptr<class history_api_plugin_impl> my;
};

}  // namespace evt
