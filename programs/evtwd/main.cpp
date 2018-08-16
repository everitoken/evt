/**
 *  @file
 *  @copyright defined in evt/LICENSE.txt
 */
#include <appbase/application.hpp>

#include <evt/http_plugin/http_plugin.hpp>
#include <evt/wallet_api_plugin/wallet_api_plugin.hpp>
#include <evt/wallet_plugin/wallet_plugin.hpp>

#include <fc/exception/exception.hpp>
#include <fc/log/logger_config.hpp>

#include <boost/exception/diagnostic_information.hpp>

#include <pwd.h>

using namespace appbase;
using namespace evt;

bfs::path
determine_home_directory() {
    bfs::path      home;
    struct passwd* pwd = getpwuid(getuid());
    if(pwd) {
        home = pwd->pw_dir;
    }
    else {
        home = getenv("HOME");
    }
    if(home.empty())
        home = "./";
    return home;
}

int
main(int argc, char** argv) {
    try {
        app().init();
        
        bfs::path home = determine_home_directory();
        app().set_default_data_dir(home / "evt-wallet");
        app().set_default_config_dir(home / "evt-wallet");
        app().register_plugin<wallet_api_plugin>();
        if(!app().initialize<wallet_plugin, wallet_api_plugin, http_plugin>(argc, argv))
            return -1;
        auto& http = app().get_plugin<http_plugin>();
        http.add_handler("/v1/evtwd/stop", [](string, string, url_response_callback cb) { cb(200, "{}"); std::raise(SIGTERM); });
        app().startup();
        app().exec();
    }
    catch(const fc::exception& e) {
        elog("${e}", ("e", e.to_detail_string()));
    }
    catch(const boost::exception& e) {
        elog("${e}", ("e", boost::diagnostic_information(e)));
    }
    catch(const std::exception& e) {
        elog("${e}", ("e", e.what()));
    }
    catch(...) {
        elog("unknown exception");
    }
    return 0;
}
