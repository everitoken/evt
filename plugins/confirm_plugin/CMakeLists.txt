file(GLOB HEADERS "include/evt/confirm_plugin/*.hpp")
add_library( confirm_plugin
             confirm_plugin.cpp
             ${HEADERS} )

target_link_libraries( confirm_plugin chain_plugin http_plugin evt_chain appbase )
target_include_directories( confirm_plugin PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include" )
