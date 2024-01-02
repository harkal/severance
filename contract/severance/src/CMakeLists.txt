project(severance)

find_package(cdt)

add_contract( severance severance severance.cpp mimcsponge.cpp verifier.cpp utils.cpp )
target_include_directories( severance PUBLIC ${CMAKE_SOURCE_DIR}/../include )
target_ricardian_directory( severance ${CMAKE_SOURCE_DIR}/../ricardian )