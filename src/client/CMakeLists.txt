# Block data storage client library
add_library(sdfs_ds SHARED
	sdfs_ds_wrapper.cc
	sdfs_ds.cc
	../common/utils.cc
	../common/exceptions.cc
	../common/epoll.cc
	../common/eventfd.cc
)

target_include_directories(sdfs_ds PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_compile_options(sdfs_ds PRIVATE -pthread -fvisibility=hidden)
target_link_options(sdfs_ds PRIVATE -Wl,--no-undefined)
target_link_libraries(sdfs_ds PRIVATE -pthread)

set_target_properties(sdfs_ds PROPERTIES
	VERSION "${SDFS_VERSION_MAJOR}.${SDFS_VERSION_MINOR}.${SDFS_VERSION_PATCH}"
	SOVERSION "${SDFS_VERSION_MAJOR}.${SDFS_VERSION_MINOR}"
	PUBLIC_HEADER "${CMAKE_CURRENT_SOURCE_DIR}/include/sdfs_ds.h")


# Utility programs for the block data storage
add_executable(sdfs-ds
	sdfs_ds_tool.cc
	../common/exceptions.cc
	../common/file_config.cc
	../common/utils.cc
	../common/strformat.cc
)

target_link_libraries(sdfs-ds PRIVATE sdfs_ds)
target_include_directories(sdfs-ds PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/include")


# Install targets
install(
	TARGETS sdfs_ds sdfs-ds
	RUNTIME DESTINATION bin
	LIBRARY DESTINATION lib
	PUBLIC_HEADER DESTINATION include)
