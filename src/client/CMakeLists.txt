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


# Filesystem client library
add_library(sdfs_fs SHARED
	sdfs_fs_wrapper.cc
	sdfs_fs.cc
	fs_utils.cc
	../common/utils.cc
	../common/exceptions.cc
)

target_include_directories(sdfs_fs PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_compile_options(sdfs_fs PRIVATE -pthread -fvisibility=hidden)
target_link_options(sdfs_fs PRIVATE -Wl,--no-undefined)
target_link_libraries(sdfs_fs PRIVATE -pthread sdfs_ds)

set_target_properties(sdfs_fs PROPERTIES
	VERSION "${SDFS_VERSION_MAJOR}.${SDFS_VERSION_MINOR}.${SDFS_VERSION_PATCH}"
	SOVERSION "${SDFS_VERSION_MAJOR}.${SDFS_VERSION_MINOR}"
	PUBLIC_HEADER "${CMAKE_CURRENT_SOURCE_DIR}/include/sdfs_fs.h")


# FUSE client for the filesystem
add_executable(sdfs-fuse
	sdfs_fuse
	../common/exceptions.cc
	../common/file_config.cc
)

target_link_libraries(sdfs-fuse PRIVATE "${LIBFUSE_LIBRARIES}" sdfs_fs)
target_include_directories(sdfs-fuse PRIVATE
	"${LIBFUSE_INCLUDE_DIRS}"
	"${CMAKE_CURRENT_SOURCE_DIR}/include")


# Utility programs for the filesystem
add_executable(sdfs-mkfs
	sdfs_mkfs.cc
	fs_utils.cc
	../common/utils.cc
	../common/exceptions.cc
	../common/file_config.cc
	../common/strformat.cc
)

target_link_libraries(sdfs-mkfs PRIVATE "${LIBFUSE_LIBRARIES}" sdfs_ds)
target_include_directories(sdfs-mkfs PRIVATE
	"${LIBFUSE_INCLUDE_DIRS}"
	"${CMAKE_CURRENT_SOURCE_DIR}/include")


# Install targets
install(
	TARGETS sdfs_ds sdfs-ds sdfs_fs sdfs-fuse sdfs-mkfs
	RUNTIME DESTINATION bin
	LIBRARY DESTINATION lib
	PUBLIC_HEADER DESTINATION include)
