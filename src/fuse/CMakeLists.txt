add_executable(sdfs-fuse
	fuse.cc
	fuse_ctx.cc
	com_ctx.cc
	cache.cc
	../common/exceptions.cc
	../common/epoll.cc
	../common/eventfd.cc
	../common/file_config.cc
	../common/prot_common.cc
	../common/prot_client.cc
	../common/utils.cc
)

target_include_directories(sdfs-fuse PRIVATE ${LIBFUSE_INCLUDE_DIRS})
target_link_libraries(sdfs-fuse PRIVATE ${LIBFUSE_LIBRARIES})

install(TARGETS sdfs-fuse DESTINATION bin)
