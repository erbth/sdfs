add_executable(sdfs-ctrl
	ctrl.cc
	ctrl_ctx.cc
	../common/strformat.cc
	../common/utils.cc
	../common/daemon_utils.cc
	../common/exceptions.cc
	../common/signalfd.cc
	../common/epoll.cc
	../common/eventfd.cc
	../common/semaphore.cc
	../common/file_config.cc
	../common/prot_common.cc
	../common/prot_dd_mgr.cc
	../common/prot_dd.cc
)

target_compile_options(sdfs-ctrl PRIVATE -pthread)
target_link_libraries(sdfs-ctrl PRIVATE -pthread)

install(TARGETS sdfs-ctrl DESTINATION sbin)
