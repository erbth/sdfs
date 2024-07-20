add_executable(sdfs-dd-mgr
	dd_mgr.cc
	dd_mgr_ctx.cc
	../common/utils.cc
	../common/daemon_utils.cc
	../common/exceptions.cc
	../common/epoll.cc
	../common/signalfd.cc
	../common/prot_common.cc
	../common/prot_dd_mgr.cc
)

install(TARGETS sdfs-dd-mgr DESTINATION sbin)
