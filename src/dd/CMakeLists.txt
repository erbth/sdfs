add_executable(sdfs-dd
	dd.cc
	dd_ctx.cc
	utils.cc
	../common/utils.cc
	../common/daemon_utils.cc
	../common/exceptions.cc
	../common/io_uring.cc
	../common/epoll.cc
	../common/signalfd.cc
	../common/strformat.cc
	../common/prot_common.cc
	../common/prot_dd_mgr.cc
	../common/prot_dd.cc
)

add_executable(sdfs-mkdd
	mkdd.cc
	utils.cc
	../common/utils.cc
	../common/exceptions.cc
	../common/strformat.cc
)

add_executable(sdfs-ddinfo
	ddinfo.cc
	utils.cc
	../common/utils.cc
	../common/exceptions.cc
	../common/strformat.cc
)

install(TARGETS sdfs-dd sdfs-mkdd sdfs-ddinfo DESTINATION sbin)
