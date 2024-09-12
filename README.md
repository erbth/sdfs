# Sequential Data FileSystem (sdfs)

A simple distributed filesystem for sequential data.

It features multipathing and relies on clients to perform asynchronous IO for
high data rates.

But note that the kernel will split large IO requests into up-to 1M chunks (for
files opened with O_DIRECT) and submites these in parallel, hence reading with
e.g. a block size of 32M generates already some parallelism - however this is
not as fast as native asynchronous IO, as the sequence of operations will
contain a synchronization point after each 32M read, followed by a short period
of inactivity while the user submits the next IO request.

libsdfs_ds:  block data storage client library
libsdfs_fs:  filesystem client library; builds on top of libsdfs-ds

sdfs-ds:     Simple block IO client
sdfs-mkfs:   Format a sdfs storage for use as filesystem (or display information
             about it)
sdfs-fuse:   fuse filesystem client

Restrictions:
  * Parallel unaligned writes can overwrite each other (race condition on the
	unaltered bytes)

  * Optimized for sequential reads; writes are (probably) slower

  * The filesystem does not implement locking. Hence parallel writes and reads
	can overlap each other and produce corrupt data, including corrupting the
	filesystem. This means that even parallel asynchronous writes overwrite each
	other's inode changes - hence currupt the filesystem if a file's allocations
	or size is changed. However for writing into an existing file without
	extending its size will only lead to undeterministic mtime overwriting,
	which is not a problem.
