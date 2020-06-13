#define FUSE_DEFAULT_USERKERNEL_BUFSIZE (8192 * 4096)
#define OSXFUSE_DEVICE_BASENAME "tfmfs"
#define OSXFUSE_MOUNT_PROG "" "@loader_path/../.." "/Contents/Resources" "/mount_" "tfmfs" ".app/Contents/MacOS/Mounter"
#define OSXFUSE_NDEVICES 64
#define OSXFUSE_VOLUME_ICON "" "@loader_path/../.." "/Contents/Resources" "/Volume.icns"
