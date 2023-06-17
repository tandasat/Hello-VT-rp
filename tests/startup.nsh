# Switch to the disk with snapshot, patch and corpus files. fs0:, in this example.
fs0:

# Copy the latest hlat.efi from ISO. fs1: in this example. This is needed for testing
# with VMware, where compiled artifacts are deployed to an ISO file, and not a disk.
#copy -q fs1:hlat.efi hlat.efi

# Run hlat.efi.
time
load hlat.efi
time
