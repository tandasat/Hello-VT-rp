# Hello-VT-rp

A simple hypervisor demonstrating the use of the Intel VT-rp (redirect protection) technology.

This repository is a complement of the blob post, [TODO](TODO), and is not meant for general use. For the details of Intel VT-rp, please read the post.


## The hypervisor

The [hypervisor/](hypervisor/) directory contains a UEFI runtime-driver-based hypervisor. It is capable of booting a single-core Windows on Dell Latitude 7330 and enabling HLAT, PW, and GPV through hypercalls.
