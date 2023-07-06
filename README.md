# Hello-VT-rp

A simple hypervisor demonstrating the use of the Intel VT-rp (redirect protection) technology.

This repository is a complement of the [Intel VT-rp blog post series](https://tandasat.github.io/blog/2023/07/05/intel-vt-rp-part-1.html) and not meant for a general use. For the overview of Intel VT-rp, please read the post.


## The hypervisor

The [hypervisor/](hypervisor/) directory contains a UEFI runtime-driver-based hypervisor. It is capable of booting a single-core Windows on Dell Latitude 7330 and enabling HLAT, PW, and GPV through hypercalls.
