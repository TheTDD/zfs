# Release info

This branch is build on [ZoL release 0.7.11](https://github.com/zfsonlinux/zfs/tree/zfs-0.7.11) and contains the completely new implementation of [Intel QuickAsssist](https://01.org/intel-quickassist-technology) Hardware support for GZIP filesystem compression and SHA2-256 (also SHA2-512 and SHA3-256 when it will needed) checksums.

The QAT implementation uses fast and simple [Data Plane DC API](https://01.org/sites/default/files/downloads/intelr-quickassist-technology/qadcapiv203public.pdf) and [Data Plane CySym API](https://01.org/sites/default/files/downloads/intelr-quickassist-technology/qacyapiv201public.pdf).

News on this release:

- early initialization of QAT is not required, the qat_service may be stopped and started at any time
- support of GZIP compression level (gzip-1 to gzip-9)
- statistics zfs/qat changed to zfs/qat-dc
- extended statistics includes throughput and counts of errors and operation status
- implementation is intesively using kernel contiguous memory for flat source and destination buffers, please configure your usdm_drv correspondingly (see `modinfo usdm_drv`)
- qat compression, decompression and checksum can be disabled independently (for by example benchmarking, comparing with sw-implementation or development/debugging purposes)
- QAT support disables itself automatically if can't initialize DC/CY instances after configurable number of requests (default 100). The threshold is configurable by zfs module parameter

# ZFS module parameters
```
[root@bg]# modinfo zfs | grep qat
depends:        spl,znvpair,zcommon,zunicode,qat_api,zavl,icp
parm:           zfs_qat_disable_sha2_256:Disable SHA2-256 digest calculations (int)
parm:           zfs_qat_disable_compression:Disable QAT compression (int)
parm:           zfs_qat_disable_decompression:Disable QAT decompression (int)
parm:           zfs_qat_init_failure_threshold:Threshold (number of init failures) to consider disabling QAT (int)
```

# ZFS module statistics compression
```
[root@bg]# cat /proc/spl/kstat/zfs/qat-dc
18 1 0x01 27 7344 646325619555 700778904942
name                            type data
init_failed                     4    0
comp_requests                   4    4393
comp_total_in_bytes             4    566758400
comp_total_out_bytes            4    320513211
comp_fails                      4    0
comp_throughput_bps             4    21867586
decomp_requests                 4    4551
decomp_total_in_bytes           4    357482496
decomp_total_out_bytes          4    594368000
decomp_fails                    4    0
decomp_throughput_bps           4    340612034
err_no_instance_available       4    0
err_timeout                     4    0
err_gen_header                  4    0
err_gen_footer                  4    0
err_overflow                    4    0
err_status_fail                 4    0
err_status_retry                4    0
err_status_param                4    0
err_status_resource             4    0
err_status_baddata              4    0
err_status_restarting           4    0
err_status_unknown              4    0
err_op_overflow                 4    0
err_op_hw                       4    0
err_op_sw                       4    0
err_op_fatal                    4    0
err_op_unknown                  4    0
```
# ZFS module statistics checksums
```
[root@bg]# cat /proc/spl/kstat/zfs/qat-cy
19 1 0x01 14 3808 5295794556 10425107063546
name                            type data
init_failed                     4    272
sha2_256_requests               4    522193
sha2_256_total_in_bytes         4    66636804608
sha2_256_total_success_bytes    4    66636804608
sha2_256_total_out_bytes        4    16710176
sha2_256_fails                  4    0
sha2_256_throughput_bps         4    420448006
err_no_instance_available       4    231
err_timeout                     4    0
err_status_fail                 4    0
err_status_retry                4    0
err_status_param                4    0
err_status_resource             4    0
err_status_restarting           4    0
err_status_unknown              4    0
```

Implementation of QAT encryption using Crypto Data Plane operations follows. Please stay tuned.

![img](http://zfsonlinux.org/images/zfs-linux.png)

ZFS on Linux is an advanced file system and volume manager which was originally
developed for Solaris and is now maintained by the OpenZFS community.

[![codecov](https://codecov.io/gh/zfsonlinux/zfs/branch/master/graph/badge.svg)](https://codecov.io/gh/zfsonlinux/zfs)

# Official Resources
  * [Site](http://zfsonlinux.org)
  * [Wiki](https://github.com/zfsonlinux/zfs/wiki)
  * [Mailing lists](https://github.com/zfsonlinux/zfs/wiki/Mailing-Lists)
  * [OpenZFS site](http://open-zfs.org/)

# Installation
Full documentation for installing ZoL on your favorite Linux distribution can
be found at [our site](http://zfsonlinux.org/).

# Contribute & Develop
We have a separate document with [contribution guidelines](./.github/CONTRIBUTING.md).
