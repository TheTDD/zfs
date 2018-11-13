# Release info

This branch is build on [ZoL release 0.7.11](https://github.com/zfsonlinux/zfs/tree/zfs-0.7.11) and contains the completely new implementation of [Intel QuickAsssist](https://01.org/intel-quickassist-technology) Hardware support for GZIP filesystem compression and SHA2-256 (also SHA2-512 and SHA3-256 when it will needed) checksums.

The QAT implementation uses fast and simple [Data Plane DC API](https://01.org/sites/default/files/downloads/intelr-quickassist-technology/qadcapiv203public.pdf) and [Data Plane CySym API](https://01.org/sites/default/files/downloads/intelr-quickassist-technology/qacyapiv201public.pdf).

News on this release:

- early initialization of QAT is not required, the qat_service may be stopped and started at any time
- support of GZIP compression level (gzip-1 to gzip-9)
- statistics zfs/qat changed to zfs/qat-dc
- extended statistics includes throughput and counts of errors and operation status
- implementation is intesively using kernel contiguous memory for flat source and destination buffers
- qat compression, decompression and checksum can be disabled independently (for by example benchmarking, comparing with sw-implementation or development/debugging purposes)
- access to QAT can be disabled completely with `zfs_qat_disable` parameter
- QAT support disables itself automatically (independent for DC and CY) if can't initialize corresponding DC or CY instances after configurable number of requests (default 100). The threshold is configurable by zfs module parameter

To avoid initialization failures at boot time caused by QAT starting later then ZFS module is loaded I can suggest to put `options zfs zfs_qat_disable=1` into `/etc/modprobe.d/zfs.conf`, then create a service which starts after QAT and enables QAT in ZFS with `echo 0 > /sys/modules/zfs/parameters/zfs_qat_disable`

# ZFS module parameters
```
[root@bg]# modinfo zfs | grep qat
depends:        spl,znvpair,zcommon,zunicode,qat_api,zavl,icp
parm:           zfs_qat_disable_sha2_256:Disable SHA2-256 digest calculations (int)
parm:           zfs_qat_disable_compression:Disable QAT compression (int)
parm:           zfs_qat_disable_decompression:Disable QAT decompression (int)
parm:           zfs_qat_init_failure_threshold:Threshold (number of init failures) to consider disabling QAT (int)
parm:           zfs_qat_disable:completely disable any access to QAT (int)
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

This build of ZFS is since 2018-11-11 in production environment with 10TB ZFS-Pool:

```
# zpool iostat -v
                                                  capacity     operations     bandwidth 
pool                                            alloc   free   read  write   read  write
----------------------------------------------  -----  -----  -----  -----  -----  -----
srv                                             5.88T  5.00T     21     80  1.27M  2.55M
  mirror                                        2.51T  1.12T      9     25   538K   648K
    ata-WDC_WD4002FYYZ-01B7CB0_K3GDHW1B             -      -      4     12   273K   324K
    ata-WDC_WD4002FYYZ-01B7CB0_K4KGXS3B             -      -      5     12   266K   324K
  mirror                                        3.31T   333G      6     26   441K   407K
    ata-ST4000NM0035-1V4107_ZC12DB9P                -      -      3     13   219K   203K
    ata-ST4000NM0035-1V4107_ZC12DAN7                -      -      3     13   221K   203K
  mirror                                        68.4G  3.56T      5     16   318K   793K
    ata-TOSHIBA_MG03ACA400_5387K02LF                -      -      3      9   170K   396K
    ata-WDC_WD4000FYYZ-01UL1B1_WD-WCC130727209      -      -      2      7   148K   396K
logs                                                -      -      -      -      -      -
  cc52ce29-2cfc-4a6e-81af-04f055d3e23d           892K  1.98G      0     11      6   762K
cache                                               -      -      -      -      -      -
  nvme-INTEL_SSDPEKKW128G8_BTHH81850QJP128A      956M   118G      1      5  3.87K  22.7K
----------------------------------------------  -----  -----  -----  -----  -----  -----
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
