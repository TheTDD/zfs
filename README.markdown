# Release info

This branch is build on [ZoL release 0.8.3](https://github.com/zfsonlinux/zfs/tree/zfs-0.8.3) and contains the completely new implementation of [Intel QuickAsssist](https://01.org/intel-quickassist-technology) Hardware support for GZIP filesystem compression and SHA2-256 (also SHA2-512 and SHA3-256 when it will needed) checksums. *QAT-Encryption is not implemented yet because I have actually no usage for it*.

The QAT implementation uses fast and simple [Data Plane DC API](https://01.org/sites/default/files/downloads/intelr-quickassist-technology/qadcapiv203public.pdf) and [Data Plane CySym API](https://01.org/sites/default/files/downloads/intelr-quickassist-technology/qacyapiv201public.pdf).

News on this release:

- early initialization of QAT is not required, module lazily initializes QAT when it is ready
- support of GZIP compression level (gzip-1 to gzip-9)
- statistics `/proc/spl/kstat/zfs/qat` changed to `/proc/spl/kstat/zfs/qat-dc`, added new statistics `/proc/spl/kstat/zfs/qat-cy`
- extended statistics includes throughput and counts of errors and operation status
- statistics is visible always even if QAT is not exists or is not initialized, but remains zero of course
- implementation is using kernel memory caches for flat source, destination and intermediate buffers to avoid fragmentation of valuable kernel memory
- qat compression, decompression and checksum can be disabled independently (for by example benchmarking, comparing with sw-implementation or development/debugging purposes)
- access to QAT can be disabled completely with `zfs_qat_disable` parameter
- QAT support disables itself automatically (independent for DC and CY) if can't initialize corresponding DC or CY instances after configurable number of requests (default 100). The threshold is configurable by zfs module parameter `zfs_qat_init_failure_threshold`

To avoid initialization failures at boot time caused by QAT starting later then ZFS module is loaded I can suggest to put `options zfs zfs_qat_disable=1` into `/etc/modprobe.d/zfs.conf`, then create a systemd service which starts after QAT and enables QAT in ZFS with `echo 0 > /sys/modules/zfs/parameters/zfs_qat_disable`.

```
# cat /etc/systemd/system/zfs-qat.service 
[Unit]
Description=Intel QuickAssist Support for ZFS file system
DefaultDependencies=no
After=qat_service.service
After=zfs.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/zfs_qat on
ExecStop=/usr/local/bin/zfs_qat off

[Install]
WantedBy=multi-user.target
```
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

# ZFS module statistics compression/decompression
```
[root@bg]# cat /proc/spl/kstat/zfs/qat-dc
18 1 0x01 31 8432 14120743908 7045360623020
name                            type data
init_failed                     4    0
comp_requests                   4    246355
comp_total_in_bytes             4    31067879936
comp_total_success_bytes        4    28560988672
comp_total_out_bytes            4    13076317638
comp_fails                      4    22437
comp_throughput_bps             4    112444837
decomp_requests                 4    604924
decomp_total_in_bytes           4    60516649472
decomp_total_success_bytes      4    60516649472
decomp_total_out_bytes          4    79038761984
decomp_fails                    4    0
decomp_throughput_bps           4    309955929
err_no_instance_available       4    0
err_out_of_mem                  4    0
err_timeout                     4    0
err_gen_header                  4    0
err_gen_footer                  4    0
err_overflow                    4    22437
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
19 1 0x01 16 4352 14120886992 7065455766148
name                            type data
init_failed                     4    0
sha2_256_requests               4    1110042
sha2_256_total_in_bytes         4    109949473280
sha2_256_total_success_bytes    4    109949473280
sha2_256_total_out_bytes        4    35521344
sha2_256_fails                  4    0
sha2_256_throughput_bps         4    408734101
err_no_instance_available       4    0
err_out_of_mem                  4    0
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
[root@bg]# zpool iostat -v
                                            capacity     operations     bandwidth
pool                                      alloc   free   read  write   read  write
----------------------------------------  -----  -----  -----  -----  -----  -----
srv                                       6.84T  4.04T     91    192  3.21M  3.75M
  mirror                                  2.25T  1.38T     33     62  1.10M  1.08M
    ata-ST4000NM002A-2HZ101_WJG0GF73          -      -     16     33   590K   555K
    ata-WDC_WD4002FYYZ-01B7CB0_K3GDHW1B       -      -     16     29   541K   555K
  mirror                                  2.18T  1.44T     30     51  1.10M   983K
    ata-ST4000NM0035-1V4107_ZC12DAN7          -      -     15     29   578K   491K
    ata-TOSHIBA_MG04ACA400E_292GK90XFJKA      -      -     15     22   545K   491K
  mirror                                  2.41T  1.22T     27     55  1.00M  1.03M
    ata-WDC_WD4002FYYZ-01B7CB0_K4KGXS3B       -      -     13     26   482K   526K
    ata-ST4000NM0035-1V4107_ZC12DB9P          -      -     13     29   546K   526K
logs                                          -      -      -      -      -      -
  cc52ce29-2cfc-4a6e-81af-04f055d3e23d    16.9M  1.97G      0     21     50   697K
cache                                         -      -      -      -      -      -
  nvme0n1                                 12.5M   119G      0      0     14  4.07K
----------------------------------------  -----  -----  -----  -----  -----  -----
```

Implementation of QAT encryption using Crypto Data Plane operations follows if I will find use of it or by request. Please stay tuned.

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
