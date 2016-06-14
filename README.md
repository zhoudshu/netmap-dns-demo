# netmap-dns-demo

the demo examples which use the [__netmap api__](http://info.iet.unipi.it/~luigi/netmap/) and dns protocol when I learned the netmap framework.

## Installed environment 

* Centos 6.6 and Linux Kernel [__linux-4.1.6__](ftp://ftp.kernel.org/pub/linux/kernel/v4.x/linux-4.1.6.tar.xz)
* Intel Corporation I350 Gigabit Network Connection
* netmap :clone from [__zhoudshu github__](https://github.com/zhoudshu/netmap-dns-demo)

## Compile demo examples

### Step 1: Compile and Install netmap
Please Compile and install netmap according with README
### Step 2: Compile and Run Demo

```nginx
# cd examples/
# make 
# ./dns-resp -v
    usage: dns-echo [-v] [-c] [-i ifa] [-i ifb] [-b burst] [-w wait_time] 
    Supported options:
    -v  if run with debug default close.
    -c  if used zerocopy default open.
    -i  Specify intput or output nic name for netmap.
    -b  max-packet in netmap ring default 1024 .
    -w  wait time in seconds default 4.

    Example:
    ./dns-resp -i netmap:eth4 -i netmap:eth5 

```

## Step 3: Run Result 
DNS Records are hard code and always has been ip addresses 10.10.1.232 and 10.10.1.231 for Test.

```bash

# dig @8.8.8.8 www.qq.com +tries=1

;; QUESTION SECTION:
;www.qq.com.                    IN      A

;; ANSWER SECTION:
www.qq.com.             34      IN      A       10.10.1.232
www.qq.com.             34      IN      A       10.10.1.231

;; Query time: 0 msec
;; SERVER: 8.8.8.8#53(8.8.8.8)
;; WHEN: Tue Jun 14 09:00:17 2016
;; MSG SIZE  rcvd: 60
```

## Note
* Nic must set promisc mode:
  ifconfig ethx promisc
* if Error "PTE Write access is not set" is occurred, We must set "intel_iommu=off" in grub.conf and reboot Linux OS

## Good Luck
