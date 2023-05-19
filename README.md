# Containers 101 - From Scratch
An overview on how to create containers from scratch using only the operating system and kernel features. Remember to change all the values, folders, names, PIDs, parameters, etc., below according to your own environment. This is just an example based on my test environment.

## Host's system info

    # mount | grep cgroup
    cgroup2 on /sys/fs/cgroup type cgroup2 (rw,nosuid,nodev,noexec,relatime,seclabel,nsdelegate,memory_recursiveprot)
    
    # uname -a
    Linux fedora.example.local 5.18.13-200.fc36.x86_64 #1 SMP PREEMPT_DYNAMIC Fri Jul 22 14:03:36 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
    
    # cat /etc/system-release
    Fedora release 36 (Thirty Six)
    
    # nproc
    2
    
    # free -ht | awk '{print $1,$2}' | tail -3
    Mem: 3,8Gi
    Swap: 4,8Gi
    Total: 8,6Gi
    
    # lsblk
    NAME           MAJ:MIN RM  SIZE RO TYPE MOUNTPOINTS
    sr0             11:0    1 1024M  0 rom  
    zram0          251:0    0  3,8G  0 disk [SWAP]
    vda            252:0    0   30G  0 disk 
    ├─vda1         252:1    0    1G  0 part /boot
    └─vda2         252:2    0   29G  0 part 
      ├─VG_01-root 253:0    0   28G  0 lvm  /
      └─VG_01-swap 253:1    0 1020M  0 lvm  [SWAP]

    # ip a
    1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
        inet 127.0.0.1/8 scope host lo
           valid_lft forever preferred_lft forever
        inet6 ::1/128 scope host 
           valid_lft forever preferred_lft forever
    2: enp1s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
        link/ether 52:54:00:85:c2:f8 brd ff:ff:ff:ff:ff:ff
        inet 192.168.1.30/24 brd 192.168.1.255 scope global noprefixroute enp1s0
           valid_lft forever preferred_lft forever
        inet6 fe80::e31f:3806:c76d:89cd/64 scope link noprefixroute 
           valid_lft forever preferred_lft forever
       
    # id   
      uid=0(root) gid=0(root) groups=0(root) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023

## Create a custom rootdir

### Fedora 36:

    # dnf --releasever=36 --best --setopt=install_weak_deps=False --installroot=/root/myrootdir/ install alternatives apr apr-util apr-util-bdb apr-util-openssl audit-libs authselect authselect-libs basesystem bash bzip2-libs ca-certificates coreutils coreutils-common cracklib crypto-policies cryptsetup-libs curl cyrus-sasl-lib dbus dbus-broker dbus-common dbus-libs device-mapper device-mapper-libs diffutils dnf dnf-data elfutils-default-yama-scope elfutils-libelf elfutils-libs expat fedora-gpg-keys-36-1 fedora-logos-httpd fedora-release fedora-release-common-36-18 fedora-release-container-36-18 fedora-release-identity-container-36-18 fedora-repos-36-1 fedora-repos-modular-36-1 file-libs filesystem findutils fonts-filesystem gawk gdbm-libs glib2 glibc glibc-common glibc-minimal-langpack gmp gnupg2 gnutls gpgme gpm-libs grep gzip hostname httpd httpd-core httpd-filesystem httpd-tools ima-evm-utils info iproute iptables-legacy iptables-legacy-libs iptables-libs iputils json-c julietaula-montserrat-fonts keyutils-libs kmod-libs krb5-libs less libacl libarchive libargon2 libassuan libattr libblkid libbpf libbrotli libcap libcap-ng libcom_err libcomps libcurl libdb libdnf libeconf libevent libfdisk libffi libfsverity libgcc libgcrypt libgomp libgpg-error libibverbs libidn2 libksba libmetalink libmnl libmodulemd libmount libnetfilter_conntrack libnfnetlink libnghttp2 libnl3 libnsl2 libpcap libpsl libpwquality librepo libreport-filesystem libseccomp libselinux libsemanage libsepol libsigsegv libsmartcols libsodium libsolv libssh libssh-config libstdc++ libtasn1 libtirpc libunistring libuuid libverto libxcrypt libxkbcommon libxml2 libyaml libzstd lua-libs lz4-libs mailcap mod_http2 mod_lua mpdecimal mpfr ncurses ncurses-base ncurses-libs net-tools nettle npth openldap openldap-compat openssl-libs p11-kit p11-kit-trust pam pam-libs pcre pcre2 pcre2-syntax popt procps-ng psmisc publicsuffix-list-dafsa python-pip-wheel python-setuptools-wheel python3 python3-dnf python3-gpg python3-hawkey python3-libcomps python3-libdnf python3-libs python3-rpm qrencode-libs readline rootfiles rpm rpm-build-libs rpm-libs rpm-plugin-systemd-inhibit rpm-sign-libs sed setup shadow-utils sqlite-libs strace stress sudo systemd systemd-libs systemd-networkd systemd-pam systemd-resolved tar tpm2-tss tzdata util-linux-core vim-common vim-data vim-enhanced vim-filesystem vim-minimal wget which xkeyboard-config xz-libs yum zchunk-libs zlib dhcp-client glibc-langpack-en passwd -y

### Fedora 38:

    # dnf --releasever=38 --best --setopt=install_weak_deps=False --installroot=/root/fedora/ install alternatives apr apr-util apr-util-bdb apr-util-openssl audit-libs authselect authselect-libs basesystem bash bzip2-libs ca-certificates coreutils coreutils-common cracklib crypto-policies cryptsetup-libs curl cyrus-sasl-lib dbus dbus-broker dbus-common device-mapper device-mapper-libs diffutils dnf dnf-data elfutils-default-yama-scope elfutils-libelf elfutils-libs expat fedora-gpg-keys fedora-logos-httpd fedora-release-common fedora-release-container fedora-release-identity-container fedora-repos fedora-repos-modular file-libs filesystem findutils fonts-filesystem gawk gdbm-libs glib2 glibc glibc-common glibc-minimal-langpack gmp gnupg2 gnutls gpgme gpm-libs grep groff-base gzip httpd httpd-core httpd-filesystem httpd-tools ima-evm-utils iproute iptables-libs iptables-nft iputils json-c julietaula-montserrat-fonts keyutils-libs kmod-libs krb5-libs libacl libarchive libargon2 libassuan libattr libb2 libblkid libbpf libbrotli libcap libcap-ng libcom_err libcomps libcurl libdb libdnf libeconf libevent libfdisk libffi libfsverity libgcc libgcrypt libgomp libgpg-error libibverbs libidn2 libksba libmetalink libmnl libmodulemd libmount libnetfilter_conntrack libnfnetlink libnftnl libnghttp2 libnl3 libnsl2 libpcap libpsl libpwquality librepo libreport-filesystem libseccomp libselinux libsemanage libsepol libsigsegv libsmartcols libsodium libsolv libssh libssh-config libstdc++ libtasn1 libtirpc libunistring libunistring1.0 libuser libuuid libverto libxcrypt libxkbcommon libxml2 libyaml libzstd lua-libs lz4-libs mailcap mod_http2 mod_lua mpdecimal mpfr ncurses ncurses-base ncurses-libs net-tools nettle npth openldap openssl-libs p11-kit p11-kit-trust pam pam-libs passwd pcre2 pcre2-syntax perl-AutoLoader perl-B perl-Carp perl-Class-Struct perl-Data-Dumper perl-Digest perl-Digest-MD5 perl-DynaLoader perl-Encode perl-Errno perl-Exporter perl-Fcntl perl-File-Basename perl-File-Path perl-File-Temp perl-File-stat perl-FileHandle perl-Getopt-Long perl-Getopt-Std perl-HTTP-Tiny perl-IO perl-IO-Socket-IP perl-IO-Socket-SSL perl-IPC-Open3 perl-MIME-Base64 perl-Mozilla-CA perl-NDBM_File perl-Net-SSLeay perl-POSIX perl-PathTools perl-Pod-Escapes perl-Pod-Perldoc perl-Pod-Simple perl-Pod-Usage perl-Scalar-List-Utils perl-SelectSaver perl-Socket perl-Storable perl-Symbol perl-Term-ANSIColor perl-Term-Cap perl-Text-ParseWords perl-Text-Tabs+Wrap perl-Time-Local perl-URI perl-base perl-constant perl-if perl-interpreter perl-libnet perl-libs perl-locale perl-mro perl-overload perl-overloading perl-parent perl-podlators perl-vars popt psmisc publicsuffix-list-dafsa python-pip-wheel python-setuptools-wheel python3 python3-dnf python3-gpg python3-hawkey python3-libcomps python3-libdnf python3-libs python3-rpm qrencode-libs readline rootfiles rpm rpm-build-libs rpm-libs rpm-sequoia rpm-sign-libs sed setup shadow-utils sqlite-libs strace stress sudo systemd systemd-libs systemd-networkd systemd-pam systemd-resolved tar tpm2-tss tzdata util-linux-core vim-common vim-data vim-enhanced vim-filesystem vim-minimal wget which xkeyboard-config xxd xz-libs yum zchunk-libs zlib -y

## Or export from an existing container image

    # podman pull docker.io/library/fedora
    
    # podman run --name=fedora -it docker.io/library/fedora /bin/bash
    
    # podman export fedora --output=/root/fedora.tar
    
    # mkdir /root/myrootdir
    
    # tar -xvf /root/fedora.tar -C /root/myrootdir/

## Populate /dev/

    # mknod -m 622 /root/myrootdir/dev/console c 5 1 && \
    
    # mknod -m 666 /root/myrootdir/dev/zero c 1 5 && \
    
    # mknod -m 666 /root/myrootdir/dev/ptmx c 5 2 && \
    
    # mknod -m 666 /root/myrootdir/dev/tty c 5 0 && \
    
    # mknod -m 444 /root/myrootdir/dev/random c 1 8 && \
    
    # mknod -m 444 /root/myrootdir/dev/urandom c 1 9 && \
    
    # chown -v root:tty /root/myrootdir/dev/{console,ptmx,tty}

## Create a script to facilitate mounting proc, sysfs and tmpfs

    # echo 'mount -t proc proc /proc/ && mount -t tmpfs tmpfs /tmp/ && mount -t sysfs sysfs /sys/' > /root/myrootdir/root/mounting.sh && chmod +x /root/myrootdir/root/mounting.sh

## Enable DNS resolution

    # rm -rf /root/myrootdir/etc/resolv.conf
    
    # echo "nameserver 8.8.8.8" > /root/myrootdir/etc/resolv.conf

## Change the httpd default listen port to 8081

    # sed -i 's/Listen 80/Listen 8081/g' /root/myrootdir/etc/httpd/conf/httpd.conf
    
    # echo "It Works On My Machine" > /root/myrootdir/var/www/html/index.html

## Download cpuburn for cgroups testing

    # wget -P /root/myrootdir/root/ https://cdn.pmylund.com/files/tools/cpuburn/linux/cpuburn-1.0-amd64.tar.gz
    
    # tar -zxvf /root/myrootdir/root/cpuburn-1.0-amd64.tar.gz -C /root/myrootdir/root/

## Create the overlayfs directories

    # mkdir /container
    
    # mkdir /root/overlayfs
    
    # mkdir /root/overlayfs/lower
    
    # mkdir /root/overlayfs/upper
    
    # mkdir /root/overlayfs/merged
    
    # mkdir /root/overlayfs/work
    
    # cp -R /root/myrootdir/* /root/overlayfs/lower
    
    # cp -R /root/myrootdir/* /root/overlayfs/upper

## Mount overlayfs and bind the upper directory

    # mount -t overlay overlay -o lowerdir=/root/overlayfs/lower,upperdir=/root/overlayfs/upper,workdir=/root/overlayfs/work /root/overlayfs/merged
    
    # mount -o bind /root/overlayfs/upper /container

## In a separate window, run your container

    # unshare -muinpfCTUr chroot /container /bin/bash

## Setting network

    # ip netns add test
    
    # ip netns del test
    
    # ip link add name br0 type bridge
    
    # ip link set br0 up
    
    # ip a add dev br0 10.0.0.1/24
    
    # echo 1 > /proc/sys/net/ipv4/ip_forward
    
    # ln -s /proc/$(lsns | grep unshare | grep net | awk '{print $4}')/ns/net /var/run/netns/container
    
    # ip l add veth0 type veth peer name ceth0
    
    # ip l set ceth0 netns container
    
    # ip l set veth0 up
    
    # ip netns exec container ip l set ceth0 up
    
    # brctl addif br0 veth0
    
    # ip netns exec container ip a add dev ceth0 10.0.0.2/24
    
    # ip netns exec container ip route add default via 10.0.0.1
    
    # systemctl stop firewalld
    
    # iptables -F
    
    # iptables -t nat -F
    
    # iptables -t nat -A POSTROUTING -o enp1s0 -s 10.0.0.0/24 -j MASQUERADE
    
    # iptables -t nat -A PREROUTING -p tcp --dport 8081 -j DNAT --to-destination 10.0.0.2:8081

## Inside the container, mount the needed filesystems and run httpd

    # /root/mounting.sh
    
    # hostname container.example.local
    
    # httpd -k start

## Inside the container, do some testing

    # hostname
    
    # mount
    
    # ps -ef
    
    # ipcs
    
    # ip a
    
    # ss -nputaw
    
    # ping 10.0.0.1
    
    # ping www.google.com.br
    
    # curl rate.sx

## Outside the container, do some testing

    # curl 10.0.0.2:8081
    
    # curl 192.168.1.30:8081

## Cgroups configuration

    # systemd-cgtop
    
    # systemd-cgls
    
    # cat /sys/fs/cgroup/cgroup.controllers
    
    # echo "+cpu" >> /sys/fs/cgroup/cgroup.subtree_control
    
    # echo "+cpuset" >> /sys/fs/cgroup/cgroup.subtree_control
    
    # mkdir /sys/fs/cgroup/container
    
    # echo "+cpu" >> /sys/fs/cgroup/container/cgroup.subtree_control
    
    # echo "+cpuset" >> /sys/fs/cgroup/container/cgroup.subtree_control
    
    # mkdir /sys/fs/cgroup/container/tasks
    
    # echo "max 100000" > /sys/fs/cgroup/container/tasks/cpu.max
    
    # echo "1" > /sys/fs/cgroup/container/tasks/cpuset.cpus    
    
    # cat /sys/fs/cgroup/user.slice/user-0.slice/session-5.scope/cgroup.procs
    
    # echo "+cpu" >> /sys/fs/cgroup/user.slice/cgroup.subtree_control
    
    # echo "+cpuset" >> /sys/fs/cgroup/user.slice/cgroup.subtree_control
    
    # echo "+memory" >> /sys/fs/cgroup/user.slice/cgroup.subtree_control
    
    # echo "+cpu" >> /sys/fs/cgroup/user.slice/user-0.slice/cgroup.subtree_control
    
    # echo "+cpuset" >> /sys/fs/cgroup/user.slice/user-0.slice/cgroup.subtree_control
    
    # echo "+memory" >> /sys/fs/cgroup/user.slice/user-0.slice/cgroup.subtree_control
    
    # echo "+cpu" >> /sys/fs/cgroup/user.slice/user-0.slice/session-5.scope/cgroup.subtree_control
    
    # echo "+cpuset" >> /sys/fs/cgroup/user.slice/user-0.slice/session-5.scope/cgroup.subtree_control
    
    # echo "+memory" >> /sys/fs/cgroup/user.slice/user-0.slice/session-5.scope/cgroup.subtree_control
    
    # echo "0-1" > /sys/fs/cgroup/user.slice/user-0.slice/session-5.scope/cpuset.cpus
    
    # echo "10000 100000" > /sys/fs/cgroup/user.slice/user-0.slice/session-5.scope/cpu.max
    
    # echo "50000000" > /sys/fs/cgroup/user.slice/user-0.slice/session-5.scope/memory.max

## Inside the container, run the CPU and memory stress test

    # /root/cpuburn/cpuburn
    
    # stress -m 1 --vm-bytes 500M --vm-keep --timeout 60s

## Outside the container, monitor the outputs

    # top
    
    # top -p `pgrep -d "," stress`
    
    # ps -eLfZ
