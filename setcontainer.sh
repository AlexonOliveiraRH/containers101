#!/bin/bash

## First time ##
creating () {
mount -t overlay overlay -o lowerdir=/root/myrootdir/overlayfs/lower,upperdir=/root/myrootdir/overlayfs/upper,workdir=/root/myrootdir/overlayfs/work /root/myrootdir/overlayfs/merged
mount -o bind /root/myrootdir/overlayfs/upper /container
read -p "Now run the following command in a second terminal and then press Enter here to continue: unshare -muinpfCTUr chroot /container /bin/bash"
ip netns add test
ip netns del test
ip link add name br0 type bridge
ip link set br0 up
ip a add dev br0 10.0.0.1/24
echo 1 > /proc/sys/net/ipv4/ip_forward
ln -s /proc/$(lsns | grep unshare | grep net | awk '{print $4}')/ns/net /var/run/netns/container
ip l add veth0 type veth peer name ceth0
ip l set ceth0 netns container
ip l set veth0 up
ip netns exec container ip l set ceth0 up
brctl addif br0 veth0
ip netns exec container ip a add dev ceth0 10.0.0.2/24
ip netns exec container ip route add default via 10.0.0.1
systemctl stop firewalld
iptables -F
iptables -t nat -F
iptables -t nat -A POSTROUTING -o enp1s0 -s 10.0.0.0/24 -j MASQUERADE
iptables -t nat -A PREROUTING -p tcp --dport 8081 -j DNAT --to-destination 10.0.0.2:8081
echo "Your container built by hand is up and running. Test it by accessing http://fedora.example.local:8081"
}

## Second time onwards ##
recreating () {
read -p "Now run the following command in a second terminal and then press Enter here to continue: unshare -muinpfCTUr chroot /container /bin/bash"
echo 1 > /proc/sys/net/ipv4/ip_forward
rm -rf /var/run/netns/container && ln -s /proc/$(lsns | grep unshare | grep net | awk '{print $4}')/ns/net /var/run/netns/container
ip l add veth0 type veth peer name ceth0
ip l set ceth0 netns container
ip l set veth0 up
ip netns exec container ip l set ceth0 up
brctl addif br0 veth0
ip netns exec container ip a add dev ceth0 10.0.0.2/24
ip netns exec container ip route add default via 10.0.0.1
systemctl stop firewalld
iptables -F
iptables -t nat -F
iptables -t nat -A POSTROUTING -o enp1s0 -s 10.0.0.0/24 -j MASQUERADE
iptables -t nat -A PREROUTING -p tcp --dport 8081 -j DNAT --to-destination 10.0.0.2:8081
echo "Your container built by hand is up and running. Test it by accessing http://fedora.example.local:8081"
}

destroying () {
read -p "Exit from your container in the second terminal with Ctrl+D or 'exit' command then press Enter here to continue"
umount /container
umount /root/myrootdir/overlayfs/merged
echo "Your container built by hand is now down"
}

case "$1" in
"start") creating ;;
"restart") recreating ;;
"stop") destroying ;;
*) echo "ERROR: There is no such option or you are missing a parameter. Use start, restart or stop"
esac
