# Run Ping in vmm-reference

## 1. Host Configuration

### 1.1 Network Configuration
```bash
sudo ip tuntap add dev tap0 mode tap
sudo ip addr add 192.168.100.1/24 dev tap0
sudo ip link set tap0 up

sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE # replace eth0 to your network interface (run "ip a" to list all interface ), for example: wlp3s0
sudo iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A FORWARD -i tap0 -o eth0 -j ACCEPT
```

### 1.2 Disk Configuration
```bash
dd if=/dev/zero of=rootfs.ext4 bs=1M count=128
mkfs.ext4 rootfs.ext4
mkdir -p ./mnt
sudo mount -o loop rootfs.ext4 ./mnt

curl -O https://busybox.net/downloads/busybox-1.37.0.tar.bz2
tar xf busybox-1.37.0.tar.bz2
cd busybox-1.37.0
make menuconfig
# select the option: "Settings -> Build static binary (no shared libs)"
make install

cd ..
sudo cp -a ./busybox-1.37.0/_install/* ./mnt/
```

```bash
sudo tee ./mnt/init.sh << 'EOF'
#!/bin/sh
set -eux

mkdir -p /proc /sys /dev

mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev

echo "[init] bring up network"

ip a

ip link set lo up
ip link set eth0 up
ip addr add 192.168.100.2/24 dev eth0
ip route add default via 192.168.100.1

echo "[init] start ping"
ping 8.8.8.8 -c 4

echo "[init] ping finished, poweroff"
poweroff -f
EOF
```

```bash
sudo chmod +x ./mnt/init.sh

sudo umount ./mnt
```

## 2. Guest Configuration

```bash
wget https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.10.1.tar.xz
tar xf linux-5.10.1.tar.xz

wget https://github.com/firecracker-microvm/firecracker/blob/main/resources/guest_configs/microvm-kernel-ci-x86_64-5.10.config
cp microvm-kernel-ci-x86_64-5.10.config linux-5.10.1/.config

cd linux-5.10.1
make oldconfig
make vmlinux -j 4

cd ..
```

## 3、Run
```bash
sudo rust-vmm/vmm-reference/target/debug/vmm-reference --kernel path=./linux-5.10.1/vmlinux,cmdline="root=/dev/vda rw init=/init.sh" --block path=rootfs.ext4 --net tap=tap0
```
