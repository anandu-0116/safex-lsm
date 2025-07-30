# Safex: Read Access Control LSM

## Overview
**Safex** is a custom Linux Security Module (LSM) that enforces file **read access control** based on a denylist. If a file path appears in /etc/safex.denylist, read operations on that file will be blocked by the kernel. This LSM uses the file_open hook to intercept access attempts and supports delayed initialization using workqueues to ensure that the denylist is loaded **after the filesystem is ready** during boot.

This README will guide you through:
* Project logic and architecture
* Kernel setup and integration steps
* Environment prerequisites
* How to build and test Safex

## Features
* Intercepts `file_open` system calls
* Checks the full absolute file path against a denylist
* Dynamically loads the denylist from `/etc/safex.denylist`
* Retry mechanism using delayed workqueue in case `/etc` isn't mounted initially
* Only blocks reads (write and execute accesses are untouched)

## Directory Structure
This repository only includes the contents of the `security/safex/` folder:
```
safex/
├── Makefile
├── Kconfig
├── safex_lsm.c     # Core logic of the LSM
├── include/
│   └── safex.h     # Shared header for constants and declarations
└── README.md
```
All other changes were made in the Linux kernel source tree externally.

## Prerequisites
1. **Download and extract kernel source:**
```
wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.11.tar.xz
tar -xf linux-6.11.tar.xz
```
2. **Install required packages:**
Install the following packages on your Linux development machine (Ubuntu recommended):
```
sudo apt update
sudo apt install libncurses-dev pkg-config
sudo apt install flex
sudo apt install bison
sudo apt install -y \
  libelf-dev \
  libssl-dev \
  flex \
  bison \
  build-essential \
  libncurses-dev \
  pkg-config \
  dwarves
sudo apt install libssl-dev
```
These packages are essential for compiling the Linux kernel with LSM support.

## Kernel Integration Steps
Safex must be integrated into the Linux kernel source tree. Below are the detailed steps:
1. **Copying Safex**

Clone the Safex repository or copy the safex folder (containing Makefile, Kconfig, safex_lsm.c, README.md, and include/safex.h) into the kernel source tree under `security/safex/`.

2. **Modify `security/Kconfig`**

Add the following line at the bottom:
```
source "security/safex/Kconfig"
```
3. **Modify `security/Makefile`**

Append this line:
```
obj-$(CONFIG_SECURITY_SAFEX) += safex/
```
4. **Enable Safex in Kernel Config**

Run:
```
make menuconfig
```
Navigate to:
```
Security Options --->
[*] Enable safex access control
```
Also ensure the following two options are set to empty strings to avoid signature verification issues:
```
CONFIG_SYSTEM_TRUSTED_KEYS=""
CONFIG_SYSTEM_REVOCATION_KEYS=""
```
5. **Update `.config` to Register Safex**

Edit the .config file manually and prepend safex to the CONFIG_LSM list.

6. **Fixing Low Disk Space Issues (Optional)**

I ran into low disk space issues during my build. If your build fails due to low space, run:
```
make localmodconfig
```
This will prune unneeded modules.

7. **Compile and Install Kernel**
```
make -j$(nproc)
make modules_install
make install
```
8. **Configure GRUB**

We can edit `/etc/default/grub` file to set a timeout and a menu so that we can select our desired linux kernel to boot to. (Linux 6.11.0 in this case).
```
GRUB_TIMEOUT=10
GRUB_TIMEOUT_STYLE=menu
``` 
Then update GRUB:
```
sudo update-grub
```
9. **Reboot**
```
sudo reboot
```
Select the new kernel version (e.g., Linux 6.11)

## Creating the Denylist File
Create `/etc/safex.denylist` as root. 
Example:
```
echo "/home/anandu/Documents/tmp.txt" | sudo tee -a /etc/safex.denylist
```
Make sure to use absolute paths for files whose paths are to be added into the denylist.

## How It Works
* On boot, Safex schedules a delayed workqueue that tries to load the denylist after 10 seconds.
* If loading fails (e.g., due to the root filesystem not being ready), it retries up to 12 times (2 minutes total).
* Once the denylist is successfully loaded, a global `lsm_active` flag is set.
* The `file_open` hook checks every file being opened against the denylist.
* If a path matches, access is denied (`-EACCES`).

## Example Behavior
Assuming `/etc/safex.denylist` contains:
```
/home/anandu/Documents/tmp.txt
```
Then running:
```
cat /home/anandu/Documents/tmp.txt
```
Will result in:
```
cat: /home/anandu/Documents/tmp.txt: Permission denied
```
And dmesg will show:
```
sudo dmesg | grep "Matched"
[30118.163023] safex: Matched path /home/anandu/Documents/tmp.txt
```

## Notes
* The LSM loads in a deferred manner to handle late-mounting filesystems.
* The denylist is static and loaded once at boot. For dynamic reload support, enhancements can be made.

## References
* [The Linux Kernel Archives](https://www.kernel.org/doc/html/v4.19/index.html)
* [Stack Overflow](https://stackoverflow.com/questions)
* GPT-4 (ChatGPT) for kernel integration and debugging help