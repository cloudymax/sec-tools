#!/bin/bash

############
## CloudInit Functions
## Library of functions for use with cloudinit for provisioning
## ubunut images in multiple environments. This should be ported to 
## python or put behind an api later. The values below will need to 
## be moved into config files/databases
#####


# password generation vars
export ROUNDS=4096
export METHOD="SHA-512"
export SALT="acab1312"
export PASSWORD="password"

# iso download values
export IMAGE="jammy-live-server-amd64.iso"
export ISO_URL="https://cdimage.ubuntu.com/ubuntu-server/daily-live/current/$IMAGE"

# working dir and path values
export IMAGE_DIR="/home/max/Desktop/repos/ark8de/usb"
export IMAGE_FILE="Ubuntu.iso"

generate_secret(){
  sudo apt-get install pwgen

}

create_secret(){
  sudo apt-get install whois

  # create encrypted pw
  encrypted=$(mkpasswd --method=$METHOD --rounds=$ROUNDS \
    --salt=$SALT \
    $PASSWORD)

  # strip identifiers
  password=$(echo "${encrypted}" | sed "s/\<rounds=$ROUNDS\>//g" | sed "s/\<$SALT\>//g"  | sed 's/\$//g' | sed 's/6//g')

  echo $password

}

download_iso(){
    wget -N -c -O Ubuntu.iso "${ISO_URL}"
}

extract_iso(){
  mkdir source_files
  7z -y x $IMAGE_DIR/$IMAGE_FILE -osource_files
}

modify_distro(){
  # Remove the unneeded '[BOOT]' dir
  rm -rf source-files/[BOOT]/

  # Copy the files boot/grub/grub.cfg and and isolinux/txt.cfg to your working directory
  cp source_files/boot/grub/grub.cfg .
  cp source-files/isolinux/txt.cfg .

  cat << EOF > /source-files/boot/grub/grub.cfg
set timeout=10
menuentry "Autoinstall Server (HWE Kernel, NVIDIA, NetworkManager)" {
	set gfxpayload=keep
	linux	/casper/hwe-vmlinuz   quiet autoinstall button.lid_init_state=open ds=nocloud;s=/cdrom/server/ ---
	initrd	/casper/hwe-initrd
}
EOF
}

create_bootable_usb(){
  IMAGE_DIR="/home/max/Desktop/repos/ark8de/usb"
  IMAGE_FILE="Ubuntu.iso"

  # be aware hadware changes the names of this shit
  # sd = sata/scsi/cd/dvd
  # hdb = IDE
  # fd = floppy

  # im making the assumption that it will be the only other disk
  DISK_NAME="/dev/sdb"
  
  # unmount the disk
  sudo umount "$DISK_NAME"

  ## dd the image to the drive

  sudo dd \
    bs=4M \
    if="$IMAGE_DIR"/"$IMAGE_FILE" \
    of="$DISK_NAME" \
    status=progress \
    oflag=sync
}

"$@"