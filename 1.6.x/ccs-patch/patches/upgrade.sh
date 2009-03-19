#! /bin/sh
#
# This is a script for converting ccs-patch-\*.diff from 1.5.x and 1.6.x to 1.6.7 .
#
sed -e 's/extern struct domain_info KERNEL_DOMAIN;//' -e 's/domain_info/ccs_domain_info/g' -e 's/\&KERNEL_DOMAIN/NULL/g' -e 's/ifdef TOMOYO_SYS_PTRACE/if 1/' -e 's/TOMOYO_/CCS_/g' -e 's/tomoyo_flags/ccs_flags/g' -e 's/CONFIG_CCS/CONFIG_TOMOYO/'

exit

########## Steps to convert ##########

(1) Go to kernel source directory.

    # cd /path/to/kernel/source/

(2) Create patches directory.

    # mkdir patches

(3) Go to patches directory.

    # cd patches/

(4) Copy old patch (say, ccs-patch-old.diff ) to this directory.

    # cp -p /path/to/ccs-patch-old.diff .

(5) Apply this script and save the result (say, ccs-patch-new.diff ).

    # ./upgrade.sh < ccs-patch-old.diff > ccs-patch-new.diff

(6) Write filename of new patch.

    # echo ccs-patch-new.diff > series

(6) Go to parent directory.

    # cd ..

(7) Apply new patch.

    # quilt push

(8) Insert ccs_check_ioctl_permission hook manually.

    If you are using kernel 2.6.x , open fs/ioctl.c and fs/compat*.c and edit like

 	error = security_file_ioctl(filp, cmd, arg);
+	/***** TOMOYO Linux start. *****/
+	if (!error)
+		error = ccs_check_ioctl_permission(filp, cmd, arg);
+	/***** TOMOYO Linux end. *****/
 	if (error)
 		goto out_fput;

    If you are using kernel 2.4.x , open fs/ioctl.c and edit like

 	filp = fget(fd);
 	if (!filp)
 		goto out;
+	/***** TOMOYO Linux start. *****/
+	error = ccs_check_ioctl_permission(filp, cmd, arg);
+	if (error) {
+		fput(filp);
+		goto out;
+	}
+	/***** TOMOYO Linux end. *****/
 	error = 0;
 	lock_kernel();
 	switch (cmd) {

(9) Refresh new patch.

    # quilt refresh

(10) Save refreshed new patch.

    # cp -p patches/ccs-patch-new.diff /path/to/save/patch/
