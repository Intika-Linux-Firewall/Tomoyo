#! /bin/bash

RPM_BUILD_DIR="/root/rpmbuild"
SOURCEDIR="/tmp"
URL_CCS="http://sourceforge.jp/frs/redir.php?f=/tomoyo/49684"
URL_CCS_SVN="http://sourceforge.jp/projects/tomoyo/svn/view/trunk/1.8.x/ccs-patch/patches"
COLOUR=0 # set to 1 for coloured output

CCS_VER="1.8.2"
CCSPATCH_VER="1.8.2-20110707"
KERNEL_VER="2.6.38.8-35.fc15"

UPDATED_DIFF=0
CCSDIFF_NAME="ccs-patch-2.6.38-fedora-15.diff"

# only required if using updated revision
#UPDATED_DIFF=1
#CCSDIFF_NAME="ccs-patch-2.6.38-fedora-15-20110526-1.8.1.diff"
#CCSDIFF_REVISION="ccs-patch-2.6.38-fedora-15.diff?revision=5059&root=tomoyo"

# stuff that probably will not be changed much
# {{{
if tput setaf 0 &>/dev/null; then
	ALL_OFF="$(tput sgr0)"
	BOLD="$(tput bold)"
	GREEN="${BOLD}$(tput setaf 2)"
	RED="${BOLD}$(tput setaf 1)"
else
	ALL_OFF="\e[1;0m"
	BOLD="\e[1;1m"
	GREEN="${BOLD}\e[1;32m"
	RED="${BOLD}\e[1;31m"
fi

msg() {
	if [[ "${COLOUR}" = 1 ]]; then
    	printf '%s\n' "${GREEN}==>${ALL_OFF}${BOLD} ${@}${ALL_OFF}" >&2
	else
	    printf '%s\n' "==> ${@}" >&2
	fi
}
error() {
	if [[ "${COLOUR}" = 1 ]]; then
    	printf '%s\n' "${RED}==>${ALL_OFF}${BOLD} ${@}${ALL_OFF}" >&2
	else
    	printf '%s\n' "==> ${@}" >&2
	fi
	exit 1
}

#################################
#if ! whereis rpmdev-wipetree >/dev/null; then
#	error "ERROR: rpmdevtools package not installed"
#fi
#
#if ! whereis yumdownloader >/dev/null; then
#	error "ERROR: yum-utils package not installed"
#fi
#
#msg "Setting up a clean rpmbuild tree ..."
#rpmdev-wipetree || error "ERROR: rpmbuild tree wipe failed"
#rpmdev-setuptree || error "ERROR: rpmbuild tree setup failed"
#################################

msg "Entering '${SOURCEDIR}' directory ..."
cd "${SOURCEDIR}" || error "ERROR: chdir to '${SOURCEDIR}' failed"

if [[ ! -e ccs-patch-${CCSPATCH_VER}.tar.gz ]]; then
	msg "Downloading ccs-patch source ..."
    wget -O "ccs-patch-${CCSPATCH_VER}.tar.gz" \
		"${URL_CCS}/ccs-patch-${CCSPATCH_VER}.tar.gz" \
		|| error "ERROR: ccs-patch source download failed"
fi

if [[ "${UPDATED_DIFF}" = 1 && ! -e ${CCSDIFF_NAME} ]]; then
	msg "Downloading ccs-patch diff ..."
    wget -O "${CCSDIFF_NAME}" \
		"${URL_CCS_SVN}/${CCSDIFF_REVISION}" \
		|| error "ERROR: ccs-patch diff download failed"
fi

if [[ ! -e "kernel-${KERNEL_VER}.src.rpm" ]]; then
	msg "Downloading kernel SRPM ..."
    wget "http://ftp.riken.jp/Linux/fedora/updates/15/SRPMS/kernel-${KERNEL_VER}.src.rpm" \
		|| error "ERROR: kernel SRPM download failed"
	# alternatively use this command (from yum-utils package) to download the latest
	# kernel source from an appropriate mirror, but will cause error if ${KERNEL_VER}
	# does not match the kernel version that is downloaded.
	#yumdownloader --source kernel || error "ERROR: kernel SRPM download failed"
fi

msg "Waiting 10 seconds ..."
read -t 10 -r -e -p "Run yum-builddep [y/N]?: " builddep
if [[ "${builddep}" = "y" || "${builddep}" = "Y" ]]; then
	msg "Installing build dependencies ..."
	su -c "yum-builddep kernel-${KERNEL_VER}.src.rpm" || "ERROR: dependency installation failed"
fi

msg "Verifying signature for kernel SRPM ..."
rpm --checksig "kernel-${KERNEL_VER}.src.rpm" || error "ERROR: signature verification failed"

msg "Installing kernel SRPM ..."
rpm -ivh "kernel-${KERNEL_VER}.src.rpm" || error "ERROR: kernel SRPM installation failed"

msg "Copying sources to '${RPM_BUILD_DIR}/SOURCES' directory ..."
cp -vp "ccs-patch-${CCSPATCH_VER}.tar.gz" "${CCSDIFF_NAME}" "${RPM_BUILD_DIR}/SOURCES/"

msg "Entering SPEC directory ..."
cd "${RPM_BUILD_DIR}/SPECS" || error "ERROR: chdir to '${RPM_BUILD_DIR}/SPECS' failed"

msg "Copying kernel.spec file ..."
cp -vp "kernel.spec" "ccs-kernel.spec" || error "ERROR: copy failed"
# }}}

patch_spec() {
	cat << "EOF"
--- ccs-kernel.spec
+++ ccs-kernel.spec
@@ -23,7 +23,7 @@
 #
 # (Uncomment the '#' and both spaces below to set the buildid.)
 #
-# % define buildid .local
+%define buildid _tomoyo_${CCS_VER}
 ###################################################################
 
 # The buildid can also be specified on the rpmbuild command line
@@ -427,6 +427,11 @@
 # to versions below the minimum
 #
 
+# TOMOYO Linux
+%define with_modsign 0
+%define _enable_debug_packages 0
+%define with_debuginfo 0
+
 #
 # First the general kernel 2.6 required versions as per
 # Documentation/Changes
@@ -486,7 +491,7 @@
 AutoProv: yes\
 %{nil}
 
-Name: kernel%{?variant}
+Name: ccs-kernel%{?variant}
 Group: System Environment/Kernel
 License: GPLv2
 URL: http://www.kernel.org/
@@ -870,7 +875,7 @@
 AutoReqProv: no\
 Requires(pre): /usr/bin/find\
 Requires: perl\
-%description -n kernel%{?variant}%{?1:-%{1}}-devel\
+%description -n ccs-kernel%{?variant}%{?1:-%{1}}-devel\
 This package provides kernel headers and makefiles sufficient to build modules\
 against the %{?2:%{2} }kernel package.\
 %{nil}
@@ -1397,6 +1402,10 @@
 
 # END OF PATCH APPLICATIONS
 
+# TOMOYO Linux
+tar -xzf %_sourcedir/ccs-patch-${CCSPATCH_VER}.tar.gz
+patch -sp1 < patches/${CCSDIFF_NAME}
+
 %endif
 
 # Any further pre-build tree manipulations happen here.
@@ -1425,6 +1434,9 @@
 for i in *.config
 do
   mv $i .config
+  # TOMOYO Linux
+  cat config.ccs >> .config
+  sed -i -e 's:CONFIG_DEBUG_INFO=.*:# CONFIG_DEBUG_INFO is not set:' -- .config
   Arch=`head -1 .config | cut -b 3-`
   make ARCH=$Arch listnewconfig | grep -E '^CONFIG_' >.newoptions || true
 %if %{listnewconfig_fail}
EOF
}

# before applying the patch, replace the placeholder variables with the real values
msg "Patching ccs-kernel.spec ..."
if [[ "${UPDATED_DIFF}" = 0 ]]; then
	patch_spec | sed -e "s#\${CCS_VER}#${CCS_VER}#g" \
		-e "s#\${CCSPATCH_VER}#${CCSPATCH_VER}#g" \
		-e "s#patches/\${CCSDIFF_NAME}#patches/${CCSDIFF_NAME}#g" | patch
elif [[ "${UPDATED_DIFF}" = 1 ]]; then
	patch_spec | sed -e "s#\${CCS_VER}#${CCS_VER}#g" \
		-e "s#\${CCSPATCH_VER}#${CCSPATCH_VER}#g" \
		-e "s#patches/\${CCSDIFF_NAME}#%_sourcedir/${CCSDIFF_NAME}#g" | patch
fi

[[ $? != 0 ]] && error "ERROR: patching ccs-kernel.spec failed"

msg "Waiting 10 seconds ..."
read -t 10 -r -e -p "View diff of spec files to check for errors [y/N]?: " view_diff
if [[ "${view_diff}" = "y" || "${view_diff}" = "Y" ]]; then
	diff -uNr kernel.spec ccs-kernel.spec | less
fi

ARCH="$(uname -m)"

printf '\n\n'
msg "Edit ${RPM_BUILD_DIR}/SPECS/ccs-kernel.spec if required."
printf '\n'
msg "To build the kernel RPM, run the following command:"
printf '\n'
printf '%s\n' "    rpmbuild -bb --target ${ARCH} --with baseonly \\"
printf '%s\n' "    --without debug --without debuginfo \\"
printf '%s\n' "    ${RPM_BUILD_DIR}/SPECS/ccs-kernel.spec"
printf '\n'

msg "Running rpmbuild -bb in 10 seconds ..."
sleep 10 && rpmbuild -bb --target ${ARCH} --with baseonly --without debug \
	--without debuginfo "${RPM_BUILD_DIR}/SPECS/ccs-kernel.spec"

exit 0
