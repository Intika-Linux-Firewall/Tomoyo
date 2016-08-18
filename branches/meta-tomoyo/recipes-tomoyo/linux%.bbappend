# This .bbappend file is intended for providing a hook for automatically
# enabling TOMOYO 2.5 when compiling a Linux kernel using bitbake.
# In order to automatically apply this hook as much as possible by appending
# meta-tomoyo repository regardless of the .bb file used for compiling
# a Linux kernel, this .bbappend file's filename is intentionally blurred.
# If either this hook is unintentionally applied or you know the .bb file's
# filename, please rename this .bbappend file's filename.

do_configure_append() {
  if [ -f .config ] && grep -qF CONFIG_SECURITY .config
  then
    (
      echo 'CONFIG_SECURITY=y'
      echo 'CONFIG_SECURITY_TOMOYO=y'
      echo 'CONFIG_DEFAULT_SECURITY_TOMOYO=y'
      echo '# CONFIG_DEFAULT_SECURITY_DAC is not set'
    ) >> .config
    yes '' | oe_runmake oldconfig
  fi
}
