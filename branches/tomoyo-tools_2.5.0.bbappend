# This .bbappend file is intended for providing an example content of /etc/tomoyo/
# directory which should be created by executing /usr/lib/tomoyo/init_policy .
# You can create this file as meta-tomoyo/recipes-tomoyo/tomoyo-tools_2.5.0.bbappend
# after downloading meta-tomoyo/recipes-tomoyo/tomoyo-tools_2.5.0.bb explained at
# https://tomoyo.osdn.jp/2.5/yocto-arm.html#step4 .

do_install_append() {
    mkdir -p ${D}/etc/tomoyo/
    cd ${D}/etc/tomoyo/ 
    NOW=`date '+%y-%m-%d.%H:%M:%S'`
    mkdir -p policy/$NOW
    ln -sf $NOW/ policy/current
    ln -sf $NOW/ policy/previous
    ln -sf policy/current/domain_policy.conf domain_policy.conf
    ln -sf policy/current/exception_policy.conf exception_policy.conf
    ln -sf policy/current/manager.conf manager.conf
    ln -sf policy/current/profile.conf profile.conf
    cat > domain_policy.conf << "EOF"
<kernel>
use_profile 1
use_group 0
EOF
    cat > exception_policy.conf << "EOF"
acl_group 0 file read /etc/ld.so.cache
acl_group 0 file read proc:/meminfo
acl_group 0 file read proc:/sys/kernel/version
acl_group 0 file read proc:/self/\*
acl_group 0 file read proc:/self/\{\*\}/\*
acl_group 0 file read /lib/lib\*.so\*
acl_group 0 file read /usr/lib/lib\*.so\*
acl_group 0 file read /lib/ld-2.\*.so
path_group ANY_PATHNAME /
path_group ANY_PATHNAME /\*
path_group ANY_PATHNAME /\{\*\}/
path_group ANY_PATHNAME /\{\*\}/\*
path_group ANY_PATHNAME \*:/
path_group ANY_PATHNAME \*:/\*
path_group ANY_PATHNAME \*:/\{\*\}/
path_group ANY_PATHNAME \*:/\{\*\}/\*
path_group ANY_PATHNAME \*:[\$]
path_group ANY_PATHNAME socket:[family=\$:type=\$:protocol=\$]
path_group ANY_DIRECTORY /
path_group ANY_DIRECTORY /\{\*\}/
path_group ANY_DIRECTORY \*:/
path_group ANY_DIRECTORY \*:/\{\*\}/
number_group COMMON_IOCTL_CMDS 0x5401
acl_group 0 file ioctl @ANY_PATHNAME @COMMON_IOCTL_CMDS
acl_group 0 file read @ANY_DIRECTORY
acl_group 0 file getattr @ANY_PATHNAME
initialize_domain /bin/busybox.nosuid from any
initialize_domain /etc/init.d/umountnfs.sh from any
initialize_domain /etc/init.d/single from any
initialize_domain /etc/init.d/sendsigs from any
initialize_domain /etc/init.d/bootmisc.sh from any
initialize_domain /etc/init.d/alignment.sh from any
initialize_domain /etc/init.d/reboot from any
initialize_domain /etc/init.d/sysfs.sh from any
initialize_domain /etc/init.d/udev-cache from any
initialize_domain /etc/init.d/halt from any
initialize_domain /etc/init.d/rcS from any
initialize_domain /etc/init.d/udev from any
initialize_domain /etc/init.d/hwclock.sh from any
initialize_domain /etc/init.d/psplash.sh from any
initialize_domain /etc/init.d/mountnfs.sh from any
initialize_domain /etc/init.d/modutils.sh from any
initialize_domain /etc/init.d/urandom from any
initialize_domain /etc/init.d/rmnologin.sh from any
initialize_domain /etc/init.d/dmesg.sh from any
initialize_domain /etc/init.d/save-rtc.sh from any
initialize_domain /etc/init.d/umountfs from any
initialize_domain /etc/init.d/dropbear from any
initialize_domain /etc/init.d/hostname.sh from any
initialize_domain /etc/init.d/bootlogd from any
initialize_domain /etc/init.d/mountall.sh from any
initialize_domain /etc/init.d/banner.sh from any
initialize_domain /etc/init.d/read-only-rootfs-hook.sh from any
initialize_domain /etc/init.d/devpts.sh from any
initialize_domain /etc/init.d/networking from any
initialize_domain /etc/init.d/populate-volatile.sh from any
initialize_domain /etc/init.d/rc from any
initialize_domain /etc/init.d/syslog.busybox from any
initialize_domain /etc/init.d/checkroot.sh from any
initialize_domain /bin/busybox.nosuid from any
initialize_domain /sbin/init.sysvinit from any
initialize_domain /bin/busybox.nosuid from any
initialize_domain /bin/busybox.nosuid from any
aggregator /etc/rc\?.d/\?\+\+urandom /etc/init.d/urandom
aggregator /etc/rc\?.d/\?\+\+networking /etc/init.d/networking
aggregator /etc/rc\?.d/\?\+\+dropbear /etc/init.d/dropbear
aggregator /etc/rc\?.d/\?\+\+save-rtc.sh /etc/init.d/save-rtc.sh
aggregator /etc/rc\?.d/\?\+\+halt /etc/init.d/halt
aggregator /etc/rc\?.d/\?\+\+psplash.sh /etc/init.d/psplash.sh
aggregator /etc/rc\?.d/\?\+\+umountnfs.sh /etc/init.d/umountnfs.sh
aggregator /etc/rc\?.d/\?\+\+syslog /etc/init.d/syslog.busybox
aggregator /etc/rc\?.d/\?\+\+umountfs /etc/init.d/umountfs
aggregator /etc/rc\?.d/\?\+\+sendsigs /etc/init.d/sendsigs
aggregator /etc/rc\?.d/\?\+\+hwclock.sh /etc/init.d/hwclock.sh
aggregator /etc/rc\?.d/\?\+\+mountnfs.sh /etc/init.d/mountnfs.sh
aggregator /etc/rc\?.d/\?\+\+dropbear /etc/init.d/dropbear
aggregator /etc/rc\?.d/\?\+\+syslog /etc/init.d/syslog.busybox
aggregator /etc/rc\?.d/\?\+\+rmnologin.sh /etc/init.d/rmnologin.sh
aggregator /etc/rc\?.d/\?\+\+networking /etc/init.d/networking
aggregator /etc/rc\?.d/\?\+\+hwclock.sh /etc/init.d/hwclock.sh
aggregator /etc/rc\?.d/\?\+\+stop-bootlogd /etc/init.d/bootlogd
aggregator /etc/rc\?.d/\?\+\+mountnfs.sh /etc/init.d/mountnfs.sh
aggregator /etc/rc\?.d/\?\+\+dropbear /etc/init.d/dropbear
aggregator /etc/rc\?.d/\?\+\+syslog /etc/init.d/syslog.busybox
aggregator /etc/rc\?.d/\?\+\+rmnologin.sh /etc/init.d/rmnologin.sh
aggregator /etc/rc\?.d/\?\+\+networking /etc/init.d/networking
aggregator /etc/rc\?.d/\?\+\+hwclock.sh /etc/init.d/hwclock.sh
aggregator /etc/rc\?.d/\?\+\+stop-bootlogd /etc/init.d/bootlogd
aggregator /etc/rc\?.d/\?\+\+mountnfs.sh /etc/init.d/mountnfs.sh
aggregator /etc/rc\?.d/\?\+\+dropbear /etc/init.d/dropbear
aggregator /etc/rc\?.d/\?\+\+syslog /etc/init.d/syslog.busybox
aggregator /etc/rc\?.d/\?\+\+rmnologin.sh /etc/init.d/rmnologin.sh
aggregator /etc/rc\?.d/\?\+\+networking /etc/init.d/networking
aggregator /etc/rc\?.d/\?\+\+hwclock.sh /etc/init.d/hwclock.sh
aggregator /etc/rc\?.d/\?\+\+stop-bootlogd /etc/init.d/bootlogd
aggregator /etc/rc\?.d/\?\+\+mountnfs.sh /etc/init.d/mountnfs.sh
aggregator /etc/rc\?.d/\?\+\+dropbear /etc/init.d/dropbear
aggregator /etc/rc\?.d/\?\+\+syslog /etc/init.d/syslog.busybox
aggregator /etc/rc\?.d/\?\+\+rmnologin.sh /etc/init.d/rmnologin.sh
aggregator /etc/rc\?.d/\?\+\+networking /etc/init.d/networking
aggregator /etc/rc\?.d/\?\+\+hwclock.sh /etc/init.d/hwclock.sh
aggregator /etc/rc\?.d/\?\+\+stop-bootlogd /etc/init.d/bootlogd
aggregator /etc/rc\?.d/\?\+\+urandom /etc/init.d/urandom
aggregator /etc/rc\?.d/\?\+\+reboot /etc/init.d/reboot
aggregator /etc/rc\?.d/\?\+\+networking /etc/init.d/networking
aggregator /etc/rc\?.d/\?\+\+dropbear /etc/init.d/dropbear
aggregator /etc/rc\?.d/\?\+\+save-rtc.sh /etc/init.d/save-rtc.sh
aggregator /etc/rc\?.d/\?\+\+psplash.sh /etc/init.d/psplash.sh
aggregator /etc/rc\?.d/\?\+\+umountnfs.sh /etc/init.d/umountnfs.sh
aggregator /etc/rc\?.d/\?\+\+syslog /etc/init.d/syslog.busybox
aggregator /etc/rc\?.d/\?\+\+umountfs /etc/init.d/umountfs
aggregator /etc/rc\?.d/\?\+\+sendsigs /etc/init.d/sendsigs
aggregator /etc/rc\?.d/\?\+\+hwclock.sh /etc/init.d/hwclock.sh
aggregator /etc/rc\?.d/\?\+\+urandom /etc/init.d/urandom
aggregator /etc/rc\?.d/\?\+\+udev /etc/init.d/udev
aggregator /etc/rc\?.d/\?\+\+psplash.sh /etc/init.d/psplash.sh
aggregator /etc/rc\?.d/\?\+\+checkroot.sh /etc/init.d/checkroot.sh
aggregator /etc/rc\?.d/\?\+\+bootmisc.sh /etc/init.d/bootmisc.sh
aggregator /etc/rc\?.d/\?\+\+dmesg.sh /etc/init.d/dmesg.sh
aggregator /etc/rc\?.d/\?\+\+bootlogd /etc/init.d/bootlogd
aggregator /etc/rc\?.d/\?\+\+banner.sh /etc/init.d/banner.sh
aggregator /etc/rc\?.d/\?\+\+sysfs.sh /etc/init.d/sysfs.sh
aggregator /etc/rc\?.d/\?\+\+populate-volatile.sh /etc/init.d/populate-volatile.sh
aggregator /etc/rc\?.d/\?\+\+hostname.sh /etc/init.d/hostname.sh
aggregator /etc/rc\?.d/\?\+\+mountall.sh /etc/init.d/mountall.sh
aggregator /etc/rc\?.d/\?\+\+alignment.sh /etc/init.d/alignment.sh
aggregator /etc/rc\?.d/\?\+\+read-only-rootfs-hook.sh /etc/init.d/read-only-rootfs-hook.sh
aggregator /etc/rc\?.d/\?\+\+udev-cache /etc/init.d/udev-cache
aggregator /etc/rc\?.d/\?\+\+devpts.sh /etc/init.d/devpts.sh
aggregator /etc/rc\?.d/\?\+\+modutils.sh /etc/init.d/modutils.sh
aggregator proc:/self/exe /proc/self/exe
EOF
    cat > manager.conf << "EOF"
/usr/sbin/tomoyo-loadpolicy
/usr/sbin/tomoyo-editpolicy
/usr/sbin/tomoyo-setlevel
/usr/sbin/tomoyo-setprofile
/usr/sbin/tomoyo-queryd
EOF
    cat > profile.conf << "EOF"
PROFILE_VERSION=20110903
0-COMMENT=-----Disabled Mode-----
0-PREFERENCE={ max_audit_log=1024 max_learning_entry=2048 }
0-CONFIG={ mode=disabled grant_log=no reject_log=yes }
1-COMMENT=-----Learning Mode-----
1-PREFERENCE={ max_audit_log=1024 max_learning_entry=2048 }
1-CONFIG={ mode=learning grant_log=no reject_log=yes }
2-COMMENT=-----Permissive Mode-----
2-PREFERENCE={ max_audit_log=1024 max_learning_entry=2048 }
2-CONFIG={ mode=permissive grant_log=no reject_log=yes }
3-COMMENT=-----Enforcing Mode-----
3-PREFERENCE={ max_audit_log=1024 max_learning_entry=2048 }
3-CONFIG={ mode=enforcing grant_log=no reject_log=yes }
EOF
    cat > stat.conf << "EOF"
# Memory quota (byte). 0 means no quota.
Memory used by policy:               0
Memory used by audit log:     16777216
Memory used by query message:  1048576
EOF
    mkdir -p tools
    cat > tools/auditd.conf << "EOF"
# This file contains sorting rules used by tomoyo-auditd command.

# An audit log consists with three lines. You can refer the first line
# using 'header' keyword, the second line using 'domain' keyword, and the
# third line using 'acl' keyword.
#
# Words in each line are separated by a space character. Therefore, you can
# use 'header[index]', 'domain[index]', 'acl[index]' for referring index'th
# word of the line. The index starts from 1, and 0 refers the whole line
# (i.e. 'header[0]' = 'header', 'domain[0]' = 'domain', 'acl[0]' = 'acl').
#
# Three operators are provided for conditional sorting.
# '.contains' is for 'fgrep keyword' match.
# '.equals' is for 'grep ^keyword$' match.
# '.starts' is for 'grep ^keyword' match.
#
# Sorting rules are defined using multi-lined chunks. A chunk is terminated
# by a 'destination' line which specifies the pathname to write the audit
# log. A 'destination' line is processed only when all preceding 'header',
# 'domain' and 'acl' lines in that chunk have matched.
# Evaluation stops at the first processed 'destination' line.
# Therefore, no audit logs are written more than once.
#
# More specific matches should be placed before less specific matches.
# For example:
#
# header.contains profile=3
# domain.contains /usr/sbin/httpd
# destination     /var/log/tomoyo/reject_003_httpd.log
#
# This chunk should be placed before the chunk that matches logs with
# profile=3. If placed after, the audit logs for /usr/sbin/httpd will be
# sent to /var/log/tomoyo/reject_003.log .

# Please use TOMOYO Linux's escape rule (e.g. '\040' rather than '\ ' for
# representing a ' ' in a word).

# Discard all granted logs.
header.contains granted=yes
destination     /dev/null

# Save rejected logs with profile=0 to /var/log/tomoyo/reject_000.log
header.contains profile=0
destination     /var/log/tomoyo/reject_000.log

# Save rejected logs with profile=1 to /var/log/tomoyo/reject_001.log
header.contains profile=1
destination     /var/log/tomoyo/reject_001.log

# Save rejected logs with profile=2 to /var/log/tomoyo/reject_002.log
header.contains profile=2
destination     /var/log/tomoyo/reject_002.log

# Save rejected logs with profile=3 to /var/log/tomoyo/reject_003.log
header.contains profile=3
destination     /var/log/tomoyo/reject_003.log

EOF
    cat > tools/notifyd.conf << "EOF"
# This file contains configuration used by tomoyo-notifyd command.

# tomoyo-notifyd is a daemon that notifies the occurrence of policy violation
# in enforcing mode.
#
# time_to_wait is grace time in second before rejecting the request that
# caused policy violation in enforcing mode. For example, if you specify
# 30, you will be given 30 seconds for starting tomoyo-queryd command and
# responding to the policy violation event.
# If you specify non 0 value, you need to register tomoyo-notifyd command to
# /sys/kernel/security/tomoyo/manager as well as tomoyo-queryd command, for tomoyo-notifyd needs to
# behave as if tomoyo-queryd command is running.
# Also, you should avoid specifying too large value (e.g. 3600) because
# the request will remain pending for that period if you can't respond.
#
# action_to_take is a command line you want to use for notification.
# The command specified by this parameter must read the policy violation
# notification from standard input. For example, mail, curl and xmessage
# commands can read from standard input.
# This parameter is passed to execve(). Thus, please use a wrapper program
# if you need shell processing (e.g. wildcard expansion, environment
# variables).
#
# minimal_interval is grace time in second before re-notifying the next
# occurrence of policy violation. You can specify 60 to limit notification
# to once per a minute, 3600 to limit notification to once per an hour.
# You can specify 0 to unlimit, but notifying of every policy violation
# events (e.g. sending a mail) might annoy you because policy violation
# can occur in clusters if once occurred.

# Please use TOMOYO Linux's escape rule (e.g. '\040' rather than '\ ' for
# representing a ' ' in a word).

# Examples:
#
# time_to_wait 180
# action_to_take mail admin@example.com
#
#    Wait for 180 seconds before rejecting the request.
#    The occurrence is notified by sending mail to admin@example.com
#    (if SMTP service is available).
#
# time_to_wait 0
# action_to_take curl --data-binary @- https://your.server/path_to_cgi
#
#    Reject the request immediately.
#    The occurrence is notified by executing curl command.
#
time_to_wait 0
action_to_take mail -s Notification\040from\040tomoyo-notifyd root@localhost
minimal_interval 60

EOF
    cat > tools/editpolicy.conf << "EOF"
# This file contains configuration used by tomoyo-editpolicy command.

# Keyword alias. ( directive-name = display-name )
keyword_alias acl_group   0                 = acl_group   0
keyword_alias acl_group   1                 = acl_group   1
keyword_alias acl_group   2                 = acl_group   2
keyword_alias acl_group   3                 = acl_group   3
keyword_alias acl_group   4                 = acl_group   4
keyword_alias acl_group   5                 = acl_group   5
keyword_alias acl_group   6                 = acl_group   6
keyword_alias acl_group   7                 = acl_group   7
keyword_alias acl_group   8                 = acl_group   8
keyword_alias acl_group   9                 = acl_group   9
keyword_alias acl_group  10                 = acl_group  10
keyword_alias acl_group  11                 = acl_group  11
keyword_alias acl_group  12                 = acl_group  12
keyword_alias acl_group  13                 = acl_group  13
keyword_alias acl_group  14                 = acl_group  14
keyword_alias acl_group  15                 = acl_group  15
keyword_alias acl_group  16                 = acl_group  16
keyword_alias acl_group  17                 = acl_group  17
keyword_alias acl_group  18                 = acl_group  18
keyword_alias acl_group  19                 = acl_group  19
keyword_alias acl_group  20                 = acl_group  20
keyword_alias acl_group  21                 = acl_group  21
keyword_alias acl_group  22                 = acl_group  22
keyword_alias acl_group  23                 = acl_group  23
keyword_alias acl_group  24                 = acl_group  24
keyword_alias acl_group  25                 = acl_group  25
keyword_alias acl_group  26                 = acl_group  26
keyword_alias acl_group  27                 = acl_group  27
keyword_alias acl_group  28                 = acl_group  28
keyword_alias acl_group  29                 = acl_group  29
keyword_alias acl_group  30                 = acl_group  30
keyword_alias acl_group  31                 = acl_group  31
keyword_alias acl_group  32                 = acl_group  32
keyword_alias acl_group  33                 = acl_group  33
keyword_alias acl_group  34                 = acl_group  34
keyword_alias acl_group  35                 = acl_group  35
keyword_alias acl_group  36                 = acl_group  36
keyword_alias acl_group  37                 = acl_group  37
keyword_alias acl_group  38                 = acl_group  38
keyword_alias acl_group  39                 = acl_group  39
keyword_alias acl_group  40                 = acl_group  40
keyword_alias acl_group  41                 = acl_group  41
keyword_alias acl_group  42                 = acl_group  42
keyword_alias acl_group  43                 = acl_group  43
keyword_alias acl_group  44                 = acl_group  44
keyword_alias acl_group  45                 = acl_group  45
keyword_alias acl_group  46                 = acl_group  46
keyword_alias acl_group  47                 = acl_group  47
keyword_alias acl_group  48                 = acl_group  48
keyword_alias acl_group  49                 = acl_group  49
keyword_alias acl_group  50                 = acl_group  50
keyword_alias acl_group  51                 = acl_group  51
keyword_alias acl_group  52                 = acl_group  52
keyword_alias acl_group  53                 = acl_group  53
keyword_alias acl_group  54                 = acl_group  54
keyword_alias acl_group  55                 = acl_group  55
keyword_alias acl_group  56                 = acl_group  56
keyword_alias acl_group  57                 = acl_group  57
keyword_alias acl_group  58                 = acl_group  58
keyword_alias acl_group  59                 = acl_group  59
keyword_alias acl_group  60                 = acl_group  60
keyword_alias acl_group  61                 = acl_group  61
keyword_alias acl_group  62                 = acl_group  62
keyword_alias acl_group  63                 = acl_group  63
keyword_alias acl_group  64                 = acl_group  64
keyword_alias acl_group  65                 = acl_group  65
keyword_alias acl_group  66                 = acl_group  66
keyword_alias acl_group  67                 = acl_group  67
keyword_alias acl_group  68                 = acl_group  68
keyword_alias acl_group  69                 = acl_group  69
keyword_alias acl_group  70                 = acl_group  70
keyword_alias acl_group  71                 = acl_group  71
keyword_alias acl_group  72                 = acl_group  72
keyword_alias acl_group  73                 = acl_group  73
keyword_alias acl_group  74                 = acl_group  74
keyword_alias acl_group  75                 = acl_group  75
keyword_alias acl_group  76                 = acl_group  76
keyword_alias acl_group  77                 = acl_group  77
keyword_alias acl_group  78                 = acl_group  78
keyword_alias acl_group  79                 = acl_group  79
keyword_alias acl_group  80                 = acl_group  80
keyword_alias acl_group  81                 = acl_group  81
keyword_alias acl_group  82                 = acl_group  82
keyword_alias acl_group  83                 = acl_group  83
keyword_alias acl_group  84                 = acl_group  84
keyword_alias acl_group  85                 = acl_group  85
keyword_alias acl_group  86                 = acl_group  86
keyword_alias acl_group  87                 = acl_group  87
keyword_alias acl_group  88                 = acl_group  88
keyword_alias acl_group  89                 = acl_group  89
keyword_alias acl_group  90                 = acl_group  90
keyword_alias acl_group  91                 = acl_group  91
keyword_alias acl_group  92                 = acl_group  92
keyword_alias acl_group  93                 = acl_group  93
keyword_alias acl_group  94                 = acl_group  94
keyword_alias acl_group  95                 = acl_group  95
keyword_alias acl_group  96                 = acl_group  96
keyword_alias acl_group  97                 = acl_group  97
keyword_alias acl_group  98                 = acl_group  98
keyword_alias acl_group  99                 = acl_group  99
keyword_alias acl_group 100                 = acl_group 100
keyword_alias acl_group 101                 = acl_group 101
keyword_alias acl_group 102                 = acl_group 102
keyword_alias acl_group 103                 = acl_group 103
keyword_alias acl_group 104                 = acl_group 104
keyword_alias acl_group 105                 = acl_group 105
keyword_alias acl_group 106                 = acl_group 106
keyword_alias acl_group 107                 = acl_group 107
keyword_alias acl_group 108                 = acl_group 108
keyword_alias acl_group 109                 = acl_group 109
keyword_alias acl_group 110                 = acl_group 110
keyword_alias acl_group 111                 = acl_group 111
keyword_alias acl_group 112                 = acl_group 112
keyword_alias acl_group 113                 = acl_group 113
keyword_alias acl_group 114                 = acl_group 114
keyword_alias acl_group 115                 = acl_group 115
keyword_alias acl_group 116                 = acl_group 116
keyword_alias acl_group 117                 = acl_group 117
keyword_alias acl_group 118                 = acl_group 118
keyword_alias acl_group 119                 = acl_group 119
keyword_alias acl_group 120                 = acl_group 120
keyword_alias acl_group 121                 = acl_group 121
keyword_alias acl_group 122                 = acl_group 122
keyword_alias acl_group 123                 = acl_group 123
keyword_alias acl_group 124                 = acl_group 124
keyword_alias acl_group 125                 = acl_group 125
keyword_alias acl_group 126                 = acl_group 126
keyword_alias acl_group 127                 = acl_group 127
keyword_alias acl_group 128                 = acl_group 128
keyword_alias acl_group 129                 = acl_group 129
keyword_alias acl_group 130                 = acl_group 130
keyword_alias acl_group 131                 = acl_group 131
keyword_alias acl_group 132                 = acl_group 132
keyword_alias acl_group 133                 = acl_group 133
keyword_alias acl_group 134                 = acl_group 134
keyword_alias acl_group 135                 = acl_group 135
keyword_alias acl_group 136                 = acl_group 136
keyword_alias acl_group 137                 = acl_group 137
keyword_alias acl_group 138                 = acl_group 138
keyword_alias acl_group 139                 = acl_group 139
keyword_alias acl_group 140                 = acl_group 140
keyword_alias acl_group 141                 = acl_group 141
keyword_alias acl_group 142                 = acl_group 142
keyword_alias acl_group 143                 = acl_group 143
keyword_alias acl_group 144                 = acl_group 144
keyword_alias acl_group 145                 = acl_group 145
keyword_alias acl_group 146                 = acl_group 146
keyword_alias acl_group 147                 = acl_group 147
keyword_alias acl_group 148                 = acl_group 148
keyword_alias acl_group 149                 = acl_group 149
keyword_alias acl_group 150                 = acl_group 150
keyword_alias acl_group 151                 = acl_group 151
keyword_alias acl_group 152                 = acl_group 152
keyword_alias acl_group 153                 = acl_group 153
keyword_alias acl_group 154                 = acl_group 154
keyword_alias acl_group 155                 = acl_group 155
keyword_alias acl_group 156                 = acl_group 156
keyword_alias acl_group 157                 = acl_group 157
keyword_alias acl_group 158                 = acl_group 158
keyword_alias acl_group 159                 = acl_group 159
keyword_alias acl_group 160                 = acl_group 160
keyword_alias acl_group 161                 = acl_group 161
keyword_alias acl_group 162                 = acl_group 162
keyword_alias acl_group 163                 = acl_group 163
keyword_alias acl_group 164                 = acl_group 164
keyword_alias acl_group 165                 = acl_group 165
keyword_alias acl_group 166                 = acl_group 166
keyword_alias acl_group 167                 = acl_group 167
keyword_alias acl_group 168                 = acl_group 168
keyword_alias acl_group 169                 = acl_group 169
keyword_alias acl_group 170                 = acl_group 170
keyword_alias acl_group 171                 = acl_group 171
keyword_alias acl_group 172                 = acl_group 172
keyword_alias acl_group 173                 = acl_group 173
keyword_alias acl_group 174                 = acl_group 174
keyword_alias acl_group 175                 = acl_group 175
keyword_alias acl_group 176                 = acl_group 176
keyword_alias acl_group 177                 = acl_group 177
keyword_alias acl_group 178                 = acl_group 178
keyword_alias acl_group 179                 = acl_group 179
keyword_alias acl_group 180                 = acl_group 180
keyword_alias acl_group 181                 = acl_group 181
keyword_alias acl_group 182                 = acl_group 182
keyword_alias acl_group 183                 = acl_group 183
keyword_alias acl_group 184                 = acl_group 184
keyword_alias acl_group 185                 = acl_group 185
keyword_alias acl_group 186                 = acl_group 186
keyword_alias acl_group 187                 = acl_group 187
keyword_alias acl_group 188                 = acl_group 188
keyword_alias acl_group 189                 = acl_group 189
keyword_alias acl_group 190                 = acl_group 190
keyword_alias acl_group 191                 = acl_group 191
keyword_alias acl_group 192                 = acl_group 192
keyword_alias acl_group 193                 = acl_group 193
keyword_alias acl_group 194                 = acl_group 194
keyword_alias acl_group 195                 = acl_group 195
keyword_alias acl_group 196                 = acl_group 196
keyword_alias acl_group 197                 = acl_group 197
keyword_alias acl_group 198                 = acl_group 198
keyword_alias acl_group 199                 = acl_group 199
keyword_alias acl_group 200                 = acl_group 200
keyword_alias acl_group 201                 = acl_group 201
keyword_alias acl_group 202                 = acl_group 202
keyword_alias acl_group 203                 = acl_group 203
keyword_alias acl_group 204                 = acl_group 204
keyword_alias acl_group 205                 = acl_group 205
keyword_alias acl_group 206                 = acl_group 206
keyword_alias acl_group 207                 = acl_group 207
keyword_alias acl_group 208                 = acl_group 208
keyword_alias acl_group 209                 = acl_group 209
keyword_alias acl_group 210                 = acl_group 210
keyword_alias acl_group 211                 = acl_group 211
keyword_alias acl_group 212                 = acl_group 212
keyword_alias acl_group 213                 = acl_group 213
keyword_alias acl_group 214                 = acl_group 214
keyword_alias acl_group 215                 = acl_group 215
keyword_alias acl_group 216                 = acl_group 216
keyword_alias acl_group 217                 = acl_group 217
keyword_alias acl_group 218                 = acl_group 218
keyword_alias acl_group 219                 = acl_group 219
keyword_alias acl_group 220                 = acl_group 220
keyword_alias acl_group 221                 = acl_group 221
keyword_alias acl_group 222                 = acl_group 222
keyword_alias acl_group 223                 = acl_group 223
keyword_alias acl_group 224                 = acl_group 224
keyword_alias acl_group 225                 = acl_group 225
keyword_alias acl_group 226                 = acl_group 226
keyword_alias acl_group 227                 = acl_group 227
keyword_alias acl_group 228                 = acl_group 228
keyword_alias acl_group 229                 = acl_group 229
keyword_alias acl_group 230                 = acl_group 230
keyword_alias acl_group 231                 = acl_group 231
keyword_alias acl_group 232                 = acl_group 232
keyword_alias acl_group 233                 = acl_group 233
keyword_alias acl_group 234                 = acl_group 234
keyword_alias acl_group 235                 = acl_group 235
keyword_alias acl_group 236                 = acl_group 236
keyword_alias acl_group 237                 = acl_group 237
keyword_alias acl_group 238                 = acl_group 238
keyword_alias acl_group 239                 = acl_group 239
keyword_alias acl_group 240                 = acl_group 240
keyword_alias acl_group 241                 = acl_group 241
keyword_alias acl_group 242                 = acl_group 242
keyword_alias acl_group 243                 = acl_group 243
keyword_alias acl_group 244                 = acl_group 244
keyword_alias acl_group 245                 = acl_group 245
keyword_alias acl_group 246                 = acl_group 246
keyword_alias acl_group 247                 = acl_group 247
keyword_alias acl_group 248                 = acl_group 248
keyword_alias acl_group 249                 = acl_group 249
keyword_alias acl_group 250                 = acl_group 250
keyword_alias acl_group 251                 = acl_group 251
keyword_alias acl_group 252                 = acl_group 252
keyword_alias acl_group 253                 = acl_group 253
keyword_alias acl_group 254                 = acl_group 254
keyword_alias acl_group 255                 = acl_group 255
keyword_alias address_group                 = address_group
keyword_alias aggregator                    = aggregator
keyword_alias capability                    = capability
keyword_alias deny_autobind                 = deny_autobind
keyword_alias file append                   = file append
keyword_alias file chgrp                    = file chgrp
keyword_alias file chmod                    = file chmod
keyword_alias file chown                    = file chown
keyword_alias file chroot                   = file chroot
keyword_alias file create                   = file create
keyword_alias file execute                  = file execute
keyword_alias file getattr                  = file getattr
keyword_alias file ioctl                    = file ioctl
keyword_alias file link                     = file link
keyword_alias file mkblock                  = file mkblock
keyword_alias file mkchar                   = file mkchar
keyword_alias file mkdir                    = file mkdir
keyword_alias file mkfifo                   = file mkfifo
keyword_alias file mksock                   = file mksock
keyword_alias file mount                    = file mount
keyword_alias file pivot_root               = file pivot_root
keyword_alias file read                     = file read
keyword_alias file rename                   = file rename
keyword_alias file rmdir                    = file rmdir
keyword_alias file symlink                  = file symlink
keyword_alias file truncate                 = file truncate
keyword_alias file unlink                   = file unlink
keyword_alias file unmount                  = file unmount
keyword_alias file write                    = file write
keyword_alias initialize_domain             = initialize_domain
keyword_alias ipc signal                    = ipc signal
keyword_alias keep_domain                   = keep_domain
keyword_alias misc env                      = misc env
keyword_alias network inet                  = network inet
keyword_alias network unix                  = network unix
keyword_alias no_initialize_domain          = no_initialize_domain
keyword_alias no_keep_domain                = no_keep_domain
keyword_alias no_reset_domain               = no_reset_domain
keyword_alias number_group                  = number_group
keyword_alias path_group                    = path_group
keyword_alias quota_exceeded                = quota_exceeded
keyword_alias reset_domain                  = reset_domain
keyword_alias task auto_domain_transition   = task auto_domain_transition
keyword_alias task auto_execute_handler     = task auto_execute_handler
keyword_alias task denied_execute_handler   = task denied_execute_handler
keyword_alias task manual_domain_transition = task manual_domain_transition
keyword_alias transition_failed             = transition_failed
keyword_alias use_group                     = use_group
keyword_alias use_profile                   = use_profile

# Line color. 0 = BLACK, 1 = RED, 2 = GREEN, 3 = YELLOW, 4 = BLUE, 5 = MAGENTA, 6 = CYAN, 7 = WHITE
line_color ACL_CURSOR       = 03
line_color ACL_HEAD         = 03
line_color DOMAIN_CURSOR    = 02
line_color DOMAIN_HEAD      = 02
line_color EXCEPTION_CURSOR = 06
line_color EXCEPTION_HEAD   = 06
line_color MANAGER_CURSOR   = 72
line_color MANAGER_HEAD     = 72
line_color STAT_CURSOR      = 03
line_color STAT_HEAD        = 03
line_color PROFILE_CURSOR   = 71
line_color PROFILE_HEAD     = 71
line_color DEFAULT_COLOR    = 70
EOF
    cat > tools/patternize.conf << "EOF"
# This file contains rewriting rules used by tomoyo-patternize command.

# Domain policy consists with domain declaration lines (which start with
# '<' ,) and acl declaration lines (which do not start with '<' ).
# You can refer the former using 'domain' keyword and the latter using 'acl'
# keyword.
#
# Words in each line are separated by a space character. Therefore, you can
# use 'domain[index]', 'acl[index]' for referring index'th word of the line.
# The index starts from 1, and 0 refers the whole line (i.e.
# 'domain[0]' = 'domain', 'acl[0]' = 'acl').
#
# Three operators are provided for conditional rewriting.
# '.contains' is for 'fgrep keyword' match.
# '.equals' is for 'grep ^keyword$' match.
# '.starts' is for 'grep ^keyword' match.
#
# Rewriting rules are defined using multi-lined chunks. A chunk is terminated
# by a 'rewrite' line which specifies old pattern and new pattern.
# A 'rewrite' line is evaluated only when all preceding 'domain' and 'acl'
# lines in that chunk have matched.
# Evaluation stops at first 'rewrite' line where a word matched old pattern.
# Therefore, no words are rewritten more than once.
#
# For user's convenience, new pattern can be omitted if old pattern is reused
# for new pattern.

# Please use TOMOYO Linux's escape rule (e.g. '\040' rather than '\ ' for
# representing a ' ' in a word).

# Files on proc filesystem.
rewrite path_pattern proc:/self/task/\$/fdinfo/\$
rewrite path_pattern proc:/self/task/\$/fd/\$
rewrite head_pattern proc:/self/task/\$/
rewrite path_pattern proc:/self/fdinfo/\$
rewrite path_pattern proc:/self/fd/\$
rewrite head_pattern proc:/self/
rewrite path_pattern proc:/\$/task/\$/fdinfo/\$
rewrite path_pattern proc:/\$/task/\$/fd/\$
rewrite head_pattern proc:/\$/task/\$/
rewrite path_pattern proc:/\$/fdinfo/\$
rewrite path_pattern proc:/\$/fd/\$
rewrite head_pattern proc:/\$/

# Files on devpts filesystem.
rewrite path_pattern devpts:/\$

# Files on pipe filesystem.
rewrite path_pattern pipe:[\$]
rewrite path_pattern pipefs:/[\$]

# Files on / partition.
rewrite tail_pattern /etc/mtab~\$
rewrite tail_pattern /etc/tomoyo/policy/\*/domain_policy.conf
rewrite tail_pattern /etc/tomoyo/policy/\*/exception_policy.conf
rewrite tail_pattern /etc/tomoyo/policy/\*/manager.conf
rewrite tail_pattern /etc/tomoyo/policy/\*/profile.conf
rewrite tail_pattern /etc/tomoyo/policy/\*/

# Files on /tmp/ partition.
rewrite tail_pattern /vte\?\?\?\?\?\?
rewrite tail_pattern /.ICE-unix/\$
rewrite tail_pattern /keyring-\?\?\?\?\?\?/socket.ssh
rewrite tail_pattern /orbit-\*/bonobo-activation-register-\X.lock
rewrite tail_pattern /orbit-\*/bonobo-activation-server-\X-ior
rewrite tail_pattern /orbit-\*/linc-\*
rewrite tail_pattern /orbit-\*/
rewrite tail_pattern /sh-thd-\$
rewrite tail_pattern /zman\?\?\?\?\?\?

# Files on home directory.
rewrite tail_pattern /.ICEauthority-\?
rewrite tail_pattern /.xauth\?\?\?\?\?\?
rewrite tail_pattern /.xauth\?\?\?\?\?\?-?
rewrite tail_pattern /.local/share/applications/preferred-mail-reader.desktop.\?\?\?\?\?\?
rewrite tail_pattern /.local/share/applications/preferred-web-browser.desktop.\?\?\?\?\?\?

# Files on /var/ partition.
rewrite tail_pattern /cache/fontconfig/\X-le64.cache-3
rewrite tail_pattern /lib/gdm/.pulse/\X-default-source
rewrite tail_pattern /lib/gdm/.pulse/\X-default-sink
rewrite tail_pattern /lib/gdm/.dbus/session-bus/\X-\X
rewrite tail_pattern /run/gdm/auth-for-\*/database-\?
rewrite tail_pattern /run/gdm/auth-for-\*/database
rewrite tail_pattern /run/gdm/auth-for-\*/
rewrite tail_pattern /spool/abrt/pyhook-\*/\{\*\}/\*
rewrite tail_pattern /spool/abrt/pyhook-\*/\{\*\}/

EOF
}
