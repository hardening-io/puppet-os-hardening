# == Class: os_hardening::suid_sgid
#
# Minimize SUID and SGID bits.
#
# === Copyright
#
# Copyright 2014, Deutsche Telekom AG
#
class os_hardening::suid_sgid (
  $whitelist = [],
  $blacklist = [],
  $remove_from_unknown = false,
  $dry_run_on_unkown = false,
){

  # suid and sgid blacklists and whitelists
  # ---------------------------------------
  # don't change values in the system_blacklist/whitelist
  # adjust values for blacklist/whitelist instead, they can override system_blacklist/whitelist

  # list of suid/sgid entries that must be removed
  $system_blacklist = [
  # blacklist as provided by NSA
  "/usr/bin/rcp", "/usr/bin/rlogin", "/usr/bin/rsh",
  # sshd must not use host-based authentication (see ssh cookbook)
  "/usr/libexec/openssh/ssh-keysign",
  "/usr/lib/openssh/ssh-keysign",
  # misc others
  "/sbin/netreport",                                            # not normally required for user
  "/usr/sbin/usernetctl",                                       # modify interfaces via functional accounts
  # connecting to ...
  "/usr/sbin/userisdnctl",                                      # no isdn...
  "/usr/sbin/pppd",                                             # no ppp / dsl ...
  # lockfile
  "/usr/bin/lockfile",
  "/usr/bin/mail-lock",
  "/usr/bin/mail-unlock",
  "/usr/bin/mail-touchlock",
  "/usr/bin/dotlockfile",
  # need more investigation, blacklist for now
  "/usr/bin/arping",
  "/usr/sbin/uuidd",
  "/usr/bin/mtr",                                               # investigate current state...
  "/usr/lib/evolution/camel-lock-helper-1.2",                   # investigate current state...
  "/usr/lib/pt_chown",                                          # pseudo-tty, needed?
  "/usr/lib/eject/dmcrypt-get-device",
  "/usr/lib/mc/cons.saver"                                      # midnight commander screensaver
  ]

  # list of suid/sgid entries that can remain untouched
  $system_whitelist = [
  # whitelist as provided by NSA
  "/bin/mount", "/bin/ping", "/bin/su", "/bin/umount", "/sbin/pam_timestamp_check",
  "/sbin/unix_chkpwd", "/usr/bin/at", "/usr/bin/gpasswd", "/usr/bin/locate",
  "/usr/bin/newgrp", "/usr/bin/passwd", "/usr/bin/ssh-agent", "/usr/libexec/utempter/utempter", "/usr/sbin/lockdev",
  "/usr/sbin/sendmail.sendmail", "/usr/bin/expiry",
  # whitelist ipv6
  "/bin/ping6","/usr/bin/traceroute6.iputils",
  # whitelist nfs
  "/sbin/mount.nfs", "/sbin/umount.nfs",
  # whitelist nfs4
  "/sbin/mount.nfs4", "/sbin/umount.nfs4",
  # whitelist cron
  "/usr/bin/crontab",
  # whitelist consolemssaging
  "/usr/bin/wall", "/usr/bin/write",
  # whitelist: only SGID with utmp group for multi-session access
  #            impact is limited; installation/usage has some remaining risk
  "/usr/bin/screen",
  # whitelist locate
  "/usr/bin/mlocate",
  # whitelist usermanagement
  "/usr/bin/chage", "/usr/bin/chfn", "/usr/bin/chsh",
  # whitelist fuse
  "/bin/fusermount",
  # whitelist pkexec
  "/usr/bin/pkexec",
  # whitelist sudo
  "/usr/bin/sudo","/usr/bin/sudoedit",
  # whitelist postfix
  "/usr/sbin/postdrop","/usr/sbin/postqueue",
  # whitelist apache
  "/usr/sbin/suexec",
  # whitelist squid
  "/usr/lib/squid/ncsa_auth", "/usr/lib/squid/pam_auth",
  # whitelist kerberos
  "/usr/kerberos/bin/ksu",
  # whitelist pam_caching
  "/usr/sbin/ccreds_validate",
  # whitelist Xorg
  "/usr/bin/Xorg",                                              # xorg
  "/usr/bin/X",                                                 # xorg
  "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",                # freedesktop ipc
  "/usr/lib/vte/gnome-pty-helper",                              # gnome
  "/usr/lib/libvte9/gnome-pty-helper",                          # gnome
  "/usr/lib/libvte-2.90-9/gnome-pty-helper"                     # gnome
  ]

  $final_blacklist = combine_sugid_lists($system_blacklist, $whitelist, $blacklist)
  $final_whitelist = combine_sugid_lists($system_whitelist, $blacklist, $whitelist)

  define blacklistFiles {
    exec{ "remove suid/sgid bit from $name":
      command => "/bin/chmod ug-s $name",
      onlyif => "/usr/bin/test -f $name",
    }
  }

  blacklistFiles{ $final_blacklist: }

  if $remove_from_unknown {
    # create a helper script
    # TODO: do without
    file { '/usr/local/sbin/remove_suids':
      ensure => file,
      owner  => root,
      group  => root,
      mode   => 500,
      content => template('os_hardening/remove_sugid_bits.erb'),
    }
    ->
    # remove all bits
    exec { 'remove SUID/SGID bits from unkown':
      command => '/usr/local/sbin/remove_suids'
    }
  }

}
