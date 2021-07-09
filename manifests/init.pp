# === Copyright
#
# Copyright 2014, Deutsche Telekom AG
# Licensed under the Apache License, Version 2.0 (the "License");
# http://www.apache.org/licenses/LICENSE-2.0
#

# == Class: os_hardening
#
# Pulls in all manifests for os_hardening.
#
class os_hardening (
  String            $system_environment                 = 'default',
  Boolean           $pe_environment                     = false,

  Array             $extra_user_paths                   = [],
  Optional[String]  $umask                              = undef,
  Optional[String]  $maildir                            = undef,
  Boolean           $usergroups                         = true,
  Optional[Integer] $sys_uid_min                        = undef,
  Optional[Integer] $sys_gid_min                        = undef,
  Integer           $password_max_age                   = 60,
  Integer           $password_min_age                   = 7,
  Integer           $password_warn_age                  = 7,
  Integer           $login_retries                      = 5,
  Integer           $login_timeout                      = 60,
  String            $chfn_restrict                      = '',
  Boolean           $allow_login_without_home           = false,

  Boolean           $allow_change_user                  = false,
  Boolean           $manage_home_permissions            = false,
  Boolean           $manage_log_permissions             = false,
  Boolean           $manage_cron_permissions            = false,
  Boolean           $manage_system_users                = true,
  Array             $ignore_users                       = [],
  Array             $ignore_home_users                  = [],
  Array             $ignore_restrict_log_dir            = [],
  Array             $ignore_files_in_folder_to_restrict = [],
  Array             $folders_to_restrict                =
    ['/usr/local/games','/usr/local/sbin','/usr/local/bin','/usr/bin','/usr/sbin','/sbin','/bin'],
  Array             $restrict_log_dir                   =
    ['/var/log/'],
  Integer           $recurselimit                       = 5,

  Boolean           $passwdqc_enabled                   = true,
  Integer           $auth_retries                       = 5,
  Integer           $auth_lockout_time                  = 600,
  String            $passwdqc_options                   = 'min=disabled,disabled,16,12,8',
  Boolean           $manage_pam_unix                    = false,
  Boolean           $enable_pw_history                  = true,
  Integer           $pw_remember_last                   = 5,
  Boolean           $only_root_may_su                   = false,

  Array             $root_ttys                          =
    ['console','tty1','tty2','tty3','tty4','tty5','tty6'],

  Array             $whitelist                          = [],
  Array             $blacklist                          = [],
  Boolean           $remove_from_unknown                = false,
  Boolean           $dry_run_on_unknown                 = false,

  Boolean           $enable_module_loading              = true,
  Array             $load_modules                       = [],
  Array             $disable_filesystems                =
    ['cramfs','freevxfs','jffs2','hfs','hfsplus','squashfs','udf'],

  String            $cpu_vendor                         = 'intel',
  String            $icmp_ratelimit                     = '100',
  Boolean           $desktop_enabled                    = false,
  Boolean           $enable_ipv4_forwarding             = false,
  Boolean           $manage_ipv6                        = true,
  Boolean           $enable_ipv6                        = false,
  Boolean           $enable_ipv6_forwarding             = false,
  Boolean           $arp_restricted                     = true,
  Boolean           $arp_ignore_samenet                 = false,
  Boolean           $enable_sysrq                       = false,
  Boolean           $enable_core_dump                   = false,
  Boolean           $enable_stack_protection            = true,
  Boolean           $enable_rpfilter                    = true,
  Boolean           $rpfilter_loose                     = false,
  Boolean           $enable_log_martians                = true,

  Array             $unwanted_packages                  = [],
  Array             $wanted_packages                    = [],
  Array             $disabled_services                  = [],

  Boolean           $enable_grub_hardening              = false,
  String            $grub_user                          = 'root',
  String            $grub_password_hash                 = '',
  Boolean           $boot_without_password              = true,

  Boolean           $enable_sysctl_config               = true,

  Optional[String]  $system_umask                       = undef,
) {

  # Prepare
  # -------

  # system environment configuration
  # there may be differences when using kvm/lxc vs metal

  # Defaults for specific platforms
  case $::osfamily {
    'Debian','Suse': {
      $def_umask = '027'
      $def_sys_uid_min = 100
      $def_sys_gid_min = 100
      $shadowgroup = 'shadow'
      $shadowmode = '0640'
    }
    'RedHat': {
      $def_umask = '077'
      $def_sys_uid_min = 201
      $def_sys_gid_min = 201
      $shadowgroup = 'root'
      $shadowmode = '0000'
    }
    default: {
      $def_umask = '027'
      $def_sys_uid_min = 100
      $def_sys_gid_min = 100
      $shadowgroup = 'root'
      $shadowmode = '0600'
    }
  }

  # Merge defaults
  $merged_umask = pick($umask, $def_umask)
  $merged_sys_uid_min = pick($sys_uid_min, $def_sys_uid_min)
  $merged_sys_gid_min = pick($sys_gid_min, $def_sys_gid_min)

  # Fix for Puppet Enterprise
  if $pe_environment {
    # Don't redefine directory
    $folders_to_restrict_int = delete($folders_to_restrict, '/usr/local/bin')
  } else {
    $folders_to_restrict_int = $folders_to_restrict
  }


  # Install
  # -------
  class { 'os_hardening::limits':
    enable_core_dump => $enable_core_dump,
  }
  class { 'os_hardening::login_defs':
    extra_user_paths         => $extra_user_paths,
    umask                    => $merged_umask,
    maildir                  => $maildir,
    usergroups               => $usergroups,
    sys_uid_min              => $merged_sys_uid_min,
    sys_gid_min              => $merged_sys_gid_min,
    password_max_age         => $password_max_age,
    password_min_age         => $password_min_age,
    password_warn_age        => $password_warn_age,
    login_retries            => $login_retries,
    login_timeout            => $login_timeout,
    chfn_restrict            => $chfn_restrict,
    allow_login_without_home => $allow_login_without_home,
  }
  class { 'os_hardening::minimize_access':
    allow_change_user                  => $allow_change_user,
    manage_home_permissions            => $manage_home_permissions,
    manage_log_permissions             => $manage_log_permissions,
    manage_cron_permissions            => $manage_cron_permissions,
    manage_system_users                => $manage_system_users,
    ignore_users                       => $ignore_users,
    ignore_home_users                  => $ignore_home_users,
    ignore_restrict_log_dir            => $ignore_restrict_log_dir,
    ignore_files_in_folder_to_restrict => $ignore_files_in_folder_to_restrict,
    folders_to_restrict                => $folders_to_restrict_int,
    restrict_log_dir                   => $restrict_log_dir,
    shadowgroup                        => $shadowgroup,
    shadowmode                         => $shadowmode,
    recurselimit                       => $recurselimit,
  }
  class { 'os_hardening::modules':
    disable_filesystems   => $disable_filesystems,
  }
  class { 'os_hardening::pam':
    passwdqc_enabled  => $passwdqc_enabled,
    auth_retries      => $auth_retries,
    auth_lockout_time => $auth_lockout_time,
    passwdqc_options  => $passwdqc_options,
    manage_pam_unix   => $manage_pam_unix,
    enable_pw_history => $enable_pw_history,
    pw_remember_last  => $pw_remember_last,
    only_root_may_su  => $only_root_may_su,
  }
  class { 'os_hardening::profile':
    enable_core_dump => $enable_core_dump,
  }
  class { 'os_hardening::securetty':
    root_ttys => $root_ttys,
  }
  class { 'os_hardening::suid_sgid':
    whitelist           => $whitelist,
    blacklist           => $blacklist,
    remove_from_unknown => $remove_from_unknown,
    dry_run_on_unknown  => $dry_run_on_unknown,
  }

  if $enable_sysctl_config {
    class { 'os_hardening::sysctl':
      system_environment      => $system_environment,
      enable_module_loading   => $enable_module_loading,
      load_modules            => $load_modules,
      cpu_vendor              => $cpu_vendor,
      icmp_ratelimit          => $icmp_ratelimit,
      desktop_enabled         => $desktop_enabled,
      enable_ipv4_forwarding  => $enable_ipv4_forwarding,
      manage_ipv6             => $manage_ipv6,
      enable_ipv6             => $enable_ipv6,
      enable_ipv6_forwarding  => $enable_ipv6_forwarding,
      arp_restricted          => $arp_restricted,
      arp_ignore_samenet      => $arp_ignore_samenet,
      enable_sysrq            => $enable_sysrq,
      enable_core_dump        => $enable_core_dump,
      enable_stack_protection => $enable_stack_protection,
      enable_rpfilter         => $enable_rpfilter,
      rpfilter_loose          => $rpfilter_loose,
      enable_log_martians     => $enable_log_martians,
    }
  }

  class { 'os_hardening::services':
    unwanted_packages => $unwanted_packages,
    wanted_packages   => $wanted_packages,
    disabled_services => $disabled_services,
  }

  class { 'os_hardening::grub':
    enable                => $enable_grub_hardening,
    user                  => $grub_user,
    password_hash         => $grub_password_hash,
    boot_without_password => $boot_without_password,
  }

  class { 'os_hardening::umask':
    system_umask          => $system_umask,
  }
}
