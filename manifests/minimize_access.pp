# === Copyright
#
# Copyright 2014, Deutsche Telekom AG
# Licensed under the Apache License, Version 2.0 (the "License");
# http://www.apache.org/licenses/LICENSE-2.0
#

# == Class: os_hardening::minimize_access
#
# Configures profile.conf.
#
class os_hardening::minimize_access (
  Boolean $allow_change_user                    = false,
  Boolean $ignore_max_files_warnings            = false,
  Boolean $manage_home_permissions              = false,
  Boolean $manage_log_permissions               = false,
  Boolean $manage_cron_permissions              = false,
  Boolean $manage_system_users                  = true,
  Array   $always_ignore_users                  =
    ['root','sync','shutdown','halt'],
  Array   $ignore_users                         = [],
  Array   $ignore_home_users                    = [],
  Array   $ignore_restrict_log_dir              = [],
  Array   $ignore_files_in_folder_to_restrict   = [],
  Array   $folders_to_restrict                  =
    ['/usr/local/games','/usr/local/sbin','/usr/local/bin','/usr/bin','/usr/sbin','/sbin','/bin'],
  Array   $restrict_log_dir                     =
    ['/var/log/'],
  String  $shadowgroup                          = 'root',
  String  $shadowmode                           = '0600',
  Integer $recurselimit                         = 5,
) {

  case $::operatingsystem {
    redhat, fedora: {
      $nologin_path = '/sbin/nologin'
      $shadow_path = ['/etc/shadow', '/etc/gshadow']
    }
    debian, ubuntu, cumuluslinux: {
      $nologin_path = '/usr/sbin/nologin'
      $shadow_path = ['/etc/shadow', '/etc/gshadow']
    }
    default: {
      $nologin_path = '/sbin/nologin'
      $shadow_path = '/etc/shadow'
    }
  }

  # Whether $folders_to_restrict should issue warnings if the puppet max_files
  # file resource exceeds the default soft limit of 1000 on recursive file
  # resources, /bin and /usr/bin can exceed this default limit
  if $ignore_max_files_warnings {
    $use_max_files = -1
  } else {
    $use_max_files = 0
  }

  # remove write permissions from path folders ($PATH) for all regular users
  # this prevents changing any system-wide command from normal users
  ensure_resources ('file',
  { $folders_to_restrict => {
      ensure                  => directory,
      ignore                  => $ignore_files_in_folder_to_restrict,
      links                   => follow,
      mode                    => 'go-w',
      recurse                 => true,
      recurselimit            => $recurselimit,
      selinux_ignore_defaults => true,
      max_files               => $use_max_files,
    }
  })
# Added users with homes
  $homes_users = split($::home_users, ',')

# added ignore these homes
  $target_home_users = difference($homes_users, $ignore_home_users)

# added homes to restrict
if $manage_home_permissions == true {
  ensure_resources ('file',
  { $target_home_users => {
      ensure       => directory,
      links        => follow,
      mode         => 'g-w,o-rwx',
      recurse      => true,
      recurselimit => $recurselimit,
    }
  })
}

# ensure log folders have right permissions
if $manage_log_permissions == true {
  ensure_resources ('file',
  { $restrict_log_dir => {
      ensure       => directory,
      ignore       => $ignore_restrict_log_dir,
      links        => follow,
      mode         => 'g-wx,o-rwx',
      recurse      => true,
      recurselimit => $recurselimit,
    }
  })
}

# ensure crontab have right permissions
if $manage_cron_permissions == true {

  $cronfiles = [ '/etc/anacrontab', '/etc/crontab' ]
  $cronfiles.each |String $cronfile| {
    if ($::existing[$cronfile]) {
      file { $cronfile:
        ensure => file,
        mode   => 'og-rwx',
        owner  => 'root',
        group  => 'root',
      }
    }
  }

# ensure cron hourly have right permissions
  ensure_resources ('file',
  { '/etc/cron.hourly' => {
      ensure       => directory,
      mode         => 'og-rwx',
      owner        => 'root',
      group        => 'root',
      links        => follow,
      recurse      => true,
      recurselimit => $recurselimit,
    }
  })

# ensure cron daily have right permissions
  ensure_resources ('file',
  { '/etc/cron.daily' => {
      ensure       => directory,
      mode         => 'og-rwx',
      owner        => 'root',
      group        => 'root',
      links        => follow,
      recurse      => true,
      recurselimit => $recurselimit,
    }
  })

# ensure cron weekly have right permissions
  ensure_resources ('file',
  { '/etc/cron.weekly' => {
      ensure       => directory,
      mode         => 'og-rwx',
      owner        => 'root',
      group        => 'root',
      links        => follow,
      recurse      => true,
      recurselimit => $recurselimit,
    }
  })

# ensure cron monthly have right permissions
  ensure_resources ('file',
  { '/etc/cron.monthly' => {
      ensure       => directory,
      mode         => 'og-rwx',
      owner        => 'root',
      group        => 'root',
      links        => follow,
      recurse      => true,
      recurselimit => $recurselimit,
    }
  })

# ensure cron.d have right permissions
  ensure_resources ('file',
  { '/etc/cron.d' => {
      ensure       => directory,
      mode         => 'og-rwx',
      owner        => 'root',
      group        => 'root',
      links        => follow,
      recurse      => true,
      recurselimit => $recurselimit,
    }
  })

# ensure cron.deny and at.deny is absent
  file { '/etc/cron.deny':
    ensure => absent,
  }

  file { '/etc/at.deny':
    ensure       => absent,
  }

# ensure cron.allow is there
  file { '/etc/cron.allow':
    ensure => present,
    owner  => 'root',
    group  => 'root',
    mode   => 'og-rwx',
  }

# ensure at.allow is there
  file { '/etc/at.allow':
    ensure => present,
    owner  => 'root',
    group  => 'root',
    mode   => 'og-rwx',
  }
}

  # shadow must only be accessible to user root
  file { $shadow_path:
    ensure => file,
    owner  => 'root',
    group  => $shadowgroup,
    mode   => $shadowmode,
  }

  # su must only be accessible to user and group root
  if $allow_change_user == false {
    file { '/bin/su':
      ensure => file,
      links  => follow,
      owner  => 'root',
      group  => 'root',
      mode   => '0750',
    }
  } else {
    file { '/bin/su':
      ensure => file,
      links  => follow,
      owner  => 'root',
      group  => 'root',
      mode   => '4755',
    }
  }

  if $manage_system_users == true {
    # retrieve system users through custom fact
    $system_users = split($::retrieve_system_users, ',')

    # build array of usernames we need to verify/change
    $ignore_users_arr = union($always_ignore_users, $ignore_users)

    # build a target array with usernames to verify/change
    $target_system_users = difference($system_users, $ignore_users_arr)

    # ensure accounts are locked (no password) and use nologin shell
    user { $target_system_users:
      ensure   => present,
      shell    => $nologin_path,
      password => '*',
    }
  }
}
