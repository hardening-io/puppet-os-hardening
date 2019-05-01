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
  Boolean $allow_change_user   = false,
  Array   $always_ignore_users =
    ['root','sync','shutdown','halt'],
  Array   $ignore_users        = [],
# Added ignore home users
  Array   $ignore_home_users        = [],
  Array   $folders_to_restrict =
    ['/usr/local/games','/usr/local/sbin','/usr/local/bin','/usr/bin','/usr/sbin','/sbin','/bin'],
  String  $shadowgroup         = 'root',
  String  $shadowmode          = '0600',
  Integer $recurselimit        = 5,
) {

  case $::operatingsystem {
    redhat, fedora: {
      $nologin_path = '/sbin/nologin'
      $shadow_path = ['/etc/shadow', '/etc/gshadow']
    }
    debian, ubuntu: {
      $nologin_path = '/usr/sbin/nologin'
      $shadow_path = ['/etc/shadow', '/etc/gshadow']
    }
    default: {
      $nologin_path = '/sbin/nologin'
      $shadow_path = '/etc/shadow'
    }
  }

  # remove write permissions from path folders ($PATH) for all regular users
  # this prevents changing any system-wide command from normal users
  ensure_resources ('file',
  { $folders_to_restrict => {
      ensure       => directory,
      links        => follow,
      mode         => 'go-w',
      recurse      => true,
      recurselimit => $recurselimit,
    }
  })

# added users with homes
  $homes_users = split($::home_users, ',')

# added ignore these homes
  $target_home_users = difference($homes_users, $ignore_home_users)

# added homes to restrict
  ensure_resources ('file',
  { $target_home_users => {
      ensure       => directory,
      links        => follow,
      mode         => 'g-w,o-rwx',
      recurse      => true,
      recurselimit => $recurselimit,
    }
  })


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

