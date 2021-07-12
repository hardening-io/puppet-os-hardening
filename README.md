# Puppet OS hardening

[![Puppet Forge Version](https://img.shields.io/puppetforge/v/hardening/os_hardening.svg)][1]
[![Puppet Forge Downloads](https://img.shields.io/puppetforge/dt/hardening/os_hardening.svg)][1]
[![Puppet Forge Endorsement](https://img.shields.io/puppetforge/e/hardening/os_hardening.svg)][1]
[![Build Status](https://github.com/dev-sec/puppet-os-hardening/workflows/tests/badge.svg)][2]

#### Table of Contents

1. [Module Description - What the module does and why it is useful](#module-description)
1. [Setup - The basics of getting started with os_hardening](#setup)
   * [Setup Requirements](#setup-requirements)
   * [Beginning with os_hardening](#beginning-with-os_hardening)
1. [Usage - Configuration options and additional functionality](#usage)
   * [Important for Puppet Enterprise](#important-for-puppet-enterprise)
   * [Parameters](#parameters)
   * [Hiera usage](#hiera-usage)
   * [Note about wanted/unwanted packages and disabled services](#note-about-wantedunwanted-packages-and-disabled-services)
1. [Limitations - OS compatibility, etc.](#limitations)
1. [Development - Guide for contributing to the module](#development)
1. [Testing - Quality gates for your changes in the code](#testing)
   * [Local Testing](#local-testing)
   * [PDK Tests](#pdk-tests)
   * [Integration Tests (Docker)](#integration-tests-docker)
   * [Integration Tests (DigitalOcean)](#integration-tests-digitalocean)
   * [CI testing of PRs & forks](#ci-testing-of-prs--forks)
1. [Get in touch](#get-in-touch)
1. [Contributors + Kudos](#contributors--kudos)
1. [License and Author](#license-and-author)

## Module Description

This Puppet module provides secure configuration of your base OS with hardening and is part of the [DevSec Hardening Framework](https://dev-sec.io).

## Setup

### Setup Requirements

* Puppet OpenSource or Enterprise
* [Module stdlib](https://forge.puppet.com/puppetlabs/stdlib)
* [Module sysctl](https://forge.puppet.com/herculesteam/augeasproviders_sysctl)

### Beginning with os_hardening

After adding this module, you can use the class:

```puppet
class { 'os_hardening': }
```

All parameters are contained within the main `os_hardening` class, so you just have to pass them like this:

```puppet
class { 'os_hardening':
  enable_ipv4_forwarding => true,
}
```

## Usage

### IMPORTANT for Puppet Enterprise

**If you are using this module in a PE environment, you have to set** `pe_environment = true`
Otherwise puppet will drop an error (duplicate resource)!

### Parameters

* `system_environment = 'default'`
  define the context in which the system runs. Some options don't work for `docker`/`lxc`
* `pe_environment = false`
  set this to true if you are using Puppet Enterprise **IMPORTANT - see above**
* `extra_user_paths = []`
  add additional paths to the user's `PATH` variable (default is empty).
* `umask = undef`
  umask used for the creation of new home directories by useradd / newusers (e.g. '027')
* `maildir = undef`
  path for maildir (e.g. '/var/mail')
* `usergroups = true`
  true if you want separate groups for each user, false otherwise
* `sys_uid_min = undef` and `sys_gid_min = undef`
  override the default setting for `login.defs`
* `password_max_age = 60`
  maximum password age
* `password_min_age = 7`
  minimum password age (before allowing any other password change)
* `password_warn_age = 7`
  Days warning before password change is due
* `login_retries = 5`
  the maximum number of login retries if password is bad (normally overridden by PAM / auth_retries)
* `login_timeout = 60`
  authentication timeout in seconds, so login will exit if this time passes
* `chfn_restrict = ''`
  which fields may be changed by regular users using chfn
* `allow_login_without_home = false`
  true if to allow users without home to login
* `allow_change_user = false`
  if a user may use `su` to change his login
* `ignore_users = []`
  array of system user accounts that should _not be_ hardened (password disabled and shell set to `/usr/sbin/nologin`)
* `folders_to_restrict = ['/usr/local/games','/usr/local/sbin','/usr/local/bin','/usr/bin','/usr/sbin','/sbin','/bin']`
  folders to make sure of that group and world do not have write access to it or any of the contents
* `ignore_max_files_warnings = false`
  true if you do not want puppet to log max_files and performance warnings on the recursion of folders with > 1000 files eg /bin /usr/bin
* `recurselimit = 5`
  directory depth for recursive permission check
* `passwdqc_enabled = true`
  true if you want to use strong password checking in PAM using passwdqc
* `auth_retries = 5`
  the maximum number of authentication attempts, before the account is locked for some time
* `auth_lockout_time = 600`
  time in seconds that needs to pass, if the account was locked due to too many failed authentication attempts
* `passwdqc_options = 'min=disabled,disabled,16,12,8'`
  set to any option line (as a string) that you want to pass to passwdqc
* `manage_pam_unix = false`
  true if you want pam_unix managed by this module
* `enable_pw_history = true`
  true if you want pam_unix to remember password history to prevent reuse of passwords (requires `manage_pam_unix = true`)
* `pw_remember_last = 5`
  the number of last passwords (e.g. 5 will prevent user to reuse any of her last 5 passwords)
* `only_root_may_su = false`
  true when only root and member of the group wheel may use su, required to be true for CIS Benchmark compliance
* `root_ttys = ['console','tty1','tty2','tty3','tty4','tty5','tty6']`
  registered TTYs for root
* `whitelist = []`
  all files which should keep their SUID/SGID bits if set (will be combined with pre-defined whiteliste of files)
* `blacklist = []`
  all files which should have their SUID/SGID bits removed if set (will be combined with pre-defined blacklist of files)
* `remove_from_unknown = false`
  `true` if you want to remove SUID/SGID bits from any file, that is not explicitly configured in a `blacklist`. This will make every Puppet run search through the mounted filesystems looking for SUID/SGID bits that are not configured in the default and user blacklist. If it finds an SUID/SGID bit, it will be removed, unless this file is in your `whitelist`.
* `dry_run_on_unknown = false`
  like `remove_from_unknown` above, only that SUID/SGID bits aren't removed. It will still search the filesystems to look for SUID/SGID bits but it will only print them in your log. This option is only ever recommended, when you first configure `remove_from_unknown` for SUID/SGID bits, so that you can see the files that are being changed and make adjustments to your `whitelist` and `blacklist`.
* `enable_module_loading = true`
  true if you want to allowed to change kernel modules once the system is running (eg `modprobe`, `rmmod`)
* `load_modules = []`
  load this modules via initramfs if enable_module_loading is false
* `disable_filesystems = ['cramfs','freevxfs','jffs2','hfs','hfsplus','squashfs','udf']`
  array of filesystems (kernel modules) that should be disabled
* `cpu_vendor = 'intel'`
  only required if `enable_module_loading = false`: set the CPU vendor for modules to load
* `icmp_ratelimit = '100'`
  default value '100', allow overwriting, needs String
* `desktop_enabled = false`
  true if this is a desktop system, ie Xorg, KDE/GNOME/Unity/etc
* `enable_ipv4_forwarding = false`
  true if this system requires packet forwarding in IPv4 (eg Router), false otherwise
* `manage_ipv6 = true`
  true to harden ipv6 setup, false to ignore ipv6 completely
* `enable_ipv6 = false`
  false to disable ipv6 on this system, true to enable
* `enable_ipv6_forwarding = false`
  true if this system requires packet forwarding in IPv6 (eg Router), false otherwise
* `arp_restricted = true`
  true if you want the behavior of announcing and replying to ARP to be restricted, false otherwise
* `arp_ignore_samenet = false`
  true will drop packets that are not from the same subnet (arp_ignore = 2), false will only check the target ip (arp_ignore = 1)
* `enable_sysrq = false`
  true to enable the magic sysrq key, false otherwise
* `enable_core_dump = false`
  false to prevent the creation of core dumps, true otherwise
* `enable_stack_protection = true`
  for Address Space Layout Randomization. ASLR can help defeat certain types of buffer overflow attacks. ASLR can locate the base, libraries, heap, and stack at random positions in a process's address space, which makes it difficult for an attacking program to predict the memory address of the next instruction.
* `enable_rpfilter = true`
  true to enable reverse path filtering (discard bogus packets), false otherwise
* `rpfilter_loose = false`
  (only if `enable_rpfilter` is true) *loose mode* (rp_filter = 2) if true, *strict mode* otherwise
* `enable_log_martians = true`
  true to enable logging on suspicious / unroutable network packets, false otherwise **WARNING - this might generate huge log files!**
* `unwanted_packages = []`
  packages that should be removed from the system
* `wanted_packages = []`
  packages that should be added to the system
* `disabled_services = []`
  services that should not be enabled
* `enable_grub_hardening = false`
  set to true to enable some grub hardening rules
* `grub_user = 'root'`
  the grub username that needs to be provided when changing config on the grub prompt
* `grub_password_hash = ''`
  a password hash created with `grub-mkpasswd-pbkdf2` that is associated with the grub\_user
* `boot_without_password = true`
  setup Grub so it only requires a password when changing an entry, not when booting an existing entry
* `system_umask = undef`
  if this variable is set setup the umask for all user in the system (e.g. '027')
* `manage_home_permissions = false`
  set to true to manage local users file and directory permissions (g-w,o-rwx)
* `ignore_home_users = []`
  array for users that is not to be restricted by manage_home_permissions
* `manage_log_permissions = false`
  set to true to manage log file permissions (g-wx,o-rwx)
* `restrict_log_dir = ['/var/log/']`
  set main log dir
* `ignore_restrict_log_dir = []`
  array to exclude log dirs under the main log dir
* `ignore_files_in_folder_to_restrict = []`
  array to ignore files to hardened in dirs under the folder_to_restrict array
* `manage_cron_permissions = false`
  set to true to manage cron file permissions (og-rwx)
* `enable_sysctl_config = true`
  set to false to disable sysctl configuration
* `manage_system_users = true`
  set to false to disable managing of system users (empty password and setting nologin shell)

### Hiera usage

It's also possible to set the parameters in Hiera like this:

```puppet
os_hardening::password_max_age:  90
os_hardening::password_min_age:  0
os_hardening::password_warn_age: 14
os_hardening::unwanted_packages: ['telnet']
os_hardening::ignore_users:      ['git','githook','ansible','apache','puppetboard']
```

### Note about wanted/unwanted packages and disabled services

As the CIS Distribution Independent Linux Benchmark is a good starting point
regarding hardening of systems, it was deemed appropriate to implement an easy
way to deal with one-offs for which one doesn't want to write an entire module.

For instance, to increase CIS DIL compliance on a Debian system, one should set
the following:

```puppet
wanted_packages   => ['ntp'],
unwanted_packages => ['telnet'],
disabled_services => ['rsync'],
```

The default settings of NTP are actually pretty good for most situations, so it
is not immediately necessary to implement a module. However, if you do use a
module to control these services, that is of course preferred.

## Limitations

This module has been tested and should run on most Linux distributions. For an extensive list of supported operating systems, see [metadata.json](https://github.com/dev-sec/puppet-os-hardening/blob/master/metadata.json)

## Development

If you want to contribute, please follow our [contribution guide](https://dev-sec.io/contributing/).

## Testing

### Local Testing

You should have Ruby interpreter installed on your system. It might be a good idea to use [rvm](https://rvm.io) for that purpose. Besides that you have to install the `Puppet Development Kit` [PDK](https://puppet.com/download-puppet-development-kit) and [Docker Community Edition](https://www.docker.com/products/docker-engine), as the integration tests run in Docker containers.

For all our integration tests we use `test-kitchen`. If you are not familiar with `test-kitchen` please have a look at [their guide](http://kitchen.ci/docs/getting-started).

#### PDK Tests

```bash
# Syntax & Lint tests
pdk validate

# Unit Tests
pdk test unit
```

#### Integration Tests (Docker)

Per default the integration tests will run in docker containers - unfortunately not all tests can run in container environments (e.g. sysctl settings).

```bash
# Install dependencies
gem install bundler
bundle install

# list all test instances
bundle exec kitchen list

# fast test on one machine
bundle exec kitchen test ubuntu-16-04-puppet5

# test on all machines
bundle exec kitchen test
```

#### Integration Tests (DigitalOcean)

For complete integration tests with [DigitalOcean](https://cloud.digitalocean.com) you have to get an account there and setup some environment variables:

* `KITCHEN_LOCAL_YAML=kitchen.do.yml`
* `DIGITALOCEAN_ACCESS_TOKEN` - [access token for DigitalOcean](https://www.digitalocean.com/community/tutorials/how-to-use-the-digitalocean-api-v2)
* `DIGITALOCEAN_SSH_KEY_IDS` - ID in DigitalOcean of your ssh key, see [this](https://github.com/test-kitchen/kitchen-digitalocean#installation-and-setup) for more information

The ssh key has to be named `~/.ssh/do_ci` and added to your profile at DigitalOcean.
After this you're ready to run the tests as described at [Integration Tests (Docker)](#integration-tests-docker).

If you want to run the full integration tests with Github Actions in your fork, you will have to add these [environment variables](https://docs.github.com/en/actions/reference/encrypted-secrets) in the settings of your fork:

* `KITCHEN_LOCAL_YAML=kitchen.do.yml`
* `DIGITALOCEAN_ACCESS_TOKEN` - [access token for DigitalOcean](https://www.digitalocean.com/community/tutorials/how-to-use-the-digitalocean-api-v2)
* `CI_SSH_KEY` - private part of a ssh key, available on DigitalOcean for your instances, in base64 encoded form (e.g. `cat id_rsa | base64 -w0 ; echo`)
* `DIGITALOCEAN_SSH_KEY_IDS` - ID in DigitalOcean of `CI_SSH_KEY`, see [this](https://github.com/test-kitchen/kitchen-digitalocean#installation-and-setup) for more information

### CI testing of PRs & forks

Your patches will automatically get tested via Github Actions. The test summary is visible on Github in your PR, details can be found in the linked tests.

## Get in touch

You can reach us on several ways:

* [@DevSecIO](https://twitter.com/DevSecIO) on Twitter
* Mailing list for questions and general discussion: devsec@freelists.org [[subsribe]](https://www.freelists.org/list/devsec)
* Mailing list with release announcements (no posts are possible here): devsec-announce@freelists.org [[subscribe]](https://www.freelists.org/list/devsec-announce)

## Contributors + Kudos

* Dominik Richter [arlimus](https://github.com/arlimus)
* Edmund Haselwanter [ehaselwanter](https://github.com/ehaselwanter)
* Christoph Hartmann [chris-rock](https://github.com/chris-rock)
* Thomas Dütsch [a-tom](https://github.com/a-tom)
* Patrick Meier [atomic111](https://github.com/atomic111)
* Artem Sidorenko [artem-sidorenko](https://github.com/artem-sidorenko)
* Kurt Huwig [kurthuwig](https://github.com/kurthuwig)
* Matthew Haughton [3flex](https://github.com/3flex)
* Reik Keutterling [spielkind](https://github.com/spielkind)
* Daniel Dreier [danieldreier](https://github.com/danieldreier)
* Timo Goebel [timogoebel](https://github.com/timogoebel)
* Tristan Helmich [fadenb](https://github.com/fadenb)
* Michael Geiger [mcgege](https://github.com/mcgege)
* Timo Bergemann [LooOOooM](https://github.com/LooOOooM)

For the original port of `chef-os-hardening` to puppet:

* Artem Sidorenko [artem-sidorenko](https://github.com/artem-sidorenko)
* Frank Kloeker [eumel8](https://github.com/eumel8)

Thank you all!!

## License and Author

* Author:: Dominik Richter <dominik.richter@gmail.com>
* Author:: Deutsche Telekom AG

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

```
  http://www.apache.org/licenses/LICENSE-2.0
```

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

[1]: https://forge.puppet.com/hardening/os_hardening
[2]: https://github.com/dev-sec/puppet-os-hardening/workflows/tests
