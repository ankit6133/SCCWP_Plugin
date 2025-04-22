#!/bin/bash
#
# Installer for Sysdig Agent
# www.draios.com
#
# (c) 2013-2015 Sysdig Inc.
#

set -eo pipefail

AGENT_DRIVER_VARNAME=SYSDIG_AGENT_DRIVER
REPOSITORY_NAME=stable
DOWNLOAD_PATH=https://download.sysdig.com/stable
GPG_PUBLIC_KEY=https://download.sysdig.com/DRAIOS-GPG-KEY.public
DOWNLOAD_PATH_DEB=${DOWNLOAD_PATH}/deb
DOWNLOAD_PATH_RPM=${DOWNLOAD_PATH}/rpm/draios.repo


function install_rpm {
  if ! hash curl >/dev/null 2>&1; then
    echo "* Installing curl"
    yum -q -y install curl
  fi

  # Only install kernel headers in the case of kmod or legacy ebpf
  if ! $UNIVERSAL_EBPF; then
    echo "* Installing kernel headers"
    KERNEL_VERSION=$(uname -r)
    if [[ $KERNEL_VERSION == *PAE* ]]; then
      yum -q -y install kernel-PAE-devel-${KERNEL_VERSION%.PAE} || kernel_warning
    elif [[ $KERNEL_VERSION == *stab* ]]; then
      # It's OpenVZ kernel and we should install another package
      yum -q -y install vzkernel-devel-$KERNEL_VERSION || kernel_warning
    elif [[ $KERNEL_VERSION == *uek* ]]; then
      yum -q -y install kernel-uek-devel-$KERNEL_VERSION || kernel_warning
    else
      yum -q -y install kernel-devel-$KERNEL_VERSION || kernel_warning
    fi
  fi

  # We need DKMS to build the kernel module (but it is not needed for the eBPF probe)
  if ! $LEGACY_EBPF && ! $UNIVERSAL_EBPF; then
    if [[ $1 != *"al202"* ]]; then
      # AL202x doesn't need EPEL for dkms
      echo "* Evaluating whether EPEL repository is needed for DKMS"
      if ! yum -q list dkms >/dev/null 2>&1; then
        echo "* Installing EPEL repository (for DKMS)."
        for i in {1..5}; do
          if [ $VERSION -eq 9 ] && ([ $DISTRO == "rocky" ] || [ $DISTRO == "almalinux" ]); then
            dnf config-manager --set-enabled crb
            dnf install epel-release -y && break
          elif [ $VERSION -eq 9 ]; then
            rpm --quiet -i https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm && break
          elif [ $VERSION -eq 8 ] && ([ $DISTRO == "rocky" ] || [ $DISTRO == "almalinux" ]); then
            dnf config-manager --set-enabled powertools
            dnf install epel-release -y && break
          elif [ $DISTRO == "euler" ]; then
            yum install -y elfutils-libelf-devel
            rpm --quiet -i https://dl.fedoraproject.org/pub/archive/epel/7/$(uname -m)/Packages/d/dkms-2.7.1-1.el7.noarch.rpm && break
          elif [ $VERSION -eq 8 ]; then
            rpm --quiet -i https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm && break
          elif [ $VERSION -eq 7 ]; then
            rpm --quiet -i https://archives.fedoraproject.org/pub/archive/epel/7/${ARCH}/Packages/e/epel-release-7-14.noarch.rpm && break
          else
            rpm --quiet -i https://archives.fedoraproject.org/pub/archive/epel/6/i386/epel-release-6-8.noarch.rpm && break
          fi
          if [ $i -eq 5 ]; then
            echo "* Failed at installing the EPEL repository. Exiting script."
            exit 1
          fi
        done
      fi
    fi
    echo "* Installing DKMS"
    yum -q -y install dkms
  fi

  echo "* Installing Sysdig public key"
  rpm --quiet --import "${GPG_PUBLIC_KEY}"
  echo "* Installing Sysdig repository"
  curl -sf -o /etc/yum.repos.d/draios.repo "${DOWNLOAD_PATH_RPM}"

  # Append version suffix if requested
  if [ ! -z "$AGENT_VERSION" ]; then
    CMDLINE=""
    for pkg in ${AGENT_ALL_PACKAGES}; do
      CMDLINE="${CMDLINE} ${pkg}-${AGENT_VERSION}"
    done
  else
    CMDLINE="${AGENT_PACKAGE}"
  fi
  echo "* Installing Sysdig Agent [${CMDLINE}]"
  yum -q -y install ${CMDLINE}

  INIT_CONF=/etc/sysconfig/dragent
}

function install_dkms_from_source {
  local DKMS_VERSION=2.2.0.3 # DKMS version compatible with SLES 12
  local DKMS_TMPDIR="$(mktemp -d)"
  trap "rm -rf -- \"${DKMS_TMPDIR}\"" EXIT
  pushd "$DKMS_TMPDIR" >/dev/null
  curl -sfL https://github.com/dell/dkms/archive/refs/tags/v$DKMS_VERSION.tar.gz | tar -zx
  pushd dkms-$DKMS_VERSION >/dev/null
  make install-redhat
  popd >/dev/null
  popd >/dev/null
  rm -rf -- "${DKMS_TMPDIR}"
  trap - EXIT
}

function install_rpm_with_zypper {
  if ! which curl >/dev/null 2>&1; then
    echo "* Installing curl"
    zypper -q install -y curl
  fi

  if ! $LEGACY_EBPF && ! $UNIVERSAL_EBPF; then
    if ! which dkms >/dev/null 2>&1; then
      echo "* Installing dkms"
      if [ $VERSION -ge 15 ]; then
        SUSEConnect -p PackageHub/$VERSION_ID/$ARCH
        zypper -q install -y dkms
      else
        echo "  * No dkms distro package found."
        echo "  * Installing make"
        zypper -q install -y make
        echo "  * Installing dkms from source"
        install_dkms_from_source
      fi
    fi
  fi

  echo "* Installing Sysdig public key"
  rpm --quiet --import "${GPG_PUBLIC_KEY}"
  echo "* Installing Sysdig repository"
  curl -sf -o /etc/zypp/repos.d/draios.repo "${DOWNLOAD_PATH_RPM}"

  if ! $UNIVERSAL_EBPF; then
    echo "* Installing kernel headers"
    # Use awk to strip "-default" or other suffixes off of uname -r output
    KERNEL_HEADER_VERSION=$(uname -r | awk 'match($0, /(.?*)-[A-Za-z].*/, uname){print uname[1]}')
    # please note how we need to use '=' instead of '-' for the version specifier
    zypper -q install -y kernel-devel=$KERNEL_HEADER_VERSION
  fi

  # Append version suffix if requested
  if [ -n "$AGENT_VERSION" ]; then
    CMDLINE=""
    for pkg in ${AGENT_ALL_PACKAGES}; do
      CMDLINE="${CMDLINE} ${pkg}-${AGENT_VERSION}"
    done
  else
    CMDLINE="${AGENT_PACKAGE}"
  fi
  echo "* Installing Sysdig Agent [${CMDLINE}]"
  zypper -q install -y ${CMDLINE}

  INIT_CONF=/etc/sysconfig/dragent
}

function install_deb {
  export DEBIAN_FRONTEND=noninteractive

  if ! hash curl >/dev/null 2>&1; then
    echo "* Installing curl"
    apt-get -qq -y install curl </dev/null
  fi

  if ! hash gnupg >/dev/null 2>&1; then
    echo "* Installing gnupg"
    apt-get -qq -y install gnupg </dev/null
  fi

  echo "* Installing Sysdig public key"
  curl -sf ${GPG_PUBLIC_KEY} -o /usr/share/keyrings/sysdig-keyring.asc
  echo "* Installing Sysdig repository"
  echo "deb [signed-by=/usr/share/keyrings/sysdig-keyring.asc] ${DOWNLOAD_PATH_DEB} stable-\$(ARCH)/" | tee /etc/apt/sources.list.d/sysdig.list > /dev/null
  apt-get -qq update </dev/null
  echo "* Installing kernel headers"
  apt-get -qq -y install linux-headers-$(uname -r) </dev/null || kernel_warning
  # Append version suffix if requested
  if [ ! -z "$AGENT_VERSION" ]; then
    CMDLINE=""
    for pkg in ${AGENT_ALL_PACKAGES}; do
      CMDLINE="${CMDLINE} ${pkg}=${AGENT_VERSION}"
    done
  else
    CMDLINE="${AGENT_PACKAGE}"
  fi
  echo "* Installing Sysdig Agent [${CMDLINE}]"
  apt-get -qq -y install ${CMDLINE} </dev/null

  INIT_CONF=/etc/default/dragent
}

function unsupported {
  echo "Unsupported operating system. distro=$1, version=$2, (if applicable)amz_version=$3."
  echo "Please consider contacting support@sysdigcloud.com or trying the manual installation."
  exit 1
}

function kernel_warning {
  echo "Unable to find kernel development files for the current kernel version" $(uname -r)
  echo "This usually means that your system is not up-to-date or you installed a custom kernel version."
  echo "The installation will continue but you'll need to install these yourself in order to use the agent."
  echo "Contact support@sysdigcloud.com if you need further assistance."
}

function help {
  echo "Usage: $(basename ${0}) -a | --access_key <value> [-t | --tags <value>]"
  echo "    [-c | --collector <value>] [-cp | --collector_port <value>]"
  echo "    [-s | --secure <value>] [-cc | --check_certificate]"
  echo "    [-ac | --additional_conf <value>] [-am | --agent_mode <value>]"
  echo "    [-ub | --universal_ebpf] [-k | --kmod] [-b | -lb | --legacy_ebpf | --bpf]"
  echo "    [--fips] [-v | --version <value>] [-ahsc | --additional_host_shield_config <value>]"
  echo "    [-h | --help]"
  echo "  access_key: Secret access key, as shown in Sysdig Monitor"
  echo "  tags: List of tags for this host."
  echo "        The syntax can be a comma-separated list of"
  echo "        TAG_NAME:TAG_VALUE or a single TAG_VALUE (in which case the tag"
  echo "        name \"Tag\" is implicitly assumed)."
  echo "        For example, \"role:webserver,location:europe\", \"role:webserver\""
  echo "        and \"webserver\" are all valid alternatives."
  echo "  collector: collector IP for Sysdig Monitor on-premises installation"
  echo "  collector_port: collector port [default 6443]"
  echo "  secure: use a secure SSL/TLS connection to send metrics to the collector"
  echo "        accepted values: true or false [default true]"
  echo "  check_certificate: disable strong SSL certificate check for Sysdig Monitor"
  echo "        on-premises installation accepted values: true or false [default true]"
  echo "  additional_conf: If provided, will be appended to agent configuration file"
  echo "  additional_host_shield_config: If provided, will be appended to host-shield.yaml file"
  echo "  agent_mode: If provided, sets the agent mode. See:"
  echo "        https://docs.sysdig.com/en/docs/installation/configuration/sysdig-agent/configure-agent-modes/"
  echo "  universal_ebpf: Enable the Universal eBPF agent driver. Requires Kernel"
  echo "        version >= 5.8 and agent version >= 12.17.0. See"
  echo "        https://docs.sysdig.com/en/docs/installation/configuration/sysdig-agent/understand-agent-drivers/"
  echo "  kmod: Enable the kernel module (kmod) agent driver.  Default for new"
  echo "        installations. See"
  echo "        https://docs.sysdig.com/en/docs/installation/configuration/sysdig-agent/understand-agent-drivers/"
  echo "  legacy_ebpf: Enable the legacy eBPF agent driver. Requires kernel"
  echo "        version >= 4.14 See"
  echo "        https://docs.sysdig.com/en/docs/installation/configuration/sysdig-agent/understand-agent-drivers/"
  echo "  fips: Install the FIPS package"
  echo "  version: Install a specific agent version (e.g. 12.11.0)"
  echo "  help: print this usage and exit"
  echo
  echo "NOTE: If this script is run to execute an upgrade, and no agent driver is"
  echo "specified, the existing agent driver selection will be retained."
  echo
  exit 1
}

function is_valid_value {
  if [[ ${1} == -* ]] || [[ ${1} == --* ]] || [[ -z ${1} ]]; then
    return 1
  else
    return 0
  fi
}

# $1 file
# $2 config environment variable name
function has_env_var {
  grep -Eq "^ *(export +)?$2=[^ ]* *\$" "$1"
}

# $1 file
# $2 environment variable name
# $3 new environment variable name and value
function replace_env_var {
  sed -Ei "s/^ *(export )? *$2=[^ ]* *\$/$3/" "$1"
}

# $1 file
# $2 environment variable name
function has_commented_env_var {
  grep -Eq "^ *# *(export +)?$2=[^ ]* *\$" "$1"
}

# $1 file
# $2 environment variable name
# $3 new environment variable name and value
function replace_commented_env_var {
  sed -Ei "s/^ *# *(export )? *$2=[^ ]* *\$/$3/" "$1"
}

# $1 file
# $2 new driver name
function update_sysdig_agent_driver {
  if has_env_var "$1" "$AGENT_DRIVER_VARNAME"; then
    replace_env_var "$1" "$AGENT_DRIVER_VARNAME" "$AGENT_DRIVER_VARNAME=$2"
  elif has_commented_env_var "$1" "$AGENT_DRIVER_VARNAME"; then
    replace_commented_env_var "$1" "$AGENT_DRIVER_VARNAME" "$AGENT_DRIVER_VARNAME=$2"
  else
    cat >>"$1" <<<"export $AGENT_DRIVER_VARNAME=$2"
  fi
}

# $1 file
function update_probe_url {
  # If we need to override the default probe URL, do it.
  # Please note: this won't delete any existing assignment if the variable ceases to exist.
  if [ -n "$SYSDIG_PROBE_URL" ]; then
    if has_env_var "$1" "SYSDIG_PROBE_URL"; then
      replace_env_var "$1" "SYSDIG_PROBE_URL" "SYSDIG_PROBE_URL=$SYSDIG_PROBE_URL"
    elif has_commented_env_var "$1" "SYSDIG_PROBE_URL"; then
      replace_commented_env_var "$1" "SYSDIG_PROBE_URL" "SYSDIG_PROBE_URL=$SYSDIG_PROBE_URL"
    else
      cat >>"$1" <<<"export SYSDIG_PROBE_URL=$SYSDIG_PROBE_URL"
    fi
  fi
}

# $1 file
function comment_out_sysdig_bpf_probe {
  sed -Ei 's/^ *((export +)?SYSDIG_BPF_PROBE=.*)/# \1/' "$1"

}

# $1 file
function uncomment_sysdig_bpf_probe {
  sed -Ei 's/^ *# *((export +)?SYSDIG_BPF_PROBE=.*)/\1/' "$1"
}

# Echoes positive number if LHS > RHS
# Echoes 0 if LHS == RHS
# Echoes negative number if LHS < RHS
# LHS and RHS must be semantic versions with major, minor, and patch release numbers, i.e. 12.16.3 or 12.17.0
# Hat-tip to Angelo Puglisi for suggesting this elegant, awk-based implementation.
# $1: LHS
# $2: RHS
function compare_semantic_versions {
  awk -v LHS=$1 -v RHS=$2 '
    BEGIN {
      split(LHS, lhs, ".");
      split(RHS, rhs, ".");
      diff_major = lhs[1]-rhs[1]
      diff_minor = lhs[2]-rhs[2]
      diff_patch = lhs[3]-rhs[3]
      if (diff_major) { print diff_major }
      else if (diff_minor) { print diff_minor }
      else if (diff_patch) { print diff_patch }
      else { print 0 }
    }'
}

#main

#Override any values for these variables coming from the environment
UNIVERSAL_EBPF=false
KMOD=false
LEGACY_EBPF=false
BAD_INPUT=false
DRIVERS_SELECTED=0
INSTALL_FIPS=false

# Parse command line options one by one
while [[ ${#} -gt 0 ]]; do
  key="${1}"

  case ${key} in
  -a | --access_key)
    if is_valid_value "${2}"; then
      ACCESS_KEY="${2}"
    else
      echo "ERROR: no value provided for access_key option, use -h | --help for $(basename ${0}) Usage"
      exit 1
    fi
    shift
    ;;
  -t | --tags)
    if is_valid_value "${2}"; then
      TAGS="${2}"
    else
      echo "ERROR: no value provided for tags option, use -h | --help for $(basename ${0}) Usage"
      exit 1
    fi
    shift
    ;;
  -c | --collector)
    if is_valid_value "${2}"; then
      COLLECTOR="${2}"
    else
      echo "ERROR: no value provided for collector endpoint option, use -h | --help for $(basename ${0}) Usage"
      exit 1
    fi
    shift
    ;;
  -cp | --collector_port)
    if is_valid_value "${2}"; then
      COLLECTOR_PORT="${2}"
    else
      echo "ERROR: no value provided for collector port option, use -h | --help for $(basename ${0}) Usage"
      exit 1
    fi
    shift
    ;;
  -s | --secure)
    if is_valid_value "${2}"; then
      SECURE="${2}"
    else
      echo "ERROR: no value provided for connection security option, use -h | --help for $(basename ${0}) Usage"
      exit 1
    fi
    shift
    ;;
  -cc | --check_certificate)
    if is_valid_value "${2}"; then
      CHECK_CERT="${2}"
    else
      echo "ERROR: no value provided for SSL check certificate option, use -h | --help for $(basename ${0}) Usage"
      exit 1
    fi
    shift
    ;;
  -ac | --additional_conf)
    if is_valid_value "${2}"; then
      ADDITIONAL_CONF="${2}"
    else
      echo "ERROR: no value provided for additional conf option, use -h | --help for $(basename ${0}) Usage"
      exit 1
    fi
    shift
    ;;
  -ahsc | --additional_host_shield_config)
    if is_valid_value "${2}"; then
      ADDITIONAL_HOST_SHIELD_CONFIG="${2}"
    else
      echo "ERROR: no value provided for additional host shield config option, use -h | --help for $(basename ${0}) Usage"
      exit 1
    fi
    shift
    ;;
  -am | --agent_mode)
    if is_valid_value "${2}"; then
      AGENT_MODE="${2}"
    else
      echo "ERROR: no value provided for agent mode option, use -h | --help for $(basename ${0}) Usage"
      exit 1
    fi
    shift
    ;;
  -ub | --universal_ebpf)
    $UNIVERSAL_EBPF || ((++DRIVERS_SELECTED))
    UNIVERSAL_EBPF=true
    ;;
  -k | --kmod)
    $KMOD || ((++DRIVERS_SELECTED))
    KMOD=true
    ;;
  -b | -lb | --legacy_ebpf | --bpf)
    $LEGACY_EBPF || ((++DRIVERS_SELECTED))
    LEGACY_EBPF=true
    ;;
  -v | --version)
    AGENT_VERSION="${2}"
    shift
    ;;
  --fips)
    INSTALL_FIPS=true
    ;;
  -h | --help)
    help
    exit 1
    ;;
  *)
    echo "ERROR: Invalid option: ${1}, use -h | --help for $(basename ${0}) Usage"
    exit 1
    ;;
  esac
  shift
done

if [[ -z "$ACCESS_KEY" ]]; then
  echo "ERROR: --access_key argument is required"
  BAD_INPUT=true
fi

if [ $DRIVERS_SELECTED -gt 1 ]; then
  echo "ERROR: Only one agent driver may be selected at a time."
  BAD_INPUT=true
fi

if $UNIVERSAL_EBPF && [[ "$REPOSITORY_NAME" == "stable" ]] && [ -n "$AGENT_VERSION" ]; then
  if [[ $(uname -m) = s390x ]]; then
    compare_result="$(compare_semantic_versions "$AGENT_VERSION" 12.18.0)"
  else
    compare_result="$(compare_semantic_versions "$AGENT_VERSION" 12.17.0)"
  fi
  if [ $compare_result -lt 0 ]; then
    echo "ERROR: agent version $AGENT_VERSION does not support universal_ebpf on this"
    echo "platform"
    BAD_INPUT=true
  fi
fi

if [[ -n $AGENT_MODE && ! $AGENT_MODE =~ ^(custom-metrics-only|monitor|monitor_light|secure|secure_light|troubleshooting)$ ]]; then
  echo "ERROR: Invalid agent mode '$AGENT_MODE'"
  BAD_INPUT=true
fi

# by default, assume we're installing something with new packaging scheme...
new_package="1"
# ... but if we're installing from stable or rc, it could be
# an older release, so compare the requested version with 13.1.0
if [[ "$REPOSITORY_NAME" == "stable" || "$REPOSITORY_NAME" == "rc" ]] && [ -n "$AGENT_VERSION" ]; then
  new_package="$(compare_semantic_versions "$AGENT_VERSION" 13.1.0)"
fi

# for older, pinned versions, use the old draios-agent package name
# NOTE: agent-slim must always be the last package in the
#       AGENT_ALL_PACKAGES list due to the way the --fips
#       behavior is implemented
if [ $new_package -lt 0 ]; then
  AGENT_PACKAGE="draios-agent"
  AGENT_ALL_PACKAGES="draios-agent"
elif $UNIVERSAL_EBPF; then
  AGENT_PACKAGE="draios-agent-slim"
  AGENT_ALL_PACKAGES="draios-agent-slim"
elif $LEGACY_EBPF; then
  AGENT_PACKAGE="draios-agent-legacy-ebpf"
  AGENT_ALL_PACKAGES="draios-agent-legacy-ebpf draios-agent-slim"
else # $KMOD is the default for all other cases
  AGENT_PACKAGE="draios-agent"
  AGENT_ALL_PACKAGES="draios-agent draios-agent-kmodule draios-agent-slim"
fi

if $INSTALL_FIPS; then
  # necessary because we do not build a FIPS version of the meta package
  # so we must force the segmented installation
  if [ -z $AGENT_VERSION ]; then
    echo "ERROR: --version argument is required when installing FIPS packages"
    BAD_INPUT=true
  fi

  fips_package_available="$(compare_semantic_versions "$AGENT_VERSION" 13.6.0)"

  if [ $fips_package_available -lt 0 ]; then
    echo "ERROR: only agent version >=13.6.0 has dedicated FIPS packages"
    BAD_INPUT=true
  else
    # We need to append the -fips suffix to the agent-slim package
    AGENT_ALL_PACKAGES+="-fips"
    if $UNIVERSAL_EBPF; then
      AGENT_PACKAGE="draios-agent-slim-fips"
    fi
  fi
fi

if $BAD_INPUT; then
  echo
  help
  exit 1
fi

if [ $(id -u) != 0 ]; then
  echo "Installer must be run as root (or with sudo)."
  exit 1
fi

echo "* Detecting operating system"

ARCH=$(uname -m)
if [[ $ARCH = "s390x" ]] || [[ $ARCH = "ppc64le" ]] || [[ $ARCH = "arm64" ]] || [[ $ARCH = "aarch64" ]]; then
  echo "------------"
  echo "WARNING: A Docker container is the only officially supported platform on $ARCH"
  echo "------------"
elif [[ ! $ARCH = *86 ]] && [[ ! $ARCH = "x86_64" ]]; then
  unsupported $DISTRO $VERSION $AMZ_AMI_VERSION
fi

if [ -f /etc/debian_version ]; then
  if [ -f /etc/lsb-release ]; then
    . /etc/lsb-release
    DISTRO=$DISTRIB_ID
    VERSION=${DISTRIB_RELEASE%%.*}
  else
    DISTRO="Debian"
    VERSION=$(cat /etc/debian_version | cut -d'.' -f1)
  fi

  case "$DISTRO" in

  "Ubuntu")
    if [ $VERSION -ge 10 ]; then
      install_deb
    else
      unsupported $DISTRO $VERSION $AMZ_AMI_VERSION
    fi
    ;;

  "LinuxMint")
    if [ $VERSION -ge 9 ]; then
      install_deb
    else
      unsupported $DISTRO $VERSION $AMZ_AMI_VERSION
    fi
    ;;

  "Debian")
    if [ $VERSION -ge 6 ]; then
      install_deb
    elif [[ $VERSION == *sid* ]]; then
      install_deb
    else
      unsupported $DISTRO $VERSION $AMZ_AMI_VERSION
    fi
    ;;
  *)
    unsupported $DISTRO $VERSION $AMZ_AMI_VERSION
    ;;

  esac

elif [ -f /etc/system-release-cpe ]; then
  DISTRO=$(cat /etc/system-release-cpe | cut -d':' -f3)

  # New Amazon Linux 2 distro
  if [[ -f /etc/image-id ]]; then
    AMZ_AMI_VERSION=$(cat /etc/image-id | grep 'image_name' | cut -d"=" -f2 | tr -d "\"")
  fi

  if [[ "${DISTRO}" == "o" ]] && ([[ ${AMZ_AMI_VERSION} = *"amzn2"* ]] || [[ ${AMZ_AMI_VERSION} = *"al202"* ]]); then
    DISTRO=$(cat /etc/system-release-cpe | cut -d':' -f4)
  fi

  VERSION=$(cat /etc/system-release-cpe | cut -d':' -f5 | cut -d'.' -f1 | sed 's/[^0-9]*//g')
  if [ -z "$VERSION" ]; then
    # this is for the amazon linux distros
    # the cat command returns cpe:2.3:o:amazon:amazon_linux:2022 as an example
    # then splits the above result by ":" to grab the 6th part
    # in the end does a regex matching to keep the version number
    VERSION=$(cat /etc/system-release-cpe | cut -d':' -f6 | sed 's/[^0-9]*//g')
  fi

  case "$DISTRO" in

  "oracle" | "centos" | "redhat")
    if [ $VERSION -ge 6 ]; then
      install_rpm
    else
      unsupported $DISTRO $VERSION $AMZ_AMI_VERSION
    fi
    ;;

  "euler")
    if [ $VERSION -ge 2 ]; then
      install_rpm
    else
      unsupported $DISTRO $VERSION $AMZ_AMI_VERSION
    fi
    ;;

  "amazon")
    install_rpm $AMZ_AMI_VERSION
    ;;

  "fedoraproject")
    if [ $VERSION -ge 13 ]; then
      install_rpm
    else
      unsupported $DISTRO $VERSION $AMZ_AMI_VERSION
    fi
    ;;

  "almalinux" | "rocky")
    if [ $VERSION -ge 8 ]; then
      install_rpm
    else
      unsupported $DISTRO $VERSION $AMZ_AMI_VERSION
    fi
    ;;

  *)
    unsupported $DISTRO $VERSION $AMZ_AMI_VERSION
    ;;

  esac
elif [ -f /etc/os-release ]; then
  . /etc/os-release
  DISTRO="$ID"
  VERSION="${VERSION_ID%%.*}"
  case $DISTRO in
  sles)
    if [ -n "$AGENT_VERSION" ] && [ "$REPOSITORY_NAME" == "stable" ] &&
      [[ $(compare_semantic_versions "$AGENT_VERSION" 13.1.0) -lt 0 ]]; then
      echo "ERROR: agent versions older than 13.1.0 are not supported on SuSE Enterprise"
      echo "Linux"
    fi
    if [ $VERSION -ge 12 ]; then
      install_rpm_with_zypper
    else
      unsupported $DISTRO $VERSION $AMZ_AMI_VERSION
    fi
    ;;
  *)
    unsupported $DISTRO $VERSION $AMZ_AMI_VERSION
    ;;
  esac
else
  unsupported $DISTRO $VERSION $AMZ_AMI_VERSION
fi

echo "* Setting access key"

CONFIG_FILE=/opt/draios/etc/dragent.yaml
HOST_SHIELD_CONFIG_FILE=/opt/draios/etc/host-shield.yaml

if ! grep ^customerid $CONFIG_FILE >/dev/null 2>&1; then
  echo "customerid: $ACCESS_KEY" >>$CONFIG_FILE
else
  sed -i "s/^customerid.*/customerid: $ACCESS_KEY/g" $CONFIG_FILE
fi

if [ ! -z "$TAGS" ]; then
  echo "* Setting tags"

  if ! grep ^tags $CONFIG_FILE >/dev/null 2>&1; then
    echo "tags: $TAGS" >>$CONFIG_FILE
  else
    sed -i "s/^tags.*/tags: $TAGS/g" $CONFIG_FILE
  fi
fi

if [ ! -z "$COLLECTOR" ]; then
  echo "* Setting collector endpoint"

  if ! grep ^collector: $CONFIG_FILE >/dev/null 2>&1; then
    echo "collector: $COLLECTOR" >>$CONFIG_FILE
  else
    sed -i "s/^collector:.*/collector: $COLLECTOR/g" $CONFIG_FILE
  fi
fi

if [ ! -z "$COLLECTOR_PORT" ]; then
  echo "* Setting collector port"

  if ! grep ^collector_port $CONFIG_FILE >/dev/null 2>&1; then
    echo "collector_port: $COLLECTOR_PORT" >>$CONFIG_FILE
  else
    sed -i "s/^collector_port.*/collector_port: $COLLECTOR_PORT/g" $CONFIG_FILE
  fi
fi

if [ ! -z "$SECURE" ]; then
  echo "* Setting connection security"

  if ! grep ^ssl: $CONFIG_FILE >/dev/null 2>&1; then
    echo "ssl: $SECURE" >>$CONFIG_FILE
  else
    sed -i "s/^ssl:.*/ssl: $SECURE/g" $CONFIG_FILE
  fi
fi

if [ ! -z "$CHECK_CERT" ]; then
  echo "* Setting SSL certificate check level"

  if ! grep ^ssl_verify_certificate $CONFIG_FILE >/dev/null 2>&1; then
    echo "ssl_verify_certificate: $CHECK_CERT" >>$CONFIG_FILE
  else
    sed -i "s/^ssl_verify_certificate.*/ssl_verify_certificate: $CHECK_CERT/g" $CONFIG_FILE
  fi
fi

if [ ! -z "$ADDITIONAL_CONF" ]; then
  echo "* Adding additional configuration to dragent.yaml"

  echo -e "$ADDITIONAL_CONF" >>$CONFIG_FILE
fi

if [ ! -z "$ADDITIONAL_HOST_SHIELD_CONFIG" ]; then
  echo "* Adding additional configuration to host-shield.yaml"

  echo -e "$ADDITIONAL_HOST_SHIELD_CONFIG" >>$HOST_SHIELD_CONFIG_FILE
fi

if [ -n "$AGENT_MODE" ]; then
  echo "* Setting agent mode"

  # Since this check is happening after $ADDITIONAL_CONF has been written,
  # we can check to see if the mode has already been set there.
  # If so, just use that value.
  if ! grep -zE "feature:.*  mode:" $CONFIG_FILE >/dev/null 2>&1; then
    echo -e "feature:\n  mode: $AGENT_MODE" >>$CONFIG_FILE
  else
    echo "! Agent mode already set, skipping"
  fi
fi

if $UNIVERSAL_EBPF; then
  echo "* Configuring Universal eBPF driver"
  [ -e "$INIT_CONF" ] || touch "$INIT_CONF"

  comment_out_sysdig_bpf_probe "$INIT_CONF"
  update_sysdig_agent_driver "$INIT_CONF" universal_ebpf
fi

if $KMOD; then
  echo "* Configuring kernel module, (kmod), driver"
  [ -e "$INIT_CONF" ] || touch "$INIT_CONF"

  comment_out_sysdig_bpf_probe "$INIT_CONF"
  update_sysdig_agent_driver "$INIT_CONF" kmod
  update_probe_url "$INIT_CONF"
fi

if $LEGACY_EBPF; then
  echo "* Configuring legacy eBPF driver"
  [ -e "$INIT_CONF" ] || touch "$INIT_CONF"

  update_sysdig_agent_driver "$INIT_CONF" legacy_ebpf
  uncomment_sysdig_bpf_probe "$INIT_CONF"
  if ! has_env_var "$INIT_CONF" SYSDIG_BPF_PROBE; then
    cat >>"$INIT_CONF" <<<"export SYSDIG_BPF_PROBE="
  fi
  update_probe_url "$INIT_CONF"
fi

echo "* Restarting the agent"
if type systemctl >/dev/null 2>&1; then
  systemctl --system daemon-reload
  systemctl restart dragent.service
  echo "* Enabling the agent"
  systemctl enable dragent.service
else
  service dragent restart
fi
