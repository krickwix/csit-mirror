#!/bin/bash

# Copyright (c) 2017 Cisco and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -ex

STREAM=$1
OS=$2

URL="https://nexus.fd.io/service/local/artifact/maven/content"
VER="RELEASE"
GROUP="io.fd.vpp"
HC_GROUP="io.fd.hc2vpp"
NSH_GROUP="io.fd.nsh_sfc"
HC_ARTIFACTS="honeycomb"
NSH_ARTIFACTS="vpp-nsh-plugin"

if [ "${OS}" == "ubuntu1404" ]; then
    OS="ubuntu.trusty.main"
    PACKAGE="deb deb.md5"
    CLASS="deb"
    VPP_ARTIFACTS="vpp vpp-dbg vpp-dev vpp-lib vpp-plugins vpp-api-java"
    DPDK_ARTIFACTS="vpp-dpdk-dkms"
elif [ "${OS}" == "ubuntu1604" ]; then
    OS="ubuntu.xenial.main"
    PACKAGE="deb deb.md5"
    CLASS="deb"
    VPP_ARTIFACTS="vpp vpp-dbg vpp-dev vpp-lib vpp-plugins vpp-api-java"
    DPDK_ARTIFACTS="vpp-dpdk-dkms"
elif [ "${OS}" == "centos7" ]; then
    OS="centos7"
    PACKAGE="rpm rpm.md5"
    CLASS=""
    VPP_ARTIFACTS="vpp vpp-debuginfo vpp-devel vpp-lib vpp-plugins vpp-api-java"
    DPDK_ARTIFACTS=""
fi

REPO="fd.io.${STREAM}.${OS}"

# download latest honeycomb, vpp-dpdk and nsh packages
for ART in ${HC_ARTIFACTS}; do
    for PAC in ${PACKAGE}; do
        curl "${URL}?r=${REPO}&g=${HC_GROUP}&a=${ART}&p=${PAC}&v=${VER}&c=${CLASS}" -O -J || exit
    done
done

for ART in ${DPDK_ARTIFACTS}; do
    for PAC in ${PACKAGE}; do
        curl "${URL}?r=${REPO}&g=${GROUP}&a=${ART}&p=${PAC}&v=${VER}&c=${CLASS}" -O -J || exit
    done
done

for ART in ${NSH_ARTIFACTS}; do
    for PAC in ${PACKAGE}; do
        curl "${URL}?r=${REPO}&g=${NSH_GROUP}&a=${ART}&p=${PAC}&v=${VER}&c=${CLASS}" -O -J || exit
    done
done

# determine VPP dependency
if [ "${OS}" == "centos7" ]; then
    VER=`rpm -qpR honeycomb*.rpm | grep 'vpp ' | cut -d ' ' -f 3`
    VER=${VER}.x86_64
else
    VER=`dpkg -I honeycomb*.deb | grep -oP 'vpp \(= \K[^\)]+'`
    VER=${VER}_amd64
fi

# download VPP packages
for ART in ${VPP_ARTIFACTS}; do
    for PAC in ${PACKAGE}; do
        curl "${URL}?r=${REPO}&g=${GROUP}&a=${ART}&p=${PAC}&v=${VER}&c=${CLASS}" -O -J || exit
    done
done

# verify downloaded package
if [ "${OS}" == "centos7" ]; then
    FILES=*.rpm
else
    FILES=*.deb
fi

for FILE in ${FILES}; do
    echo " "${FILE} >> ${FILE}.md5
done
for MD5FILE in *.md5; do
    md5sum -c ${MD5FILE} || exit
    rm ${MD5FILE}
done