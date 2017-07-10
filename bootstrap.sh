#!/bin/bash
# Copyright (c) 2016 Cisco and/or its affiliates.
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

set -x

cat /etc/hostname
cat /etc/hosts

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
export PYTHONPATH=${SCRIPT_DIR}

if [ -f "/etc/redhat-release" ]; then
    DISTRO="CENTOS"
    sudo yum install -y python-devel python-virtualenv
    VPP_ARTIFACTS="vpp vpp-debuginfo vpp-devel vpp-lib vpp-plugins"
    DPDK_ARTIFACTS=""
    PACKAGE="rpm"
    VPP_CLASSIFIER=""
    DPDK_STABLE_VER=$(cat ${SCRIPT_DIR}/DPDK_STABLE_VER).x86_64
    VPP_REPO_URL=$(cat ${SCRIPT_DIR}/VPP_REPO_URL_CENTOS)
    VPP_STABLE_VER=$(cat ${SCRIPT_DIR}/VPP_STABLE_VER_CENTOS)
    VIRL_TOPOLOGY=$(cat ${SCRIPT_DIR}/VIRL_TOPOLOGY_CENTOS)
    VIRL_RELEASE=$(cat ${SCRIPT_DIR}/VIRL_RELEASE_CENTOS)
    SHARED_MEMORY_PATH="/dev/shm"
else
    DISTRO="UBUNTU"
    export DEBIAN_FRONTEND=noninteractive
    sudo apt-get -y update
    sudo apt-get -y install libpython2.7-dev python-virtualenv
    VPP_ARTIFACTS="vpp vpp-dbg vpp-dev vpp-lib vpp-plugins"
    DPDK_ARTIFACTS="vpp-dpdk-dkms"
    PACKAGE="deb"
    VPP_CLASSIFIER="-deb"
    DPDK_STABLE_VER=$(cat ${SCRIPT_DIR}/DPDK_STABLE_VER)_amd64
    VPP_REPO_URL=$(cat ${SCRIPT_DIR}/VPP_REPO_URL_UBUNTU)
    VPP_STABLE_VER=$(cat ${SCRIPT_DIR}/VPP_STABLE_VER_UBUNTU)
    VIRL_TOPOLOGY=$(cat ${SCRIPT_DIR}/VIRL_TOPOLOGY_UBUNTU)
    VIRL_RELEASE=$(cat ${SCRIPT_DIR}/VIRL_RELEASE_UBUNTU)
    SHARED_MEMORY_PATH="/run/shm"
fi

VIRL_SERVERS=( "10.60.16.22" 
               "10.60.16.23" )
IPS_PER_VIRL=( "10.60.16.22:252"
               "10.60.16.23:252" )
VMS_PER_VIRL=( "10.60.16.22:36"
               "10.60.16.23:36" )
IPS_PER_SIMULATION=5

function get_max_ip_nr() {
    virl_server=$1
    IP_VALUE="0"
    for item in "${IPS_PER_VIRL[@]}" ; do
        if [ "${item%%:*}" == "${virl_server}" ]
        then
            IP_VALUE=${item#*:}
            break
        fi
    done
    echo "$IP_VALUE"
}

function get_max_vm_nr() {
    virl_server=$1
    VM_VALUE="0"
    for item in "${VMS_PER_VIRL[@]}" ; do
        if [ "${item%%:*}" == "${virl_server}" ]
        then
            VM_VALUE=${item#*:}
            break
        fi
    done
    echo "$VM_VALUE"
}

VIRL_USERNAME=jenkins-in
VIRL_PKEY=priv_key
VIRL_SERVER_STATUS_FILE="status"
VIRL_SERVER_EXPECTED_STATUS="PRODUCTION"

SSH_OPTIONS="-i ${VIRL_PKEY} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o LogLevel=error"

TEST_GROUPS=("gre,ipv6,lisp,policer,rpf,softwire" "dhcp,ipsec,l2bd,l2xc,telemetry,vrf,vxlan" "cop,fds,honeycomb,iacl,ipv4,tap,vhost,vlan")
SUITE_PATH="tests.func"
SKIP_PATCH="SKIP_PATCH"

# Create tmp dir
mkdir ${SCRIPT_DIR}/tmp

# Use tmp dir to store log files
LOG_PATH="${SCRIPT_DIR}/tmp"

# Use tmp dir for tarballs
export TMPDIR="${SCRIPT_DIR}/tmp"

function ssh_do() {
    echo
    echo "### "  ssh $@
    ssh ${SSH_OPTIONS} $@
}

rm -f ${VIRL_PKEY}
cat > ${VIRL_PKEY} <<EOF
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAwPMBNkeLbYp8GW0Vapm3SUBsoH8gM6jOM1kr1N64PqKhAqTV
ckFkJblQoBX8eQP6AHIQ2foErU9GfQtMK37pHpZlXDRLZjj1xRpUKiVfhGsgYSNc
2QtvnBbZRU1IIWxzGqlKGLdZx7o6JKgrA7t9LH3xLBj///jUzbH5DvmqBnUE90Q3
xW5WkpAe6xH+JUqtoWXuFHbyNYp1xuXhl9lLLk3SBSGI00qOtiiFPCLwXzOD/VOg
9Ujk7gDnnjmadfa0qtj47gLxGVVam9m6ME9nPj7yOrtnnkaQoHRMABYqpKfNF0aY
ydj1yHRNlsTr+SiMlQ+tdr614LWs/RF9pNe+9QIDAQABAoIBADTWlx9hKkp+IQvp
dnLx02KI9PZiudPLx2QCaGFr+HKWoJcTwqv+QkmeXPjp7HDLaPwUQI8gy4UWb4ww
utQyde59axZ776X3tT4bvq6n+2dM2tofD/8UBaVuEGPNDRKyGzdS4sqv8zMhyWhe
cSEdh+LWPmRAGGLlpokJ0tWKA0iu6kdlCxPZGtxEMWmVjutnPA1dOMx4e/aA8k+E
h0rXRhw1lI4GXf/Be6wH/yB1DNVJpOMArotB8P37CfXmh9al8y4yJf2Sfu9+CWRY
zJfrxz6Wlm3tVzdQgPyrcxaURIilgpW37NzzXbBdCCZZfmZaYxkV6OS42uyhOWIh
7tyT74UCgYEA/M8Sfc9D7xcs+rCdpcbOjHwEI2n8rOA2BAQnQ5Spky8EfZBziiJ6
cVzdXP8JSDVKU+2lXlPQg26z0KdUJZ4wDqTI9segMW1JkXZ7N5J3TJofcRd9hdfl
SmijKpIPcptTfu2lg+CqiIej4oLnH/dbz80iM4dWReVHYNo8NgftyocCgYEAw2KA
dUuQHL8VomJhZSZ+4D/hiirhTzRPOfAtrmHr2asL3mV9SD/gUAz/vW+beLAELFQ9
n0cZdpEPRPeo2flB0pGaz5ZWs9U6LLRsHn//g4VM6+XlA4dr9DI/ZX+NSTRkcvmu
DcfQZvPG7NzBKG1XPJFAtVYvbaoYGTjS9GqtnaMCgYEA55ym6lBbgs6OzNXGeLyd
OyPbfr55WcDIfAF6H3YxrcCjso4G7IUN/JIB1FNro5X/FMliefr7y44+e2jxtM0q
ZiAeZckaQG5JulT8KjurxKhnKetFerwDO5qF8liCgpM/ecgrnZjVY+QxBzK6oRS0
LrtXHDJfngWi0V7fTvkQqD0CgYAjh/AwZHNqpt06UIXBrUR5Z2SOicm7a5nUwXat
NaV8Sfy4juA/mU4jgJmpS3iMdAXuQcuLAZUB2NNcCWWtbgSoVE5A3egaf/Y6Vv0q
dsBynHUmmQISqDfbip+4x39cBqkVt44Nd37QmhhczrBZt7ibjRalY2zwlnQXchv6
0sOL3QKBgAWuAvb4dTyRYs0tv6U2lju/945DhWpks3HfXxmpqIPjoDI8PzDh4Ob9
vykyTIkweSrxg1sPSpljm6yD8AiddrIXtO89am83mW4aMjtk3b1E13dmzZsbg7pL
Iq/9sUivYeSg6z3j1wP07aNCWiLdNFPPuG8EXzlBJwfIBM3Hs/an
-----END RSA PRIVATE KEY-----
EOF
chmod 600 ${VIRL_PKEY}

#
# The server must be reachable and have a "status" file with
# the content "PRODUCTION" to be selected.
#
# If the server is not reachable or does not have the correct
# status remove it from the array and start again.
#
# Abort if there are no more servers left in the array.
#
VIRL_PROD_SERVERS=()
for index in "${!VIRL_SERVERS[@]}"; do
    virl_server_status=$(ssh ${SSH_OPTIONS} ${VIRL_USERNAME}@${VIRL_SERVERS[$index]} cat $VIRL_SERVER_STATUS_FILE 2>&1)
    echo VIRL HOST ${VIRL_SERVERS[$index]} status is \"$virl_server_status\"
    if [ "$virl_server_status" == "$VIRL_SERVER_EXPECTED_STATUS" ]
    then
        # Candidate is in good status. Add to array.
        VIRL_PROD_SERVERS+=(${VIRL_SERVERS[$index]})
    fi
done

VIRL_SERVERS=("${VIRL_PROD_SERVERS[@]}")
echo "VIRL servers in production: ${VIRL_SERVERS[@]}"
num_hosts=${#VIRL_SERVERS[@]}
if [ $num_hosts == 0 ]
then
    echo "No more VIRL candidate hosts available, failing."
    exit 127
fi

# Get the LOAD of each server based on number of active simulations (testcases)
VIRL_SERVER_LOAD=()
for index in "${!VIRL_SERVERS[@]}"; do
    VIRL_SERVER_LOAD[${index}]=$(ssh ${SSH_OPTIONS} ${VIRL_USERNAME}@${VIRL_SERVERS[$index]} "list-testcases | grep session | wc -l")
done

# Pick for each TEST_GROUP least loaded server
VIRL_SERVER=()
for index in "${!TEST_GROUPS[@]}"; do
    least_load_server_idx=$(echo "${VIRL_SERVER_LOAD[*]}" | tr -s ' ' '\n' | awk '{print($0" "NR)}' | sort -g -k1,1 | head -1 | cut -f2 -d' ')
    least_load_server=${VIRL_SERVERS[$least_load_server_idx-1]}
    VIRL_SERVER+=($least_load_server)
    # Adjusting load as we are not going run simulation immediately
    VIRL_SERVER_LOAD[$least_load_server_idx-1]=$((VIRL_SERVER_LOAD[$least_load_server_idx-1]+1))
done

echo "Selected VIRL servers: ${VIRL_SERVER[@]}"

# Temporarily download VPP and DPDK packages from nexus.fd.io
if [ "${#}" -ne "0" ]; then
    arr=(${@})
    echo ${arr[0]}
    SKIP_PATCH="skip_patchORskip_vpp_patch"
    # Download DPDK parts not included in dpdk plugin of vpp build
    for ARTIFACT in ${DPDK_ARTIFACTS}; do
        wget -q "${VPP_REPO_URL}/${ARTIFACT}/${DPDK_STABLE_VER}/${ARTIFACT}-${DPDK_STABLE_VER}${VPP_CLASSIFIER}.${PACKAGE}" || exit
    done
else
    rm -f *.${PACKAGE}
    for ARTIFACT in ${DPDK_ARTIFACTS}; do
        wget -q "${VPP_REPO_URL}/${ARTIFACT}/${DPDK_STABLE_VER}/${ARTIFACT}-${DPDK_STABLE_VER}${VPP_CLASSIFIER}.${PACKAGE}" || exit
    done
    for ARTIFACT in ${VPP_ARTIFACTS}; do
        wget -q "${VPP_REPO_URL}/${ARTIFACT}/${VPP_STABLE_VER}/${ARTIFACT}-${VPP_STABLE_VER}${VPP_CLASSIFIER}.${PACKAGE}" || exit
    done
fi

VPP_PKGS=(*.$PACKAGE)
echo ${VPP_PKGS[@]}
VIRL_DIR_LOC="/tmp"
VPP_PKGS_FULL=(${VPP_PKGS[@]})

# Prepend directory location at remote host to package file list
for index in "${!VPP_PKGS_FULL[@]}"; do
    VPP_PKGS_FULL[${index}]=${VIRL_DIR_LOC}/${VPP_PKGS_FULL[${index}]}
done

echo "Updated file names: " ${VPP_PKGS_FULL[@]}

cat ${VIRL_PKEY}

# Copy the files to VIRL hosts
DONE=""
for index in "${!VIRL_SERVER[@]}"; do
    # Do not copy files in case they have already been copied to the VIRL host
    [[ "${DONE[@]}" =~ "${VIRL_SERVER[${index}]}" ]] && copy=0 || copy=1

    if [ "${copy}" -eq "0" ]; then
        echo "VPP packages have already been copied to the VIRL host ${VIRL_SERVER[${index}]}"
    else
        scp ${SSH_OPTIONS} *.${PACKAGE} \
        ${VIRL_USERNAME}@${VIRL_SERVER[${index}]}:${VIRL_DIR_LOC}/

        result=$?
        if [ "${result}" -ne "0" ]; then
            echo "Failed to copy VPP packages to VIRL host ${VIRL_SERVER[${index}]}"
            echo ${result}
            exit ${result}
        else
            echo "VPP packages successfully copied to the VIRL host ${VIRL_SERVER[${index}]}"
        fi
        DONE+=(${VIRL_SERVER[${index}]})
    fi
done

# Start a simulation on VIRL server

function stop_virl_simulation {
    for index in "${!VIRL_SERVER[@]}"; do
        ssh ${SSH_OPTIONS} ${VIRL_USERNAME}@${VIRL_SERVER[${index}]}\
            "stop-testcase ${VIRL_SID[${index}]}"
    done
}

# Upon script exit, cleanup the simulation execution
trap stop_virl_simulation EXIT

for index in "${!VIRL_SERVER[@]}"; do
    echo "Starting simulation nr. ${index} on VIRL server ${VIRL_SERVER[${index}]}"
    # Get given VIRL server limits for max. number of VMs and IPs
    max_ips=$(get_max_ip_nr ${VIRL_SERVER[${index}]})
    max_ips_from_vms=$(($(get_max_vm_nr ${VIRL_SERVER[${index}]})*IPS_PER_SIMULATION))
    # Set quota to lower value
    IP_QUOTA=$([ $max_ips -le $max_ips_from_vms ] && echo "$max_ips" || echo "$max_ips_from_vms")
    # Start the simulation
    VIRL_SID[${index}]=$(ssh ${SSH_OPTIONS} \
        ${VIRL_USERNAME}@${VIRL_SERVER[${index}]} \
        "start-testcase -vv --quota ${IP_QUOTA} --copy ${VIRL_TOPOLOGY} \
        --release ${VIRL_RELEASE} ${VPP_PKGS_FULL[@]}")
    retval=$?
    if [ ${retval} -ne "0" ]; then
        echo "VIRL simulation start failed on ${VIRL_SERVER[${index}]}"
        exit ${retval}
    fi
    if [[ ! "${VIRL_SID[${index}]}" =~ session-[a-zA-Z0-9_]{6} ]]; then
        echo "No VIRL session ID reported."
        exit 127
    fi
    echo "VIRL simulation nr. ${index} started on ${VIRL_SERVER[${index}]}"

    ssh_do ${VIRL_USERNAME}@${VIRL_SERVER[${index}]}\
     cat /scratch/${VIRL_SID[${index}]}/topology.yaml

    # Download the topology file from VIRL session and rename it
    scp ${SSH_OPTIONS} \
        ${VIRL_USERNAME}@${VIRL_SERVER[${index}]}:/scratch/${VIRL_SID[${index}]}/topology.yaml \
        topologies/enabled/topology${index}.yaml

    retval=$?
    if [ ${retval} -ne "0" ]; then
        echo "Failed to copy topology file from VIRL simulation nr. ${index} on VIRL server ${VIRL_SERVER[${index}]}"
        exit ${retval}
    fi
done

echo ${VIRL_SID[@]}

virtualenv --system-site-packages env
. env/bin/activate

echo pip install
pip install -r ${SCRIPT_DIR}/requirements.txt

for index in "${!VIRL_SERVER[@]}"; do
    pykwalify -s ${SCRIPT_DIR}/resources/topology_schemas/3_node_topology.sch.yaml \
              -s ${SCRIPT_DIR}/resources/topology_schemas/topology.sch.yaml \
              -d ${SCRIPT_DIR}/topologies/enabled/topology${index}.yaml \
              -vvv
    if [ "$?" -ne "0" ]; then
        echo "Topology${index} schema validation failed."
        echo "However, the tests will start."
    fi
done

function run_test_set() {
    set +x
    OLDIFS=$IFS
    IFS=","
    nr=$(echo $1)
    rm -f ${LOG_PATH}/test_run${nr}.log
    exec &> >(while read line; do echo "$(date +'%H:%M:%S') $line" \
     >> ${LOG_PATH}/test_run${nr}.log; done;)
    suite_str=""
    for suite in ${TEST_GROUPS[${nr}]}; do
        suite_str="${suite_str} --suite ${SUITE_PATH}.${suite}"
    done
    IFS=$OLDIFS

    echo "PYTHONPATH=`pwd` pybot -L TRACE -W 136\
        -v TOPOLOGY_PATH:${SCRIPT_DIR}/topologies/enabled/topology${nr}.yaml \
        ${suite_str} \
        --include vm_envAND3_node_single_link_topo \
        --include vm_envAND3_node_double_link_topo \
        --exclude PERFTEST \
        --exclude ${SKIP_PATCH} \
        --noncritical EXPECTED_FAILING \
        --output ${LOG_PATH}/log_test_set_run${nr} \
        tests/"

    PYTHONPATH=`pwd` pybot -L TRACE -W 136\
        -v TOPOLOGY_PATH:${SCRIPT_DIR}/topologies/enabled/topology${nr}.yaml \
        ${suite_str} \
        --include vm_envAND3_node_single_link_topo \
        --include vm_envAND3_node_double_link_topo \
        --exclude PERFTEST \
        --exclude ${SKIP_PATCH} \
        --noncritical EXPECTED_FAILING \
        --output ${LOG_PATH}/log_test_set_run${nr} \
        tests/

    local_run_rc=$?
    echo ${local_run_rc} > ${SHARED_MEMORY_PATH}/rc_test_run${nr}
    set -x
}

set +x
# Send to background an instance of the run_test_set() function for each number,
# record the pid.
for index in "${!VIRL_SERVER[@]}"; do
    run_test_set ${index} &
    pid=$!
    echo "Sent to background: Test_set${index} (pid=$pid)"
    pids[$pid]=$index
done

echo
echo -n "Waiting..."

# Watch the stable of background processes.
# If a pid goes away, remove it from the array.
while [ -n "${pids[*]}" ]; do
    for i in $(seq 0 9); do
        sleep 1
        echo -n "."
    done
    for pid in "${!pids[@]}"; do
        if ! ps "$pid" >/dev/null; then
            echo -e "\n"
            echo "Test_set${pids[$pid]} with PID $pid finished."
            unset pids[$pid]
        fi
    done
    if [ -z "${!pids[*]}" ]; then
        break
    fi
    echo -n -e "\nStill waiting for test set(s): ${pids[*]} ..."
done

echo
echo "All test set runs finished."
echo

set -x

RC=0
for index in "${!VIRL_SERVER[@]}"; do
    echo "Test_set${index} log:"
    cat ${LOG_PATH}/test_run${index}.log
    RC_PARTIAL_RUN=$(cat ${SHARED_MEMORY_PATH}/rc_test_run${index})
    RC=$((RC+RC_PARTIAL_RUN))
    rm -f ${SHARED_MEMORY_PATH}/rc_test_run${index}
    rm -f ${LOG_PATH}/test_run${index}.log
    echo
done

# Log the final result
if [ "${RC}" -eq "0" ]; then
    set +x
    echo
    echo "========================================================================================================================================"
    echo "Final result of all test loops:                                                                                                 | PASS |"
    echo "All critical tests have passed."
    echo "========================================================================================================================================"
    echo
    set -x
else
    if [ "${RC}" -eq "1" ]; then
        HLP_STR="test has"
    else
        HLP_STR="tests have"
    fi
    set +x
    echo
    echo "========================================================================================================================================"
    echo "Final result of all test loops:                                                                                                 | FAIL |"
    echo "${RC} critical ${HLP_STR} failed."
    echo "========================================================================================================================================"
    echo
    set -x
fi

echo Post-processing test data...

partial_logs=""
for index in "${!VIRL_SERVER[@]}"; do
    partial_logs="${partial_logs} ${LOG_PATH}/log_test_set_run${index}.xml"
done

# Rebot output post-processing
rebot --noncritical EXPECTED_FAILING \
      --output output.xml ${partial_logs}

# Remove unnecessary log files
rm -f ${partial_logs}

echo Post-processing finished.

if [ ${RC} -eq 0 ]; then
    RETURN_STATUS=0
else
    RETURN_STATUS=1
fi

exit ${RETURN_STATUS}
