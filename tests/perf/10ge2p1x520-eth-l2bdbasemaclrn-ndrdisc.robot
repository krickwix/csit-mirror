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

*** Settings ***
| Resource | resources/libraries/robot/performance.robot
| Force Tags | 3_NODE_SINGLE_LINK_TOPO | PERFTEST | HW_ENV | PERFTEST_LONG
| ... | NIC_Intel-X520-DA2 | PERFTEST_BASE
| Suite Setup | 3-node Performance Suite Setup with DUT's NIC model
| ... | L2 | Intel-X520-DA2
| Suite Teardown | 3-node Performance Suite Teardown
| Test Setup | Setup all DUTs before test
| Test Teardown | Run Keywords
| ...           | Run Keyword If Test Failed
| ...           | Traffic should pass with no loss | 10
| ...           | ${min_rate}pps | ${framesize} | 3-node-bridge
| ...           | fail_on_loss=${False}
| ...           | AND | Remove startup configuration of VPP from all DUTs
| ...           | AND | Show vpp trace dump on all DUTs
| Documentation | *RFC2544: Pkt throughput L2BD test cases*
| ...
| ... | *[Top] Network Topologies:* TG-DUT1-DUT2-TG 3-node circular topology\
| ... | with single links between nodes.
| ... | *[Enc] Packet Encapsulations:* Eth-IPv4 for L2 switching of IPv4.
| ... | *[Cfg] DUT configuration:* DUT1 and DUT2 are configured with L2 bridge-\
| ... | domain and MAC learning enabled. DUT1 and DUT2 tested with 2p10GE NI
| ... | X520 Niantic by Intel.
| ... | *[Ver] TG verification:* TG finds and reports throughput NDR (Non Drop\
| ... | Rate) with zero packet loss tolerance or throughput PDR (Partial Drop\
| ... | Rate) with non-zero packet loss tolerance (LT) expressed in percentage\
| ... | of packets transmitted. NDR and PDR are discovered for different\
| ... | Ethernet L2 frame sizes using either binary search or linear search\
| ... | algorithms with configured starting rate and final step that determines\
| ... | throughput measurement resolution. Test packets are generated by TG on\
| ... | links to DUTs. TG traffic profile contains two L3 flow-groups\
| ... | (flow-group per direction, 253 flows per flow-group) with all packets\
| ... | containing Ethernet header, IPv4 header with IP protocol=61 and static\
| ... | payload. MAC addresses are matching MAC addresses of the TG node\
| ... | interfaces.
| ... | *[Ref] Applicable standard specifications:* RFC2544.

*** Variables ***
#X520-DA2 bandwidth limit
| ${s_limit} | ${10000000000}

*** Keywords ***
| L2 Bridge Domain NDR Binary Search
| | [Arguments] | ${framesize} | ${min_rate} | ${wt} | ${rxq}
| | Set Test Variable | ${framesize}
| | Set Test Variable | ${min_rate}
| | ${max_rate}= | Calculate pps | ${s_limit} | ${framesize}
| | ${binary_min}= | Set Variable | ${min_rate}
| | ${binary_max}= | Set Variable | ${max_rate}
| | ${threshold}= | Set Variable | ${min_rate}
| | Add '${wt}' worker threads and rxqueues '${rxq}' in 3-node single-link topo
| | Add PCI devices to DUTs from 3-node single link topology
| | ${get_framesize}= | Get Frame Size | ${framesize}
| | Run Keyword If | ${get_framesize} < ${1522} | Add No Multi Seg to all DUTs
| | Apply startup configuration on all VPP DUTs
| | L2 bridge domain initialized in a 3-node circular topology
| | Find NDR using binary search and pps
| | ... | ${framesize} | ${binary_min} | ${binary_max} | 3-node-bridge
| | ... | ${min_rate} | ${max_rate} | ${threshold}

| L2 Bridge Domain PDR Binary Search
| | [Arguments] | ${framesize} | ${min_rate} | ${wt} | ${rxq}
| | Set Test Variable | ${framesize}
| | Set Test Variable | ${min_rate}
| | ${max_rate}= | Calculate pps | ${s_limit} | ${framesize}
| | ${binary_min}= | Set Variable | ${min_rate}
| | ${binary_max}= | Set Variable | ${max_rate}
| | ${threshold}= | Set Variable | ${min_rate}
| | Add '${wt}' worker threads and rxqueues '${rxq}' in 3-node single-link topo
| | Add PCI devices to DUTs from 3-node single link topology
| | ${get_framesize}= | Get Frame Size | ${framesize}
| | Run Keyword If | ${get_framesize} < ${1522} | Add No Multi Seg to all DUTs
| | Apply startup configuration on all VPP DUTs
| | L2 bridge domain initialized in a 3-node circular topology
| | Find PDR using binary search and pps
| | ... | ${framesize} | ${binary_min} | ${binary_max} | 3-node-bridge
| | ... | ${min_rate} | ${max_rate} | ${threshold}
| | ... | ${glob_loss_acceptance} | ${glob_loss_acceptance_type}

*** Test Cases ***
| TC01: 64B NDR binary search - DUT L2BD - 1thread 1core 1rxq
| | ... | ${64} | ${100000} | 1 | 1
| | [Tags] | 1_THREAD_NOHTT_RXQUEUES_1 | SINGLE_THREAD | NDR
| | [Documentation]
| | ... | [Cfg] DUT runs L2BD switching config with with\
| | ... | 1 thread, 1 phy core, 1 receive queue per NIC port.
| | ... | [Ver] Find NDR for 64 Byte frames using binary search start at 10GE\
| | ... | linerate, step 100kpps.
| | [Template] | L2 Bridge Domain NDR Binary Search

| TC02: 64B PDR binary search - DUT L2BD - 1thread 1core 1rxq
| | ... | ${64} | ${100000} | 1 | 1
| | [Tags] | 1_THREAD_NOHTT_RXQUEUES_1 | SINGLE_THREAD | PDR | SKIP_PATCH
| | [Documentation]
| | ... | [Cfg] DUT runs L2BD switching config with with\
| | ... | 1 thread, 1 phy core, 1 receive queue per NIC port.
| | ... | [Ver] Find PDR for 64 Byte frames using binary search start at 10GE\
| | ... | linerate, step 100kpps, LT=0.5%.
| | [Template] | L2 Bridge Domain PDR Binary Search

| TC03: 1518B NDR binary search - DUT L2BD - 1thread 1core 1rxq
| | ... | ${1518} | ${10000} | 1 | 1
| | [Tags] | 1_THREAD_NOHTT_RXQUEUES_1 | SINGLE_THREAD | NDR
| | [Documentation]
| | ... | [Cfg] DUT runs L2BD switching config with with\
| | ... | 1 thread, 1 phy core, 1 receive queue per NIC port.
| | ... | [Ver] Find NDR for 1518 Byte frames using binary search start at 10GE\
| | ... | linerate, step 10kpps.
| | [Template] | L2 Bridge Domain NDR Binary Search

| TC04: 1518B PDR binary search - DUT L2BD - 1thread 1core 1rxq
| | ... | ${1518} | ${10000} | 1 | 1
| | [Tags] | 1_THREAD_NOHTT_RXQUEUES_1 | SINGLE_THREAD | PDR | SKIP_PATCH
| | [Documentation]
| | ... | [Cfg] DUT runs L2BD switching config with with\
| | ... | 1 thread, 1 phy core, 1 receive queue per NIC port.
| | ... | [Ver] Find PDR for 1518 Byte frames using binary search start at 10GE\
| | ... | linerate, step 10kpps, LT=0.5%.
| | [Template] | L2 Bridge Domain PDR Binary Search

| TC05: 9000B NDR binary search - DUT L2BD - 1thread 1core 1rxq
| | ... | ${9000} | ${10000} | 1 | 1
| | [Tags] | 1_THREAD_NOHTT_RXQUEUES_1 | SINGLE_THREAD | NDR
| | [Documentation]
| | ... | [Cfg] DUT runs L2BD switching config with with\
| | ... | 1 thread, 1 phy core, 1 receive queue per NIC port.
| | ... | [Ver] Find NDR for 9000 Byte frames using binary search start at 10GE\
| | ... | linerate, step 10kpps.
| | [Template] | L2 Bridge Domain NDR Binary Search

| TC06: 9000B PDR binary search - DUT L2BD - 1thread 1core 1rxq
| | ... | ${9000} | ${10000} | 1 | 1
| | [Tags] | 1_THREAD_NOHTT_RXQUEUES_1 | SINGLE_THREAD | PDR | SKIP_PATCH
| | [Documentation]
| | ... | [Cfg] DUT runs L2BD switching config with with\
| | ... | 1 thread, 1 phy core, 1 receive queue per NIC port.
| | ... | [Ver] Find PDR for 9000 Byte frames using binary search start at 10GE\
| | ... | linerate, step 10kpps, LT=0.5%.
| | [Template] | L2 Bridge Domain PDR Binary Search

| TC07: 64B NDR binary search - DUT L2BD - 2thread 2core 1rxq
| | ... | ${64} | ${100000} | 2 | 1
| | [Tags] | 2_THREAD_NOHTT_RXQUEUES_1 | MULTI_THREAD | NDR
| | [Documentation]
| | ... | [Cfg] DUT runs L2BD switching config with with\
| | ... | 2 threads, 2 phy cores, 1 receive queue per NIC port.
| | ... | [Ver] Find NDR for 64 Byte frames using binary search start at 10GE\
| | ... | linerate, step 100kpps.
| | [Template] | L2 Bridge Domain NDR Binary Search

| TC08: 64B PDR binary search - DUT L2BD - 2thread 2core 1rxq
| | ... | ${64} | ${100000} | 2 | 1
| | [Tags] | 2_THREAD_NOHTT_RXQUEUES_1 | MULTI_THREAD | PDR | SKIP_PATCH
| | [Documentation]
| | ... | [Cfg] DUT runs L2BD switching config with with\
| | ... | 2 threads, 2 phy cores, 1 receive queue per NIC port.
| | ... | [Ver] Find PDR for 64 Byte frames using binary search start at 10GE\
| | ... | linerate, step 100kpps, LT=0.5%.
| | [Template] | L2 Bridge Domain PDR Binary Search

| TC09: 1518B NDR binary search - DUT L2BD - 2thread 2core 1rxq
| | ... | ${1518} | ${10000} | 2 | 1
| | [Tags] | 2_THREAD_NOHTT_RXQUEUES_1 | MULTI_THREAD | NDR | SKIP_PATCH
| | [Documentation]
| | ... | [Cfg] DUT runs L2BD switching config with with\
| | ... | 2 threads, 2 phy cores, 1 receive queue per NIC port.
| | ... | [Ver] Find NDR for 1518 Byte frames using binary search start at 10GE\
| | ... | linerate, step 10kpps.
| | [Template] | L2 Bridge Domain NDR Binary Search

| TC10: 1518B PDR binary search - DUT L2BD - 2thread 2core 1rxq
| | ... | ${1518} | ${10000} | 2 | 1
| | [Tags] | 2_THREAD_NOHTT_RXQUEUES_1 | MULTI_THREAD | PDR | SKIP_PATCH
| | [Documentation]
| | ... | [Cfg] DUT runs L2BD switching config with with\
| | ... | 2 threads, 2 phy cores, 1 receive queue per NIC port.
| | ... | [Ver] Find PDR for 1518 Byte frames using binary search start at 10GE\
| | ... | linerate, step 10kpps, LT=0.5%.
| | [Template] | L2 Bridge Domain PDR Binary Search

| TC11: 9000B NDR binary search - DUT L2BD - 2thread 2core 1rxq
| | ... | ${9000} | ${10000} | 2 | 1
| | [Tags] | 2_THREAD_NOHTT_RXQUEUES_1 | MULTI_THREAD | NDR | SKIP_PATCH
| | [Documentation]
| | ... | [Cfg] DUT runs L2BD switching config with with\
| | ... | 2 threads, 2 phy cores, 1 receive queue per NIC port.
| | ... | [Ver] Find NDR for 9000 Byte frames using binary search start at 10GE\
| | ... | linerate, step 10kpps.
| | [Template] | L2 Bridge Domain NDR Binary Search

| TC12: 9000B PDR binary search - DUT L2BD - 2thread 2core 1rxq
| | ... | ${9000} | ${10000} | 2 | 1
| | [Tags] | 2_THREAD_NOHTT_RXQUEUES_1 | MULTI_THREAD | PDR | SKIP_PATCH
| | [Documentation]
| | ... | [Cfg] DUT runs L2BD switching config with with\
| | ... | 2 threads, 2 phy cores, 1 receive queue per NIC port.
| | ... | [Ver] Find PDR for 9000 Byte frames using binary search start at 10GE\
| | ... | linerate, step 10kpps, LT=0.5%.
| | [Template] | L2 Bridge Domain PDR Binary Search

| TC13: 64B NDR binary search - DUT L2BD - 4thread 4core 2rxq
| | ... | ${64} | ${100000} | 4 | 2
| | [Tags] | 4_THREAD_NOHTT_RXQUEUES_2 | MULTI_THREAD | NDR
| | [Documentation]
| | ... | [Cfg] DUT runs L2BD switching config with with\
| | ... | 4 threads, 4 phy cores, 2 receive queues per NIC port.
| | ... | [Ver] Find NDR for 64 Byte frames using binary search start at 10GE\
| | ... | linerate, step 100kpps.
| | [Template] | L2 Bridge Domain NDR Binary Search

| TC14: 64B PDR binary search - DUT L2BD - 4thread 4core 2rxq
| | ... | ${64} | ${100000} | 4 | 2
| | [Tags] | 4_THREAD_NOHTT_RXQUEUES_2 | MULTI_THREAD | PDR | SKIP_PATCH
| | [Documentation]
| | ... | [Cfg] DUT runs L2BD switching config with with\
| | ... | 4 threads, 4 phy cores, 2 receive queues per NIC port.
| | ... | [Ver] Find PDR for 64 Byte frames using binary search start at 10GE\
| | ... | linerate, step 100kpps, LT=0.5%.
| | [Template] | L2 Bridge Domain PDR Binary Search

| TC15: 1518B NDR binary search - DUT L2BD - 4thread 4core 2rxq
| | ... | ${1518} | ${10000} | 4 | 2
| | [Tags] | 4_THREAD_NOHTT_RXQUEUES_2 | MULTI_THREAD | NDR | SKIP_PATCH
| | [Documentation]
| | ... | [Cfg] DUT runs L2BD switching config with with\
| | ... | 4 threads, 4 phy cores, 2 receive queues per NIC port.
| | ... | [Ver] Find NDR for 1518 Byte frames using binary search start at 10GE\
| | ... | linerate, step 10kpps.
| | [Template] | L2 Bridge Domain NDR Binary Search

| TC16: 1518B PDR binary search - DUT L2BD - 4thread 4core 2rxq
| | ... | ${1518} | ${10000} | 4 | 2
| | [Tags] | 4_THREAD_NOHTT_RXQUEUES_2 | MULTI_THREAD | PDR | SKIP_PATCH
| | [Documentation]
| | ... | [Cfg] DUT runs L2BD switching config with with\
| | ... | 4 threads, 4 phy cores, 2 receive queues per NIC port.
| | ... | [Ver] Find PDR for 1518 Byte frames using binary search start at 10GE\
| | ... | linerate, step 10kpps, LT=0.5%.
| | [Template] | L2 Bridge Domain PDR Binary Search

| TC17: 9000B NDR binary search - DUT L2BD - 4thread 4core 2rxq
| | ... | ${9000} | ${10000} | 4 | 2
| | [Tags] | 4_THREAD_NOHTT_RXQUEUES_2 | MULTI_THREAD | NDR | SKIP_PATCH
| | [Documentation]
| | ... | [Cfg] DUT runs L2BD switching config with with\
| | ... | 4 threads, 4 phy cores, 2 receive queues per NIC port.
| | ... | [Ver] Find NDR for 9000 Byte frames using binary search start at 10GE\
| | ... | linerate, step 10kpps.
| | [Template] | L2 Bridge Domain NDR Binary Search

| TC18: 9000B PDR binary search - DUT L2BD - 4thread 4core 2rxq
| | ... | ${9000} | ${10000} | 4 | 2
| | [Tags] | 4_THREAD_NOHTT_RXQUEUES_2 | MULTI_THREAD | PDR | SKIP_PATCH
| | [Documentation]
| | ... | [Cfg] DUT runs L2BD switching config with with\
| | ... | 4 threads, 4 phy cores, 2 receive queues per NIC port.
| | ... | [Ver] Find PDR for 9000 Byte frames using binary search start at 10GE\
| | ... | linerate, step 10kpps, LT=0.5%.
| | [Template] | L2 Bridge Domain PDR Binary Search