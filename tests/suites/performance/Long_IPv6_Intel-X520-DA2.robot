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
| ...        | NIC_Intel-X520-DA2
| Suite Setup | 3-node Performance Suite Setup with DUT's NIC model
| ... | L3 | Intel-X520-DA2
| Suite Teardown | 3-node Performance Suite Teardown
| Test Setup | Setup all DUTs before test
| Test Teardown | Run Keyword | Show statistics on all DUTs
| Documentation | *Throughput search suite (based on RFC2544).*
| ...
| ... | Test suite uses 3-node topology TG - DUT1 - DUT2 - TG, with one link
| ... | between nodes. Traffic profile contain 2 L3 streams (1 stream per
| ... | direction). Packets contain Ethernet header, IPv6 header, and random
| ... | payload. Ethernet header MAC addresses are matching MAC addresses
| ... | of the TG node.

*** Test Cases ***
| Find NDR by using RFC2544 linear search and 78B frames through IPv6 forwarding in 3-node topology
| | [Documentation]
| | ... | Find throughput with non drop rate for 78B frames by using
| | ... | linear search starting at 4.0Mpps, stepping down with step of 0.1Mpps
| | [Tags] | 1_THREAD_NOHTT_RSS_1 | SINGLE_THREAD
| | ${framesize}= | Set Variable | 78
| | ${start_rate}= | Set Variable | 4000000
| | ${step_rate}= | Set Variable | 100000
| | ${min_rate}= | Set Variable | 100000
| | ${max_rate}= | Set Variable | 14880952
| | Given Setup '1' worker threads and rss '1' without HTT on all DUTs
| | And   IPv6 forwarding initialized in a 3-node circular topology
| | Then Find NDR using linear search and pps | ${framesize} | ${start_rate}
| | ...                                       | ${step_rate} | 3-node-IPv6
| | ...                                       | ${min_rate} | ${max_rate}

| Find NDR by using RFC2544 linear search and 1518B frames through IPv6 forwarding in 3-node topology
| | [Documentation]
| | ... | Find throughput with non drop rate for 1518B frames by using
| | ... | linear search starting at 812,743pps, stepping down with step of
| | ... | 10,000pps
| | [Tags] | 1_THREAD_NOHTT_RSS_1 | SINGLE_THREAD
| | ${framesize}= | Set Variable | 1518
| | ${start_rate}= | Set Variable | 812743
| | ${step_rate}= | Set Variable | 10000
| | ${min_rate}= | Set Variable | 10000
| | ${max_rate}= | Set Variable | 812743
| | Given Setup '1' worker threads and rss '1' without HTT on all DUTs
| | And   IPv6 forwarding initialized in a 3-node circular topology
| | Then Find NDR using linear search and pps | ${framesize} | ${start_rate}
| | ...                                       | ${step_rate} | 3-node-IPv6
| | ...                                       | ${min_rate} | ${max_rate}

| Find NDR by using RFC2544 linear search and 9000B frames through IPv6 forwarding in 3-node topology
| | [Documentation]
| | ... | Find throughput with non drop rate for 9000B frames by using
| | ... | linear search starting at 138,580pps, stepping down with step of
| | ... | 5,000pps
| | [Tags] | 1_THREAD_NOHTT_RSS_1 | SINGLE_THREAD
| | ${framesize}= | Set Variable | 9000
| | ${start_rate}= | Set Variable | 138580
| | ${step_rate}= | Set Variable | 5000
| | ${min_rate}= | Set Variable | 5000
| | ${max_rate}= | Set Variable | 138580
| | Given Setup '1' worker threads and rss '1' without HTT on all DUTs
| | And   IPv6 forwarding initialized in a 3-node circular topology
| | Then Find NDR using linear search and pps | ${framesize} | ${start_rate}
| | ...                                       | ${step_rate} | 3-node-IPv6
| | ...                                       | ${min_rate} | ${max_rate}

| Find NDR with 2 cores and rss 1 by using RFC2544 linear search and 78B frames through IPv6 forwarding in 3-node topology
| | [Documentation]
| | ... | Find throughput on 2 cores with non drop rate for 78B frames by using
| | ... | linear search starting at 7.8Mpps, stepping down with step of 0.1Mpps
| | [Tags] | 2_THREAD_NOHTT_RSS_1 | MULTI_THREAD
| | ${framesize}= | Set Variable | 78
| | ${start_rate}= | Set Variable | 7800000
| | ${step_rate}= | Set Variable | 100000
| | ${min_rate}= | Set Variable | 100000
| | ${max_rate}= | Set Variable | 14880952
| | Given Setup '2' worker threads and rss '1' without HTT on all DUTs
| | And   IPv6 forwarding initialized in a 3-node circular topology
| | Then Find NDR using linear search and pps | ${framesize} | ${start_rate}
| | ...                                       | ${step_rate} | 3-node-IPv6
| | ...                                       | ${min_rate} | ${max_rate}

| Find NDR with 2 cores and rss 1 by using RFC2544 linear search and 1518B frames through IPv6 forwarding in 3-node topology
| | [Documentation]
| | ... | Find throughput on 2 cores with non drop rate for 1518B frames by
| | ... | using linear search starting at 812,743pps, stepping down with step
| | ... | of 10.000pps
| | [Tags] | 2_THREAD_NOHTT_RSS_1 | MULTI_THREAD
| | ${framesize}= | Set Variable | 1518
| | ${start_rate}= | Set Variable | 812743
| | ${step_rate}= | Set Variable | 10000
| | ${min_rate}= | Set Variable | 10000
| | ${max_rate}= | Set Variable | 812743
| | Given Setup '2' worker threads and rss '1' without HTT on all DUTs
| | And   IPv6 forwarding initialized in a 3-node circular topology
| | Then Find NDR using linear search and pps | ${framesize} | ${start_rate}
| | ...                                       | ${step_rate} | 3-node-IPv6
| | ...                                       | ${min_rate} | ${max_rate}

| Find NDR with 2 cores and rss 1 by using RFC2544 linear search and 9000B frames through IPv6 forwarding in 3-node topology
| | [Documentation]
| | ... | Find throughput on 2 cores with non drop rate for 9000B frames by
| | ... | using linear search starting at 138,580pps, stepping down with step
| | ... | of 5,000pps
| | [Tags] | 2_THREAD_NOHTT_RSS_1 | MULTI_THREAD
| | ${framesize}= | Set Variable | 9000
| | ${start_rate}= | Set Variable | 138580
| | ${step_rate}= | Set Variable | 5000
| | ${min_rate}= | Set Variable | 5000
| | ${max_rate}= | Set Variable | 138580
| | Given Setup '2' worker threads and rss '1' without HTT on all DUTs
| | And   IPv6 forwarding initialized in a 3-node circular topology
| | Then Find NDR using linear search and pps | ${framesize} | ${start_rate}
| | ...                                       | ${step_rate} | 3-node-IPv6
| | ...                                       | ${min_rate} | ${max_rate}

| Find NDR with 4 cores and rss 2 by using RFC2544 linear search and 78B frames through IPv6 forwarding in 3-node topology
| | [Documentation]
| | ... | Find throughput on 4 cores and rss 2 with non drop rate for 78B
| | ... | frames by using linear search starting at 9.8Mpps, stepping down with
| | ... | step of 0.1Mpps
| | [Tags] | 4_THREAD_NOHTT_RSS_2 | MULTI_THREAD
| | ${framesize}= | Set Variable | 78
| | ${start_rate}= | Set Variable | 9800000
| | ${step_rate}= | Set Variable | 100000
| | ${min_rate}= | Set Variable | 100000
| | ${max_rate}= | Set Variable | 14880952
| | Given Setup '4' worker threads and rss '2' without HTT on all DUTs
| | And   IPv6 forwarding initialized in a 3-node circular topology
| | Then Find NDR using linear search and pps | ${framesize} | ${start_rate}
| | ...                                       | ${step_rate} | 3-node-IPv6
| | ...                                       | ${min_rate} | ${max_rate}

| Find NDR with 4 cores and rss 2 by using RFC2544 linear search and 1518B frames through IPv6 forwarding in 3-node topology
| | [Documentation]
| | ... | Find throughput on 4 cores and rss 2 with non drop rate for 1518B
| | ... | frames by using linear search starting at 812,743pps, stepping down
| | ... | with step of 10.000pps
| | [Tags] | 4_THREAD_NOHTT_RSS_2 | MULTI_THREAD
| | ${framesize}= | Set Variable | 1518
| | ${start_rate}= | Set Variable | 812743
| | ${step_rate}= | Set Variable | 10000
| | ${min_rate}= | Set Variable | 10000
| | ${max_rate}= | Set Variable | 812743
| | Given Setup '4' worker threads and rss '2' without HTT on all DUTs
| | And   IPv6 forwarding initialized in a 3-node circular topology
| | Then Find NDR using linear search and pps | ${framesize} | ${start_rate}
| | ...                                       | ${step_rate} | 3-node-IPv6
| | ...                                       | ${min_rate} | ${max_rate}

| Find NDR with 4 cores and rss 2 by using RFC2544 linear search and 9000B frames through IPv6 forwarding in 3-node topology
| | [Documentation]
| | ... | Find throughput on 4 cores and rss 2 with non drop rate for 9000B
| | ... | frames by using linear search starting at 138,580pps, stepping down
| | ... | with step of 5,000pps
| | [Tags] | 4_THREAD_NOHTT_RSS_2 | MULTI_THREAD
| | ${framesize}= | Set Variable | 9000
| | ${start_rate}= | Set Variable | 138580
| | ${step_rate}= | Set Variable | 5000
| | ${min_rate}= | Set Variable | 5000
| | ${max_rate}= | Set Variable | 138580
| | Given Setup '4' worker threads and rss '2' without HTT on all DUTs
| | And   IPv6 forwarding initialized in a 3-node circular topology
| | Then Find NDR using linear search and pps | ${framesize} | ${start_rate}
| | ...                                       | ${step_rate} | 3-node-IPv6
| | ...                                       | ${min_rate} | ${max_rate}

| Find NDR with 2 cores by using RFC2544 binary search and 78B frames through IPv6 forwarding in 3-node topology
| | [Documentation]
| | ... | Find throughput on 2 cores with non drop rate for 78B
| | ... | frames by using binary search with threshold 5,000pps
| | [Tags] | 2_THREAD_NOHTT_RSS_1 | MULTI_THREAD
| | ${framesize}= | Set Variable | 78
| | ${binary_min}= | Set Variable | 5000000
| | ${binary_max}= | Set Variable | 9000000
| | ${min_rate}= | Set Variable | 100000
| | ${max_rate}= | Set Variable | 14880952
| | ${threshold}= | Set Variable | 5000
| | Given Setup '2' worker threads and rss '1' without HTT on all DUTs
| | And   IPv6 forwarding initialized in a 3-node circular topology
| | Then Find NDR using binary search and pps | ${framesize} | ${binary_min}
| | ...                                       | ${binary_max} | 3-node-IPv6
| | ...                                       | ${min_rate} | ${max_rate}
| | ...                                       | ${threshold}

| Find NDR with 4 cores and rss 2 by using RFC2544 binary search and 78B frames through IPv6 forwarding in 3-node topology
| | [Documentation]
| | ... | Find throughput on 4 cores and rss 2 with non drop rate for 78B
| | ... | frames by using binary search with threshold 5,000pps
| | [Tags] | 4_THREAD_NOHTT_RSS_2 | MULTI_THREAD
| | ${framesize}= | Set Variable | 78
| | ${binary_min}= | Set Variable | 6000000
| | ${binary_max}= | Set Variable | 11000000
| | ${min_rate}= | Set Variable | 100000
| | ${max_rate}= | Set Variable | 14880952
| | ${threshold}= | Set Variable | 5000
| | Given Setup '4' worker threads and rss '2' without HTT on all DUTs
| | And   IPv6 forwarding initialized in a 3-node circular topology
| | Then Find NDR using binary search and pps | ${framesize} | ${binary_min}
| | ...                                       | ${binary_max} | 3-node-IPv6
| | ...                                       | ${min_rate} | ${max_rate}
| | ...                                       | ${threshold}