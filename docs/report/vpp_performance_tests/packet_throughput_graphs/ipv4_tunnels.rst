IPv4 Overlay Tunnels
====================

Following sections include summary graphs of VPP Phy-to-Phy performance
with IPv4 Overlay Tunnels, including NDR throughput (zero packet loss)
and PDR throughput (<0.5% packet loss).  Performance is reported for VPP
running in multiple configurations of VPP worker thread(s), a.k.a. VPP
data plane thread(s), and their physical CPU core(s) placement.

NDR Throughput
~~~~~~~~~~~~~~

VPP NDR 64B packet throughput in 1t1c setup (1thread, 1core) is presented
in the graph below.

.. raw:: html

    <iframe width="700" height="1000" frameborder="0" scrolling="no" src="../../_static/vpp/64B-1t1c-ethip4-ndrdisc.html"></iframe>

*Figure 1. VPP 1thread 1core - NDR Throughput for Phy-to-Phy IPv4 Overlay
Tunnels.*

CSIT source code for the test cases used for above plots can be found in CSIT
git repository:

.. code-block:: bash

    $ cd $CSIT/tests/perf
    $ grep -E "64B-1t1c-ethip4[a-z0-9]+-[a-z0-9]*-ndrdisc" *

    10ge2p1x520-ethip4lispip4-ip4base-ndrpdrdisc.robot:| tc01-64B-1t1c-ethip4lispip4-ip4base-ndrdisc
    10ge2p1x520-ethip4lispip6-ip4base-ndrpdrdisc.robot:| tc01-64B-1t1c-ethip4lispip6-ip4base-ndrdisc
    10ge2p1x520-ethip4vxlan-l2bdbasemaclrn-ndrpdrdisc.robot:| tc01-64B-1t1c-ethip4vxlan-l2bdbasemaclrn-ndrdisc
    10ge2p1x520-ethip4vxlan-l2xcbase-ndrpdrdisc.robot:| tc01-64B-1t1c-ethip4vxlan-l2xcbase-ndrdisc

VPP NDR 64B packet throughput in 2t2c setup (2thread, 2core) is presented
in the graph below.

.. raw:: html

    <iframe width="700" height="1000" frameborder="0" scrolling="no" src="../../_static/vpp/64B-2t2c-ethip4-ndrdisc.html"></iframe>

*Figure 2. VPP 2threads 2cores - NDR Throughput for Phy-to-Phy IPv4 Overlay Tunnels.*

CSIT source code for the test cases used for above plots can be found in CSIT
git repository:

.. code-block:: bash

    $ cd $CSIT/tests/perf
    $ grep -E "64B-2t2c-ethip4[a-z0-9]+-[a-z0-9]*-ndrdisc" *

    10ge2p1x520-ethip4lispip4-ip4base-ndrpdrdisc.robot:| tc07-64B-2t2c-ethip4lispip4-ip4base-ndrdisc
    10ge2p1x520-ethip4lispip6-ip4base-ndrpdrdisc.robot:| tc07-64B-2t2c-ethip4lispip6-ip4base-ndrdisc
    10ge2p1x520-ethip4vxlan-l2bdbasemaclrn-ndrpdrdisc.robot:| tc07-64B-2t2c-ethip4vxlan-l2bdbasemaclrn-ndrdisc
    10ge2p1x520-ethip4vxlan-l2xcbase-ndrpdrdisc.robot:| tc07-64B-2t2c-ethip4vxlan-l2xcbase-ndrdisc

PDR Throughput
~~~~~~~~~~~~~~

VPP PDR 64B packet throughput in 1t1c setup (1thread, 1core) is presented
in the graph below. PDR measured for 0.5% packet loss ratio.

.. raw:: html

    <iframe width="700" height="1000" frameborder="0" scrolling="no" src="../../_static/vpp/64B-1t1c-ethip4-pdrdisc.html"></iframe>

*Figure 3. VPP 1thread 1core - PDR Throughput for Phy-to-Phy IPv4 Overlay
Tunnels.*

CSIT source code for the test cases used for above plots can be found in CSIT
git repository:

.. code-block:: bash

    $ cd $CSIT/tests/perf
    $ grep -E "64B-1t1c-ethip4[a-z0-9]+-[a-z0-9]*-pdrdisc" *

    10ge2p1x520-ethip4lispip4-ip4base-ndrpdrdisc.robot:| tc02-64B-1t1c-ethip4lispip4-ip4base-pdrdisc
    10ge2p1x520-ethip4lispip6-ip4base-ndrpdrdisc.robot:| tc02-64B-1t1c-ethip4lispip6-ip4base-pdrdisc
    10ge2p1x520-ethip4vxlan-l2bdbasemaclrn-ndrpdrdisc.robot:| tc02-64B-1t1c-ethip4vxlan-l2bdbasemaclrn-pdrdisc
    10ge2p1x520-ethip4vxlan-l2xcbase-ndrpdrdisc.robot:| tc02-64B-1t1c-ethip4vxlan-l2xcbase-pdrdisc

VPP PDR 64B packet throughput in 2t2c setup (2thread, 2core) is presented
in the graph below. PDR measured for 0.5% packet loss ratio.

.. raw:: html

    <iframe width="700" height="1000" frameborder="0" scrolling="no" src="../../_static/vpp/64B-2t2c-ethip4-pdrdisc.html"></iframe>

*Figure 4. VPP 2thread 2core - PDR Throughput for Phy-to-Phy IPv4 Overlay Tunnels.*

CSIT source code for the test cases used for above plots can be found in CSIT
git repository:

.. code-block:: bash

    $ cd $CSIT/tests/perf
    $ grep -E "64B-2t2c-ethip4[a-z0-9]+-[a-z0-9]*-pdrdisc" *

    10ge2p1x520-ethip4lispip4-ip4base-ndrpdrdisc.robot:| tc08-64B-2t2c-ethip4lispip4-ip4base-pdrdisc
    10ge2p1x520-ethip4lispip6-ip4base-ndrpdrdisc.robot:| tc08-64B-2t2c-ethip4lispip6-ip4base-pdrdisc
    10ge2p1x520-ethip4vxlan-l2bdbasemaclrn-ndrpdrdisc.robot:| tc08-64B-2t2c-ethip4vxlan-l2bdbasemaclrn-pdrdisc
    10ge2p1x520-ethip4vxlan-l2xcbase-ndrpdrdisc.robot:| tc08-64B-2t2c-ethip4vxlan-l2xcbase-pdrdisc

