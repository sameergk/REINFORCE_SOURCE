[REINFORCE][reinforce]
==

About
--
REINFORCE is an openNetVM[onvm] based high performance NFV service chain resiliency platform based on [Intel DPDK][dpdk] and [Docker][docker] containers.  
openNetVM is SDN-enabled, allowing the network controller to provide rules that dictate what network functions need to process each packet flow.
openNetVM is an open source version of the NetVM platform described in our [NSDI 2014 paper][nsdi04], released under the [BSD][license] license.

Installing
--
To install openNetVM, please see the [openNetVM Installation][install] guide for a thorough walkthrough.

Using openNetVM
--
openNetVM can be used in a variety of ways.  To get started with some examples, please see the [Example Uses][examples] guide

Creating NFs
--
The [NF Development][nfs] guide will provide what you need to start create your own NFs.

Resilient NF chains
--
More details to follow on how to setup the Local an Remote replica mapping.

[reinforce]: https://github.com/sameergk/REINFORCE_SOURCE
[onvm]: http://sdnfv.github.io/onvm/
[license]: LICENSE
[dpdk]: http://dpdk.org
[docker]: https://www.docker.com/
[nsdi04]: http://faculty.cs.gwu.edu/~timwood/papers/14-NSDI-netvm.pdf
[install]: docs/Install.md
[examples]: docs/Examples.md
[nfs]: docs/NF_Dev.md
