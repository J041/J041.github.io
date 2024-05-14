---
title: "OSPF Disguised LSA on MD5 enabled networks"
date: 2024-05-14T00:22:35+00:00
draft: false
---

## **What is the OSPF Disguised LSA Attack ?**

Open Shortest Path First (OSPF) is a dynamic routing protocol commonly used in large scale networks to determine the most efficient path for a packet to take to reach its destination. It is based on a link-state algorithm, where routers exchange information about network topology through Link State Advertisements (LSAs). OSPF calculates the shortest path to a destination using a cost metric, facilitating optimal routing and efficient network communication.

The Disguised LSA Attack allows an attacker to inject malicious LSAs into the routing domain potentially disrupting the OSPF routing process. This can lead to security risks such as unauthorized traffic redirection and denial of service.

Read about the original research here: 
[BH_US_11_Nakibly_Owning_the_Routing_Table_WP](https://media.blackhat.com/bh-us-11/Nakibly/BH_US_11_Nakibly_Owning_the_Routing_Table_WP.pdf)


This research was built on top on [https://microlab.red/2018/05/03/practical-routing-attacks-2-3-ospf/](https://microlab.red/2018/05/03/practical-routing-attacks-2-3-ospf/) which talks about the disguised LSA attack and provides a script to exploit it [https://github.com/illordlo/exploits/blob/master/routing/ospf-disguised-lsa.py](https://github.com/illordlo/exploits/blob/master/routing/ospf-disguised-lsa.py)

## **OSPF MD5 authentication**

OSPF can be configured with a few different types of authentication, namely Null authentication, Simple password authentication and Cryptographic authentication which uses md5. For this post, we will be focusing on exploiting the MD5 authentication. 

Routers will have to be configured with the same shared key in order to use OSPF MD5 authentication. For each OSPF packet, the key is used to generate and verify a message digest that is appended to the end. This is used to ensure the integrity and authenticity of OSPF packets exchanged between routers. When configured to use MD5 authentication, the OSPF header will have an Auth type of 2 and additional fields such as Key id, Data Length, Sequence Number and crypt data.

An example of a MD5 enabled OSPF Header

![ospf-md5-header](/images/ospf/ospf-md5-header.png)

## **MD5 Authentication Key**

In order for the attack to work on a MD5 authenticated network, we would need to know the shared key used by the routers in order to generate valid LSA packets. We can brute force the shared key if we have some OSPF packets from the authenticated network due to MD5 inherent weakness. 

In a packet, the Auth Crypt Data field contains the MD5 hash calculated by the router. 

The hash is calculated by hashing the value of 
- the OSPF header without the Auth Crypt Data field 
- appended with its data 
- as well as the shared key padded or truncated to the nearest 16 byte.

For example, a shared key of `123` was used to generate the following packet. we can see that the hash calculated by the router is `e768b0f69a33a728d04844cc8a0336aa` (Auth Crypt Data)

**OSPF Header**
![image info](/images/ospf/ospf-header.png)

**OSPF Data**
![image info](/images/ospf/ospf-data.png)


## **Calculating authentication Key**

Assuming we have a key `123`, we can convert it to hex and append it to the values in the ospf header + data
![image info](/images/ospf/ospf-hexkey.png)
![image info](/images/ospf/ospf-append-data.png)


Hashing this value would give us `e768b0f69a33a728d04844cc8a0336aa` which is the same value that's calculated by the router, thus we know that the shared key used was `123`

![image info](/images/ospf/ospf-hash.png)

## **Exploit Development**

We made a simple script that can brute force a shared key given a pcap with OSPF authenticated packets. The script can be found here:
[https://github.com/J041/ospfpwn/blob/main/attacks/md5_cracker.py](https://github.com/J041/ospfpwn/blob/main/attacks/md5_cracker.py)

Performing the disguised LSA attack on a MD5 authenticated network would require us to modify every packet we send to be hashed with the shared key. In order to do this, we had to modify scapy’s source code to be able to send authenticated packets. 

The exploit script has been tested on OSPFv2 and can work on all 3 types of authentication. It can be found here: [https://github.com/J041/ospfpwn/blob/main/attacks/disguised_lsa.py](https://github.com/J041/ospfpwn/blob/main/attacks/disguised_lsa.py)

The topology that it was tested on
![ospf-topology](/images/ospf/ospf-topology.png)


## **Potential Mitigations**

Some potential mitigation includes using HMAC Authentication (rfc5709) instead of MD5 authentication as well as using static routes for critical networking devices such as servers that are unlikely to change within the network as static routes take precedence over dynamically learned routes.

