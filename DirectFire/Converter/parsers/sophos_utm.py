#!/usr/bin/env python

# Import modules

import logging
import sys
import xml.etree.ElementTree as ET

# Import common, logging and settings

import DirectFire.Converter.common as common
import DirectFire.Converter.settings as settings

# Initialise common functions

cleanse_names = common.cleanse_names
ipv4_prefix_to_mask = common.ipv4_prefix_to_mask

# Initiate logging

logger = logging.getLogger(__name__)

# Parser

def parse(src_config, routing_info=""):

    logger.info(__name__ + ": parser module started")

    # Initialise data

    src_config_xml = ET.ElementTree(ET.fromstring(src_config))

    # Initialise variables

    data = {}

    data["system"] = {}

    data["interfaces"] = {}
    data["zones"] = {}

    data["routes"] = []
    data["routes6"] = []

    data["network_objects"] = {}
    data["network6_objects"] = {}
    data["network_groups"] = {}
    data["network6_groups"] = {}

    data["service_objects"] = {}
    data["service_groups"] = {}

    data["policies"] = []

    data["nat"] = []

    # Parser specific variables

    """
    Parser specific variables
    """

    # Parse system

    logger.info(__name__ + ": parse system")

    src_system = src_config_xml.find("./nodes/management/content/settings/content/hostname")
    data["system"]["hostname"] = src_system.find("content").text
    logger.info(__name__ + ": system: hostname is " + data["system"]["hostname"])
    # Todo: separate host and domain parts from source FQDN

    # Parse interfaces

    logger.info(__name__ + ": parse interfaces - not yet supported")

    """
    Parse interfaces
    """

    # Parse zones

    logger.info(__name__ + ": parse zones - not yet supported")

    """
    Parse zones
    """

    # Parse static routes

    logger.info(__name__ + ": parse static routes - not yet supported")

    """
    Parse static routes
    """

    # Parse IPv4 network objects

    logger.info(__name__ + ": parse IPv4 network objects - work in progress")

    src_network_root = src_config_xml.find("./objects/network/content")

    src_host = src_network_root.find("./host/content")

    for addr in src_host:
        addr_name = cleanse_names(addr.find("./content/name/content").text)

        data["network_objects"][addr_name] = {}
        data["network_objects"][addr_name]["type"] = "host"
        data["network_objects"][addr_name]["host"] = addr.find("./content/address/content").text
        data["network_objects"][addr_name]["description"] = addr.find("./content/comment/content").text
        data["network_objects"][addr_name]["interface"] = "" # Todo get name from REF addr.find("./content/interface/content").text

    src_network = src_network_root.find("./network/content")

    for addr in src_network:
        addr_name = cleanse_names(addr.find("./content/name/content").text)

        data["network_objects"][addr_name] = {}
        data["network_objects"][addr_name]["type"] = "network"
        data["network_objects"][addr_name]["network"] = addr.find("./content/address/content").text
        data["network_objects"][addr_name]["mask"] = ipv4_prefix_to_mask("/" + addr.find("./content/netmask/content").text)
        data["network_objects"][addr_name]["description"] = addr.find("./content/comment/content").text
        data["network_objects"][addr_name]["interface"] = "" # Todo get name from REF addr.find("./content/interface/content").text

    src_fqdn = src_network_root.find("./dns_host/content")

    for fqdn in src_fqdn:
        fqdn_name = cleanse_names(fqdn.find("./content/name/content").text)

        data["network_objects"][fqdn_name] = {}
        data["network_objects"][fqdn_name]["type"] = "fqdn"
        data["network_objects"][fqdn_name]["fqdn"] = fqdn.find("./content/hostname/content").text
        data["network_objects"][fqdn_name]["description"] = fqdn.find("./content/comment/content").text
        data["network_objects"][fqdn_name]["interface"] = "" # Todo get name from REF addr.find("./content/interface/content").text

    # Parse IPv6 network objects

    logger.info(__name__ + ": parse IPv6 network objects - not yet supported")

    """
    Parse IPv6 network objects
    """

    # Parse IPv4 network groups

    logger.info(__name__ + ": parse IPv4 network groups - work in progress")

    # Parse IPv6 network groups

    logger.info(__name__ + ": parse IPv6 network groups - not yet supported")

    """
    Parse IPv6 network groups
    """

    # Parse service objects

    logger.info(__name__ + ": parse service objects - work in progress")

    src_service_root = src_config_xml.find("./objects/service/content")

    src_tcp = src_service_root.find("./tcp/content")

    for tcp in src_tcp:
        tcp_name = cleanse_names(tcp.find("./content/name/content").text)
        src_low = tcp.find("./content/src_low/content").text
        src_high = tcp.find("./content/src_high/content").text
        dst_low = tcp.find("./content/dst_low/content").text
        dst_high = tcp.find("./content/dst_high/content").text
        comment = tcp.find("./content/comment/content").text

        src_ports = src_low if src_high is None or src_high == src_low else f"{src_low}-{src_high}"
        dst_ports = dst_low if dst_high is None or dst_high == dst_low else f"{dst_low}-{dst_high}"

        data["service_objects"][tcp_name] = {
            "type": "v2",
            "protocols": ["6"],
            "src_ports": [src_ports],
            "dst_ports": [dst_ports],
            "description": comment,
        }

    src_udp = src_service_root.find("./udp/content")

    for udp in src_udp:
        udp_name = cleanse_names(udp.find("./content/name/content").text)
        src_low = udp.find("./content/src_low/content").text
        src_high = udp.find("./content/src_high/content").text
        dst_low = udp.find("./content/dst_low/content").text
        dst_high = udp.find("./content/dst_high/content").text
        comment = udp.find("./content/comment/content").text

        src_ports = src_low if src_high is None or src_high == src_low else f"{src_low}-{src_high}"
        dst_ports = dst_low if dst_high is None or dst_high == dst_low else f"{dst_low}-{dst_high}"

        data["service_objects"][udp_name] = {
            "type": "v2",
            "protocols": ["17"],
            "src_ports": [src_ports],
            "dst_ports": [dst_ports],
            "description": comment,
        }
    
    src_tcpudp = src_service_root.find("./tcpudp/content")

    for tcpudp in src_tcpudp:
        tcpudp_name = cleanse_names(tcpudp.find("./content/name/content").text)
        src_low = tcpudp.find("./content/src_low/content").text
        src_high = tcpudp.find("./content/src_high/content").text
        dst_low = tcpudp.find("./content/dst_low/content").text
        dst_high = tcpudp.find("./content/dst_high/content").text
        comment = tcpudp.find("./content/comment/content").text

        src_ports = src_low if src_high is None or src_high == src_low else f"{src_low}-{src_high}"
        dst_ports = dst_low if dst_high is None or dst_high == dst_low else f"{dst_low}-{dst_high}"

        data["service_objects"][tcpudp_name] = {
            "type": "v2",
            "protocols": ["6", "17"],
            "src_ports": [src_ports],
            "dst_ports": [dst_ports],
            "description": comment,
        }

    src_icmp = src_service_root.find("./icmp/content")

    for icmp in src_icmp:
        icmp_name = cleanse_names(icmp.find("./content/name/content").text)
        icmp_type = icmp.find("./content/type/content").text
        icmp_code = icmp.find("./content/code/content").text
        comment = icmp.find("./content/comment/content").text

        data["service_objects"][icmp_name] = {
            "type": "v2",
            "protocols": ["1"],
            "icmp_type": icmp_type,
            "icmp_code": icmp_code,
            "description": comment,
            "dst_ports": [""],
        }

    src_ip = src_service_root.find("./ip/content")

    for ip in src_ip:
        ip_name = cleanse_names(ip.find("./content/name/content").text)
        proto = ip.find("./content/proto/content").text
        comment = ip.find("./content/comment/content").text

        data["service_objects"][ip_name] = {
            "type": "v2",      
            "protocols": [proto],
            "description": comment,
            "dst_ports": [""],
        }

    # Not supported: icmpv6, esp, ah

    # Parse service groups

    logger.info(__name__ + ": parse service groups - work in progress")

    # src_servicegroup_root = src_config_xml.find("./objects/service/content/group/content")

    # Parse firewall policies

    logger.info(__name__ + ": parse firewall policies - not yet supported")

    """
    Parse firewall policies
    """

    # Parse NAT

    logger.info(__name__ + ": parse NAT - not yet supported")

    """
    Parse NAT policies
    """

    # Return parsed data

    logger.info(__name__ + ": parser module finished")

    return data
