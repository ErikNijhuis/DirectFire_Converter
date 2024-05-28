#!/usr/bin/env python

# Import modules

import logging
from mimetypes import add_type
import sys
import xml.etree.ElementTree as ET

# Import common, logging and settings

import DirectFire.Converter.common as common
import DirectFire.Converter.settings as settings

# Initialise common functions

cleanse_names = common.cleanse_names

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

    src_system = src_config_xml.find("AdminSettings").find("HostnameSettings")
    data["system"]["hostname"] = src_system.find("HostName").text
    logger.info(__name__ + ": system: hostname is " + data["system"]["hostname"])

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

    src_addr = src_config_xml.findall("./IPHost")
    src_fqdn = src_config_xml.findall("./FQDNHost")

    # Parse IPv6 network objects

    logger.info(__name__ + ": parse IPv6 network objects - not yet supported")

    """
    Parse IPv6 network objects
    """

    # Parse IPv4 network groups

    logger.info(__name__ + ": parse IPv4 network groups - work in progress")

    src_addr_grp = src_config_xml.findall("./IPHostGroup")
    src_fqdn_grp = src_config_xml.findall("./FQDNHostGroup")

    # Parse IPv6 network groups

    logger.info(__name__ + ": parse IPv6 network groups - not yet supported")

    """
    Parse IPv6 network groups
    """

    # Parse service objects

    logger.info(__name__ + ": parse service objects - work in progress")

    src_svc = src_config_xml.findall("./Services")

    # Parse service groups

    logger.info(__name__ + ": parse service groups")

    src_svc_grp = src_config_xml.findall("./ServiceGroup")

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
