#!/usr/bin/env python3

# Title: DirectFire Converter
# Description: DirectFire is a firewall configuration conversion tool written in Python
# Author: Glenn Akester (@glennake)
# Version: 0.0.1
#
# DirectFire Converter is free software: you can redistribute it and/or
# modify it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# DirectFire Converter is distributed in the hope that it will be
# useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# If you don't have a copy of the GNU General Public License,
# it is available here <http://www.gnu.org/licenses/>.


# Imports

try:
    import argparse
except:
    raise ImportError("Could not import module: argparse")

try:
    from colorama import Fore, Back, Style
except:
    raise ImportError("Could not import module: colorama")

from datetime import datetime

import logging

from traceback_with_variables import prints_exc, LoggerAsFile

# Import common and settings

import DirectFire.Converter.common as common
import DirectFire.Converter.settings as settings

# Get arguments

arg_parser = argparse.ArgumentParser()

arg_parser.add_argument("-c", "--config", help="/full/path/to/config", required=True)

arg_parser.add_argument(
    "-s",
    "--source",
    choices=[
        "ciscoasa",
        "ciscoasa_pre83",
        "fortigate",
        "junipersrx",
        "netscreen",
        "watchguard",
        "sophos_xg",
        "sophos_utm"
    ],
    help="source format",
    required=True,
)

arg_parser.add_argument(
    "-d",
    "--destination",
    choices=["ciscoasa", "data", "fortigate"],
    help="destination format",
    required=True,
)

arg_parser.add_argument(
    "-r", "--routing", help="path to supplemental routing information csv file"
)

args = arg_parser.parse_args()

# Initiate logging

now = str(datetime.now().strftime("%Y%m%d_%H%M%S"))

logging.basicConfig(
    filename="logs/"
    + now
    + "_"
    + str(args.source)
    + "_"
    + str(args.destination)
    + ".log",
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.DEBUG,
)

logger = logging.getLogger(__name__)

logger.info("DirectFire.Converter.main: converter starting")
logger.info("DirectFire.Converter.main: source format is " + args.source)


def parse(src_format, src_config, routing_info=""):

    logger.info("DirectFire.Converter.parse: loading parser module for " + src_format)

    if src_format == "ciscoasa":  ## Cisco ASA
        from DirectFire.Converter.parsers.ciscoasa import parse

    elif src_format == "ciscoasa_pre83":  ## Cisco ASA pre 8.3
        from DirectFire.Converter.parsers.ciscoasa_pre83 import parse

    elif src_format == "fortigate":  ## Fortinet FortiGate
        from DirectFire.Converter.parsers.fortigate import parse

    elif src_format == "junipersrx":  ## Juniper SRX (JunOS)
        from DirectFire.Converter.parsers.junipersrx import parse

    elif src_format == "netscreen":  ## Juniper Netscreen (ScreenOS)
        from DirectFire.Converter.parsers.netscreen import parse

    elif src_format == "watchguard":  ## WatchGuard
        from DirectFire.Converter.parsers.watchguard import parse

    elif src_format == "sophos_xg":  ## Sophos XG
        from DirectFire.Converter.parsers.sophos_xg import parse

    elif src_format == "sophos_utm":  ## Sophos UTM
        from DirectFire.Converter.parsers.sophos_utm import parse
    else:
        logger.info(
            "DirectFire.Converter.parse: failed to load parser module for " + src_format
        )

        print(f"{Fore.RED}Error: failed to load parser module.{Style.RESET_ALL}")

        exit()

    logger.info("DirectFire.Converter.parse: loaded parser module for " + src_format)

    logger.info("DirectFire.Converter.parse: starting parse of source configuration")

    parsed_data = parse(src_config, routing_info)

    logger.info("DirectFire.Converter.parse: completed parse of source configuration")

    return parsed_data


def generate(dst_format, parsed_data):

    logger.info(
        "DirectFire.Converter.generate: loading generator module for " + dst_format
    )

    if dst_format == "ciscoasa":  ## Cisco ASA post 8.3
        from DirectFire.Converter.generators.ciscoasa import generate

    elif dst_format == "data":  ## JSON Data
        from DirectFire.Converter.generators.data import generate

    elif dst_format == "fortigate":  ## Fortinet FortiGate
        from DirectFire.Converter.generators.fortigate import generate

    else:
        logger.info(
            "DirectFire.Converter.parse: failed to load generator module for "
            + dst_format
        )

        print(f"{Fore.RED}Error: failed to load generator module.{Style.RESET_ALL}")

        exit()

    logger.info(
        "DirectFire.Converter.generate: loaded generator module for " + dst_format
    )

    logger.info(
        "DirectFire.Converter.generate: starting generation of destination output"
    )

    dst_config = generate(parsed_data)

    logger.info(
        "DirectFire.Converter.generate: completed generation of destination output"
    )

    return dst_config


@prints_exc(file_=LoggerAsFile(logger), fmt=settings.TBWV_FMT)
def main(src_format, dst_format, routing_info=""):

    # Load source configuration file

    logger.info(
        "DirectFire.Converter.main: loading source configuration from " + args.config
    )

    try:

        with open(args.config) as config_file:
            src_config = config_file.read()

    except:

        logger.error(
            "DirectFire.Converter.main: source file either not found or not readable "
            + args.config
        )

        print(
            f"{Fore.RED}Error: source file either not found or not readable.{Style.RESET_ALL}"
        )

        exit()

    if routing_info:

        try:

            with open(args.routing) as routing_file:
                routing_info = routing_file.read()

        except:

            logger.error(
                "DirectFire.Converter.main: routing file either not found or not readable "
                + args.config
            )

            print(
                f"{Fore.RED}Error: routing file either not found or not readable.{Style.RESET_ALL}"
            )

            exit()

    # Run configuration parser

    logger.info("DirectFire.Converter.main: running configuration parser")

    parsed_data = parse(
        src_format=src_format, src_config=src_config, routing_info=routing_info
    )

    logger.info("DirectFire.Converter.main: configuration parser finished")

    # Output

    logger.info("DirectFire.Converter.main: running configuration generator")

    dst_config = generate(dst_format=dst_format, parsed_data=parsed_data)

    for line in dst_config:
        print(line)

    ### add support for output to file

    logger.info("DirectFire.Converter.main: configuration generator finished")

    logger.info("DirectFire.Converter.main: converter exiting")


if __name__ == "__main__":

    main(src_format=args.source, dst_format=args.destination, routing_info=args.routing)
