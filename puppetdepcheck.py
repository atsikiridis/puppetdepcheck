#!/usr/bin/env python

import logging
import argparse

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s %(levelname)s %(message)s')


def main():
    usage = 'usage: puppetdepcheck [puppet_file_names]'
    parser = argparse.ArgumentParser(usage)
    help_message = "Checks for potential dependency issues in puppet script."
    parser.add_argument('puppet_file_name', nargs='+', help=help_message)
    puppet_file_names = parser.parse_args().puppet_file_name
    logging.info(puppet_file_names)

if __name__ == "__main__":
    main()
