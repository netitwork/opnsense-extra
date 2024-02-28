#!/usr/bin/python3
# SPDX-License-Identifier: MIT
#
# OPNsense OpenVPN (Server) configuration converter
# © 2024 NETitwork GmbH (https://netitwork.net)

import sys
from lxml import etree
import uuid
import base64

def prepare_structure(root):
    """Prepare the XML structure, ensuring that the necessary sections exist."""
    opnsense_section = root.find('.//OPNsense')
    if opnsense_section is None:
        opnsense_section = etree.SubElement(root, 'OPNsense')

    openvpn_section = opnsense_section.find('.//OpenVPN')
    if openvpn_section is None:
        openvpn_section = etree.SubElement(opnsense_section, 'OpenVPN', version="1.0.0")

    instances_section = openvpn_section.find('.//Instances')
    if instances_section is None:
        instances_section = etree.SubElement(openvpn_section, 'Instances')

    static_keys_section = openvpn_section.find('.//StaticKeys')
    if static_keys_section is None:
        static_keys_section = etree.SubElement(openvpn_section, 'StaticKeys')

    return opnsense_section, openvpn_section, instances_section, static_keys_section

def handle_tls_key(old_server, instance, static_keys_section):
    """Handle the TLS key conversion and placement."""
    tls_element = old_server.find('tls')
    if tls_element is not None:
        tls_key_uuid = str(uuid.uuid4())
        static_key = etree.SubElement(static_keys_section, 'StaticKey', uuid=tls_key_uuid)
        etree.SubElement(instance, 'tls_key').text = tls_key_uuid
        etree.SubElement(static_key, 'mode').text = 'crypt'
        decoded_key = base64.b64decode(tls_element.text).decode('utf-8').replace('\r', '')
        etree.SubElement(static_key, 'key').text = decoded_key  # No CDATA needed as we're handling XML
        description = old_server.find('description')
        if description is not None:
            etree.SubElement(static_key, 'description').text = description.text

def remove_old_servers(root):
    """Remove the original <openvpn-server> sections to avoid duplication."""
    for old_server in root.xpath('//openvpn/openvpn-server'):
        old_server.getparent().remove(old_server)

def write_new_config(root, filename):
    """Write the modified XML to a new file."""
    with open(filename, 'wb') as file:
        file.write(etree.tostring(root, pretty_print=True, xml_declaration=True, encoding='UTF-8'))

# Function to convert fields according to the mapping table
def convert_fields(old_server, instance):
    # Define the mappings from old to new fields
    mappings = {
        'authmode': 'authmode', 'caref': 'ca', 'ipaddr': 'local', 'certref': 'cert', 'cert_depth': 'cert_depth',
        'crlref': 'crl', 'crypto': 'data-ciphers', 'description': 'description', 'dev_mode': 'dev_type',
        'dns_domain': 'dns_domain', 'local_network': 'push_route', 'local_port': 'port',
        'protocol': 'proto', 'tunnel_network': 'server', 'verbosity_level': 'verb', 'vpnid': 'vpnid'
    }

    # Set fields that are always added or have fixed values
    fixed_fields = {
        'enabled': '1', 'mssfix': '0', 'register_dns': '0', 'role': 'server',
        'username_as_common_name': '0', 'verify_client_cert': 'require', 'auth': '', 'auth-gen-token': '',
        'data-ciphers-fallback': '', 'dns_domain_search': '', 'fragment': '', 'keepalive_interval': '',
        'keepalive_timeout': '', 'local_group': '', 'maxclients': '', 'ntp_servers': '', 'password': '',
        'redirect_gateway': '', 'remote': '', 'reneg-sec': '', 'route': '', 'server_ipv6': '',
        'strictusercn': '', 'topology': '', 'tun_mtu': '', 'username': '', 'various_flags': ''
    }

    # Apply mappings for existing fields
    for old_field, new_field in mappings.items():
        old_element = old_server.find(old_field)
        if old_element is not None and old_element.text:
            etree.SubElement(instance, new_field).text = old_element.text.lower() if new_field == 'proto' else old_element.text

    # Special handling for DNS servers (merge with comma separation)
    dns_servers = [old_server.find('dns_server1'), old_server.find('dns_server2')]
    dns_servers = [dns.text for dns in dns_servers if dns is not None and dns.text]
    if dns_servers:
        etree.SubElement(instance, 'dns_servers').text = ','.join(dns_servers)

    # Apply fixed fields
    for new_field, value in fixed_fields.items():
        etree.SubElement(instance, new_field).text = value

def main():
    # Check for correct number of command-line arguments
    if len(sys.argv) != 3:
        print("Usage: ./convert_opnsense_openvpn_config.py <ORIG.XML> <NEW.XML>")
        sys.exit(1)

    # Assign command line arguments to variables for clarity
    input_filename = sys.argv[1]
    output_filename = sys.argv[2]

    # Load the original XML
    parser = etree.XMLParser(remove_blank_text=True)
    try:
        tree = etree.parse(input_filename, parser)
    except IOError:
        print(f"Error: File {input_filename} not found.")
        sys.exit(1)
    except etree.XMLSyntaxError as e:
        print(f"Error: XML syntax error in {input_filename}: {e}")
        sys.exit(1)

    root = tree.getroot()

    # Prepare XML structure and process configuration
    opnsense_section, openvpn_section, instances_section, static_keys_section = prepare_structure(root)
    for old_server in root.xpath('//openvpn/openvpn-server'):
        instance_uuid = str(uuid.uuid4())
        instance = etree.SubElement(instances_section, 'Instance', uuid=instance_uuid)
        convert_fields(old_server, instance)
        handle_tls_key(old_server, instance, static_keys_section)

    # Remove original <openvpn-server> sections and write the new configuration
    remove_old_servers(root)
    write_new_config(root, output_filename)

    print(f"Conversion complete. New configuration written to {output_filename}")

if __name__ == "__main__":
    main()
