from scapy.all import *
from scapy.layers.l2 import ARP, Ether

startTime = time.time()


# start by getting host name and ip address for reference point
def get_host():
    host_name = socket.gethostname()
    host_ip = socket.gethostbyname(host_name)
    print(f'''
***********************
Host Name: {host_name} 
Host IP: {host_ip}
***********************\n''')


def open_ports():
    # get the open ports of a selected network
    target = input('\nEnter Network To Be Scanned (ex. 192.168.1.1): ')
    target_ip = target
    print(f"Starting Scan On {target_ip}\n")

    for i in range(1, 65535):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = s.connect_ex((target_ip, i))
            if result == 0:
                print(f'Port {i}  OPEN')
                s.close()
        except:
            print('*** Cannot Resolve IP, Try Again ***')
            break
    print(f"Scan Took {time.time() - startTime} seconds")


def net_scan():
    # using the ip of the router to scan the entire network for active devices
    target_ip = "192.168.1.1/24"
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # << indicates braodcasting
    packet = ether / arp

    result = srp(packet, timeout=3, verbose=0)[0]
    clients = []  # creates an empty list for the results to fill
    for sent, received in result:
        # add IP and MAC to a list of clients
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})

    for client in clients:
        print('''IP:{:16}     MAC: {}'''.format(client['ip'], client['mac']))
    print('\n')