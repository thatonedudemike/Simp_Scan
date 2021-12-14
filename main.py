from Scanner import*

def main():
#  this code needs to be ran in a terminal with have sudo privleges.
    get_host()  # gets host name #
    net_scan()    # can for other IP/MAc addresses on the network
    inp = input('Would you like to run a port scan? Y/n >>> ')
    if inp == 'y' or 'yes':
        open_ports()  # scans the network for open ports
    if inp == 'n' or 'no':
        sys.exit()
if __name__ == '__main__':
    main()