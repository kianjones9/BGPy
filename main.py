import socket
from binascii import hexlify
from math import log,ceil,floor
import time, threading
from events.Event import ManualStartEvent
import asyncio
from queue import Queue


BGP_MESSAGE_TYPES = {
    "NONE": 0 ,
    "OPEN": 1,
    "UPDATE": 2,
    "NOTIFICATION": 3,
    "KEEPALIVE": 4,
    "ROUTE-REFRESH": 5,
}

BGP_ATTRIBUTE_TYPE_CODES = {
    "ORIGIN": 1,
    "AS_PATH": 2,
    "NEXT_HOP": 3,
    "MULTI_EXIT_DISC": 4,
    "LOCAL_PREF": 5,
    "ATOMIC_AGGREGATE": 6,
    "AGGREGATOR": 7
}

BGP_STATES = {
    "IDLE": 1,
    "CONNECT": 2,
    "ACTIVE": 3
}

class BGPStateMachine:
    def __init__(self):
        self.state = BGP_STATES["IDLE"]

    def set_state(self,state):
        self.state = state

class BGPPeer:
    def __init__(self,bgp,address,asn,port=179):
        self.state = BGPStateMachine()
        self.address = address
        self.asn = asn
        self.bgp = bgp
        self.port = port
        self.connect_retry_timer_interval = 10 # DETERMINE HOW THIS SHOULD BE SET
        self.in_queue = Queue()
        self.out_queue = Queue()

    def send_open_message(self):
        message = OpenMessage(self.bgp.asn,self.bgp.identifier,self.active_connection)
        message.send()

    def init_client_connection(self):
        self.active_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.active_connection.connect((self.address,self.port))

    def get_messages(self):
        header = self.active_connection.recv(19)
        length = header[16*8: 16*8 + 16] if header else -1
        msg = ''
        if length != -1:
            msg = self.active_connection.recv(int(length,16) - 19)
        print(header)
        print(msg)
        # while true
            # rcv packet header
            # get length from header
            # rcv (length-header)

        # grab packet length
        
        
        



    # def connect(self,passive=False):
    #     if not passive:
    #         self.state.set_state(BGP_STATES["CONNECT"])
    #     else:
    #         self.state.set_state(BGP_STATES["ACTIVE"])

    #     if not passive:
    #         self.active_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #         self.active_connection.connect(self.address,self.port)

    #     self.passive_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #     server_address = ('localhost', 179)
    #     self.passive_connection.bind(server_address)
    #     self.passive_connection.listen(1)

    #     self.connect_retry_counter = 0
    #     self.connect_retry_timer = threading.Timer(self.connect_retry_timer_interval, self.connect_retry_timer_expired)
    #     self.connect_retry_timer.start()

    # def disconnect(self):
    #     self.active_connection.close()
    #     self.connect_retry_counter = 0
    #     self.connect_retry_timer.cancel()
    #     self.state.set_state(BGP_STATES["IDLE"])


class BGP:
    def __init__(self,asn,identifier):
        self.events = Queue()
        self.peers = []
        self.asn = asn
        self.identifier = identifier

        # try:
        #     thread.start_new_thread(self.process_messages, (self.peers))
        #     thread.start_new_thread(self.process_events, (self.events_queue))
        #     while threading.activeCount():
        #         pass
        # except:
        #     print ("Error: unable to start thread")
    
    def add_peer(self, address, asn, port=179):
        peer = BGPPeer(self, address, asn, port)
        self.peers.append(peer)
        return peer
    
    def remove_peer(self, peer):
        self.peers.remove(peer)
        return peer
        
# dispatch correct event (ex. Event 19: BGPOpen, Event 25: NotifMsg, Event 26: KeepAliveMsg, Event 27: UpdateMsg)
    def process_events(self, events):
        
        while True:
            if events:
                events.get().execute()

    def process_messages(self, peers):
    
        while True:
            for peer in peers:
                while not peer.in_queue.empty():
                    peer.in_queue.get().process()
                while not peer.out_queue.empty():
                    peer.out_queue.get().process()

                
class Utils:
    @staticmethod
    def identify_protocol(address):
        try:
            socket.inet_aton(address)
            return 4
        except socket.error: pass
        try:
            socket.inet_pton(socket.AF_INET6, address)
            return 6
        except socket.error: pass
        raise ValueError(address)

    @staticmethod
    def bytes_needed(n):
        if n == 0:
            return 1
        return int(log(n, 256)) + 1

    @staticmethod
    def ip2hex(ip):
        protocol = Utils.identify_protocol(ip)
        if protocol == 4:
            return Utils.ipv42hex(ip)
        elif protocol == 6:
            return Utils.ipv62hex(ip)

    @staticmethod
    def ipv42hex(ip):
        return int(socket.inet_aton(ip).hex(),16)

    @staticmethod
    def ipv62hex(ip):
        return int(socket.inet_pton(socket.AF_INET6, ip).hex(),16)

class MessageHeader:
    def __init__(self,length,_type):
        self.length = length + 19 # total message length (including header)
        self.type = _type
        self.marker = 0xffffffffffffffffffffffffffffffff # 16 octets of 1s

    def get_bytes(self):
        data = [
            self.marker.to_bytes(16,'big'), 
            self.length.to_bytes(2,'big'), 
            self.type.to_bytes(1,'big')
        ]        

        return b''.join(data)

class Route:
    def __init__(self,network, prefix_length):
        self.network = network
        self.prefix_length = prefix_length
        self.protocol = Utils.identify_protocol(self.network)
        self.address_length = 32 if self.protocol == 4 else 128

    def create_bitmask(self):
        mask = ('1'*self.prefix_length) + ((self.address_length-self.prefix_length)*'0')
        return int(mask,2)

    def get_prefix(self):
        shift = floor((self.address_length - self.prefix_length) / 8) * 8
        return self.network >> shift
    
    def get_bytes(self):
        return self.prefix_length.to_bytes(1,'big') + self.get_prefix().to_bytes(ceil(self.prefix_length/8),'big')
        

class PathAttribute:
    def __init__(self,optional, transitive, partial, extended,type_code):
        self.optional = optional
        self.transitive = transitive
        self.partial = partial
        self.extended = extended
        self.type = type_code
        self.value = None # payload to be set by child class

    def get_bytes(self):
        flags = ''
        flag_vars = [self.optional, self.transitive, self.partial, self.extended,0,0,0,0]
        for flag in flag_vars:
            flags += str(int(flag))

        length_bytes = 2 if self.extended else 1
        data = [
            int(flags,2).to_bytes(1,'big'),
            self.type.to_bytes(1,'big'),
            self.get_length().to_bytes(length_bytes,'big'),
            self.value #prob set length in child class and refer to it here
        ]
        
        return b''.join(data)
        
    def get_length(self):
        pass

        #bit 0 - optional
        #bit 1 - Transitive bit
        #bit 2 - Partial bit
        #bit 3 - Extended Length bit if true, length = octets 3 and 4 otherwise just octet 3
        # bit 4-7 = 0

class OriginPathAttribute(PathAttribute):
    def __init__(self,value):
        super().__init__(
            optional=False,
            transitive=True,
            partial=False,
            extended=False,
            type_code=BGP_ATTRIBUTE_TYPE_CODES["ORIGIN"]
        )
        self.value = value.to_bytes(1,'big') #check if value is one of valid values

    def get_length(self):
        return 4 # 2 Byte type + 1 Byte length + 1 Byte value

class PathSegment():
    def __init__(self,_type,as_values):
        self.type = _type
        self.as_values = as_values
        
    def get_length(self):
        return len(self.as_values)

    def to_bytes(self):
        data = [
            self.type.to_bytes(1,'big'),
            self.get_length().to_bytes(1,'big'),
            b''.join([asn.to_bytes(2,'big') for asn in self.as_values]),
        ]

        return b''.join(data)

class AsPathPathAttribute(PathAttribute):
    def __init__(self,path_segments):
        super().__init__(
            optional=False,
            transitive=True,
            partial=False, # IDK
            extended=False,
            type_code=BGP_ATTRIBUTE_TYPE_CODES["AS_PATH"]
        )
        self.segments = path_segments

        self.value = b''.join([segment.to_bytes() for segment in self.segments])
    
    def get_length(self):
        length = 3 #unless extended is set
        for segment in self.segments:
            length += segment.get_length() * 2 + 2 # 1 byte each for type and length + 2/ASN

        return length

class NextHopPathAttribute(PathAttribute):
    def __init__(self,address):
        super().__init__(
            optional=False,
            transitive=True,
            partial=False,
            extended=False,
            type_code=BGP_ATTRIBUTE_TYPE_CODES["NEXT_HOP"]
        )
        self.address = address
        self.value = Utils.ip2hex(self.address)

    def get_length(self):
        # base length = 3 + 4 (IPv4) or 16 (IPv6)
        return 7 if Utils.identify_protocol(self.address) == 4 else 19
    
class MultiExitDiscPathAttribute(PathAttribute):
    def __init__(self,value):
        super().__init__(
            optional=True,
            transitive=False,
            partial=False,
            extended=False,
            type_code=BGP_ATTRIBUTE_TYPE_CODES["MULTI_EXIT_DISC"]
        )
        self.value = value.to_bytes(4,'big')

    def get_length(self):
        return 7

class LocalPrefPathAttribute(PathAttribute):
    def __init__(self,value):
        super().__init__(
            optional=True,
            transitive=True,
            partial=False,
            extended=False,
            type_code=BGP_ATTRIBUTE_TYPE_CODES["LOCAL_PREF"]
        )
        self.value = value.to_bytes(4,'big')

class AtomicAggregate(PathAttribute):
    def __init__(self):
        super().__init__(
            optional=True,
            transitive=True,
            partial=False,
            extended=False,
            type_code=BGP_ATTRIBUTE_TYPE_CODES["ATOMIC_AGGREGATE"]
        )
        self.value = b'' # Empty Body

    def get_length(self):
        return 3

class AggregatorPathAttribute(PathAttribute):
    def __init__(self,asn,address):
        super().__init__(
            optional=True,
            transitive=True,
            partial=False,
            extended=False,
            type_code=BGP_ATTRIBUTE_TYPE_CODES["AGGREGATOR"]
        )
        self.value = asn.to_bytes(2,'big') + Utils.ip2hex(address).to_bytes(4,'big')

    def get_length(self):
        return 9 #3 base + 2 asn + 4 IP address

class Message:
    def __init__(self,_type,connection):
        self.type = _type
        self.connection = connection

    def get_length(self):
        pass

    def get_bytes(self):
        pass

    def send(self):
        header = MessageHeader(self.get_length(),self.type)
        print(header.get_bytes() + self.get_bytes())
        self.connection.sendall(header.get_bytes() + self.get_bytes())
    

class OpenMessage(Message):
    def get_length(self):
        return (sum([
            1, #version
            2, #asn
            2, #hold time
            4, #identifier
            1, # Optional param_length
            self.opt_param_length
        ]))

    def get_bytes(self):
        data = [
            self.version.to_bytes(1,'big'),
            self.asn.to_bytes(2,'big'),
            self.hold_timer.to_bytes(2,'big'),
            self.identifier.to_bytes(4,'big'),
            self.opt_param_length.to_bytes(1,'big'),
            #OPT Params
        ]

        return b''.join(data)

    def __init__(self,asn,identifier,connection,version=4,hold_timer=180):
        super().__init__(BGP_MESSAGE_TYPES["OPEN"], connection)
        self.version = version # BGP Version (Default: 4)
        self.asn = asn # Local Autonomous System Number
        self.hold_timer = hold_timer # Proposed Hold Timer
        self.identifier = Utils.ip2hex(identifier) # 32-bit BGP Identifier
        self.opt_param_length = 0# Length of opt_params in octets
        self.opt_params = []# List of optional parameters in TLV format

class UpdateMessage(Message):
    def __init__(self, connection, withdrawn_routes=[], path_attributes=[], nlri=[]):
        super().__init__(BGP_ATTRIBUTE_TYPE_CODES["UPDATE"],connection)
        self.withdrawn_routes = withdrawn_routes
        self.path_attributes = path_attributes
        self.nlri = nlri
        
    def get_bytes(self):
        withdrawn_routes = []
        self.withdrawn_routes_length = 0
        for route in self.withdrawn_routes:
            self.withdrawn_routes_length += (1 + ceil(route.prefix_length/8))
            withdrawn_routes.append(route.get_bytes())

        path_attributes = []
        self.path_attribute_length = 0
        for attr in self.path_attributes:
            self.path_attribute_length += attr.get_length()
            path_attributes.append(attr.get_bytes())

        nlri = []
        for route in self.nlri:
            nlri.append(route.get_bytes())
        
        data = [
            self.withdrawn_routes_length.to_bytes(2,'big'),
            b''.join(withdrawn_routes),
            self.path_attribute_length.to_bytes(2,'big'),
            b''.join(path_attributes),
            b''.join(nlri)
        ]

        return b''.join(data)

    def get_length(self):
        return 4 + self.withdrawn_routes_length + self.path_attribute_length
        
        
class KeepAliveMessage(Message):
    def __init__(self,connection):
        super().__init__(BGP_MESSAGE_TYPES["KEEP_ALIVE"],connection)

    def get_bytes(self):
        return b''

    def get_length(self):
        return 0

class NotificationMessage(Message):
    def __init__(self,connection,error_code,data=None,error_subcode=0):
        super().__init__(BGP_MESSAGE_TYPES["NOTIFICATION"],connection)
        self.error_code = error_code # check if valid
        self.error_subcode = error_subcode
        if data:
            self.data = data.to_bytes(Utils.bytes_needed(data),'big')
        else:
            self.data = b''

    def get_bytes(self):
        data = [
            self.error_code.to_bytes(1,'big'),
            self.error_subcode.to_bytes(1,'big'),
            self.data
        ]

        return b''.join(data)

    def get_length(self):
        return 2 + len(self.data)
        


# sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# server_address = ('localhost', 180)
# sock.connect(server_address)

# message = OpenMessage(65000,'10.10.10.10',sock)
# message.send()

# message2 = UpdateMessage(sock)
# print(message2.get_bytes())

bgp = BGP(65000,'0.0.0.0')

event = ManualStartEvent(bgp,'localhost',65001,180)
event.execute()