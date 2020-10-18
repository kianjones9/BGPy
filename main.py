import socket
from binascii import hexlify
from math import log,ceil,floor

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
    def __init__(self, withdrawn_routes=[], path_attributes=[], nlri=[]):
        self.withdrawn_routes = withdrawn_routes
        self.path_attributes = path_attributes
        self.nlri = nlri
        
    def get_bytes(self):
        withdrawn_routes = []
        withdrawn_routes_length = 0
        for route in self.withdrawn_routes:
            withdrawn_routes_length += (1 + ceil(route.prefix_length/8))
            withdrawn_routes.append(route.get_bytes())

        path_attributes = []
        path_attribute_length = 0
        for attr in self.path_attributes:
            path_attribute_length += attr.get_length()
            path_attributes.append(attr.get_bytes())

        nlri = []
        for route in self.nlri:
            nlri.append(route.get_bytes())
        
        data = [
            withdrawn_routes_length.to_bytes(2,'big'),
            b''.join(withdrawn_routes),
            path_attribute_length.to_bytes(2,'big'),
            b''.join(path_attributes),
            b''.join(nlri)
        ]

        return b''.join(data)
        

        


sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', 180)
sock.connect(server_address)

message = OpenMessage(65000,'10.10.10.10',sock)
message.send()

message2 = UpdateMessage()
print(message2.get_bytes())