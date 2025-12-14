import struct

class Packet:
    def __init__(self, packet_id, payload=b''):
        self.packet_id = packet_id
        self.payload = payload

    def to_bytes(self):
        # Length includes header (4 bytes) + payload
        length = 4 + len(self.payload)
        # Pack: unsigned short (length), unsigned short (id)
        header = struct.pack('<HH', length, self.packet_id)
        return header + self.payload

    @staticmethod
    def parse_header(header_bytes):
        """
        Parses the first 4 bytes.
        Returns (length, packet_id)
        """
        if len(header_bytes) < 4:
            return None, None
        length, packet_id = struct.unpack('<HH', header_bytes)
        return length, packet_id

class PacketReader:
    def __init__(self, data):
        self.data = data
        self.offset = 0

    def read_byte(self):
        """Read a single byte (unsigned)"""
        if self.offset >= len(self.data):
            raise IndexError("PacketReader: offset out of bounds")
        val = self.data[self.offset]
        self.offset += 1
        return val

    def read_int(self):
        """Read 4-byte integer (little-endian)"""
        if self.offset + 4 > len(self.data):
            raise IndexError("PacketReader: not enough data for int")
        val = struct.unpack_from('<I', self.data, self.offset)[0]
        self.offset += 4
        return val

    def read_short(self):
        """Read 2-byte short (little-endian)"""
        if self.offset + 2 > len(self.data):
            raise IndexError("PacketReader: not enough data for short")
        val = struct.unpack_from('<H', self.data, self.offset)[0]
        self.offset += 2
        return val
    
    def read_string(self):
        """Read length-prefixed string (short length + UTF-8 data)"""
        try:
            length = self.read_short()
            if self.offset + length > len(self.data):
                raise IndexError(f"PacketReader: string length {length} exceeds data")
            val = self.data[self.offset:self.offset+length]
            self.offset += length
            return val.decode('utf-8', errors='ignore')
        except Exception as e:
            # Fallback: try to read until null terminator
            end = self.data.find(b'\x00', self.offset)
            if end != -1:
                val = self.data[self.offset:end].decode('utf-8', errors='ignore')
                self.offset = end + 1
                return val
            raise e
    
    def read_remaining(self):
        """Read all remaining bytes"""
        remaining = self.data[self.offset:]
        self.offset = len(self.data)
        return remaining
    
    def has_data(self):
        """Check if there's more data to read"""
        return self.offset < len(self.data)
    
    def peek_byte(self):
        """Peek at next byte without advancing offset"""
        if self.offset >= len(self.data):
            return None
        return self.data[self.offset]

class PacketBuilder:
    def __init__(self, packet_id):
        self.packet_id = packet_id
        self.buffer = bytearray()

    def write_int(self, value):
        """Write 4-byte integer (little-endian)"""
        self.buffer.extend(struct.pack('<I', value))
        
    def write_short(self, value):
        """Write 2-byte short (little-endian)"""
        self.buffer.extend(struct.pack('<H', value))

    def write_byte(self, value):
        """Write single byte"""
        self.buffer.extend(struct.pack('<B', value))

    def write_string(self, value):
        """Pascal String: Short Length + content (utf-8)"""
        encoded = value.encode('utf-8')
        self.write_short(len(encoded))
        self.buffer.extend(encoded)

    def write_string_null(self, value):
        """C-Style String: content (latin1) + 1 null byte"""
        encoded = value.encode('latin-1', errors='ignore')
        self.buffer.extend(encoded)
        self.write_byte(0)
    
    def write_bytes(self, data):
        """Write raw bytes"""
        self.buffer.extend(data)
    
    def get_size(self):
        """Get current buffer size"""
        return len(self.buffer)

    def build(self):
        """Build final packet"""
        return Packet(self.packet_id, bytes(self.buffer))