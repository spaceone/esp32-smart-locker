import ujson
import os
from machine import Pin, SoftSPI
import time
from mfrc522 import MFRC522
import _thread
import random
import asyncio


class SimpleINIParser:
    """
    A simple INI-style configuration file parser.
    Reads key-value pairs from a file with format: key=value.
    Ignores empty lines and comments starting with '#'.
    """
    
    def __init__(self, filename):
        """Initialize the parser with a given filename."""
        self.filename = filename
        self.data = {}
        self._load()

    def _load(self):
        """Load key-value pairs from the file into a dictionary."""
        try:
            with open(self.filename, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue  # Skip empty lines and comments
                    if "=" in line:
                        key, value = map(str.strip, line.split("=", 1))
                        self.data[key] = value
        except OSError:
            pass  # Handle missing file gracefully

    def get(self, key, default=None):
        """Retrieve the value associated with a key, or return a default value."""
        return self.data.get(key, default)

    def set(self, key, value):
        """Set a key-value pair and save it to the file."""
        self.data[key] = value
        self._save()

    def _save(self):
        """Save the current key-value pairs back to the file."""
        with open(self.filename, "w") as f:
            for key, value in self.data.items():
                f.write(f"{key}={value}\n")

    def set_hex(self, key, hex_values):
        """Store a list of hex values as a hex string prefixed with '0x'."""
        hex_string = '0x' + ''.join(f"{x:02X}" for x in hex_values)
        self.set(key, hex_string)

    def get_hex(self, key, default=None):
        """Retrieve a hex string prefixed with '0x' and convert it back to a list of integers."""
        hex_string = self.get(key, default)
        if hex_string is None or not hex_string.startswith("0x"):
            return default
        hex_string = hex_string[2:]  # Remove '0x' prefix
        return [int(hex_string[i:i+2], 16) for i in range(0, len(hex_string), 2)]


config = SimpleINIParser("config.ini")


# def load_credentials():
#     with open("credentials.txt", "r") as f:
#         username = f.readline().strip()
#         password = f.readline().strip()
#     return username, password
# 
# USERNAME, PASSWORD = load_credentials()
# 
#
# def load_authorized_uids():
#     try:
#         with open("/authorized_uids.json", "r") as f:
#             return ujson.load(f)
#     except:
#         return []
#     
#
# _tags = load_authorized_uids()
#
# def save_authorized_uids(tags):
#     global _tags
#     with open("/authorized_uids.json", "w") as f:
#         ujson.dump(tags, f)
#     _tags = tags
# 
# 
# def add_uid(uid, username, timestamp):
#     global _tags
#     if not is_uid_registered(uid):
#         _tags.append(dict(uid=uid, username=username, timestamp=timestamp))
#         save_authorized_uids(_tags)
# 
# 
# def remove_uid(uid):
#     global _tags
#     tags = [i for i in _tags if i['uid'] != uid]
#     if len(tags) != len(_tags):
#         save_authorized_uids(tags)
# 
# 
# def is_uid_registered(uid):
#     global _tags
#     uids = set([i['uid'] for i in _tags])
#     return uid in uids


# RFID keys
DEFAULT_KEY = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
CUSTOM_KEY = config.get_hex('key')


sck = Pin(14, Pin.OUT)
mosi = Pin(15, Pin.OUT)
miso = Pin(35)
spi = SoftSPI(baudrate=1000000, polarity=0, phase=0, sck=sck, mosi=mosi, miso=miso)
sda = Pin(2, Pin.OUT)
reader = MFRC522(spi, sda)
reader_lock = asyncio.Lock()

# Data sector to use
SECTOR_META = 1
SECTOR_USERNAME = 2
SECTOR_COLLMEX_ID = 3
SECTOR_PASSWORD = 4

# Access flags
FLAG_DOOR = 0b0001
FLAG_CASH_REGISTER = 0b0010


class RFIDException(Exception):
    """Base exception class for all RFID-related errors."""
    pass

class NoCardDetectedException(RFIDException):
    """Raised when no RFID card is detected within the timeout."""
    pass

class AccessDeniedException(RFIDException):
    """Raised when an unauthorized card tries to access the system."""
    pass

class AuthenticationFailureException(RFIDException):
    """Raised when authentication with an RFID key fails."""
    pass

class ReadWriteFailureException(RFIDException):
    """Raised when reading from or writing to the RFID card fails."""
    pass

class UnexpectedMetaDataException(RFIDException):
    """Raised when the expected meta data is not as expected."""
    pass



def get_start_block(sector):
    """
    Calculate the starting block for the sector
    The first 32 sectors (0–31) each have 4 blocks: 32 × 4 = 128 blocks.
    Starting from sector 32, each sector has 16 blocks.
    """
    if sector < 32:
        return sector * 4
    return 128 + (sector - 32) * 16


def get_sector_trailer(sector):
    """
    Returns for the given sector the trailing block, i.e. the 4th block for sectors 0-31
    and the 16th block for sectors >= 32.
    """
    if sector < 32:  # Sectors 0–31 (4-block sectors)
        return (sector * 4) + 3
    else:  # Sectors 32–39 (16-block sectors)
        return (sector * 16) + 15


def write_multiple_blocks(sector, data, uid, key=DEFAULT_KEY):
    """
    Write data string (UTF-8 encoded) into the sector blocks (over all data blocks of the sector).
    """
    start_block = get_start_block(sector)

    # Convert string to bytes if necessary
    if isinstance(data, str):
        data = data.encode("utf-8")  # Convert string to bytes

    # Ensure data is exactly 3 blocks with 16 bytes each (48 bytes)
    if len(data) > 48:
        raise ReadWriteFailureException("Data exceeds the maximum size of 3 blocks (48 bytes).")

    # Pad the data to fill all 15 blocks
    if len(data) < 48:
        data += b'\x00' * (48 - len(data))

    if reader.auth(reader.AUTH, start_block, key, uid) != reader.OK:
        raise AuthenticationFailureException(f"Sector {sector} authentication failure.")
    
    # Write the data block by block
    for i in range(0, 48, 16):
        block_number = start_block + (i // 16)
        block_data = data[i:i + 16]
        if reader.write(block_number, block_data) != reader.OK:
            raise ReadWriteFailureException(f"Failed to write Block {block_number}.")


def read_multiple_blocks(sector, uid, key=DEFAULT_KEY):
    """
    Read data from all blocks of the given sector and return the data as string (UTF-8 encoded).
    """
    start_block = get_start_block(sector)

    # Buffer to hold the read data
    data = b''

    # Authenticate for the block
    if reader.auth(reader.AUTH, start_block, key, uid) != reader.OK:
        raise AuthenticationFailureException(f"Sector {sector} authentication failure.")

    # Read the data block by block
    for i in range(3):  # 3 blocks to read
        block_number = start_block + i
        # Read the block
        block_data = reader.read(block_number)
        if block_data:
            data += bytes(block_data)  # Append the read data to the buffer
        else:
            raise ReadWriteFailureException(f"Failed to read Block {block_number}.")

    # Remove null bytes and convert to string
    return data.rstrip(b'\x00').decode('utf-8')


# Decorator to handle card detection
def card_action(func):
    """
    Decorator function for reading and accessing an RFID tag.
    """
    async def wrapper(*args, **kwargs):
        async with reader_lock:
            status, tag_type = reader.request(reader.CARD_REQIDL)
            if status != reader.OK:
                raise NoCardDetectedException("No RFID card detected.")
            
            print(f"Card detected! Tag Type: 0x{tag_type:02X}")
            if tag_type == 0x08:
                print("MIFARE Classic 1K detected.")
            elif tag_type == 0x10:
                print("MIFARE Classic 4K detected.")
            elif tag_type == 0x04:
                print("MIFARE Ultralight detected.")
            elif tag_type == 0x44:
                print("MIFARE DESFire detected.")
            elif tag_type == 0x20:
                print("MIFARE Plus detected.")
            elif tag_type == 0x40:
                print("MIFARE Mini detected.")
            else:
                print("Unknown or unsupported card type.")                    
            (status, raw_uid) = reader.anticoll()
            uid_str = '0x' + (''.join('%02X' % i for i in raw_uid))
            if status != reader.OK:
                raise ReadWriteFailureException(f"Failed to access card with UID: {uid_str}")
            
            print(f"Card detected. UID: {uid_str}")
            if reader.select_tag(raw_uid) != reader.OK:
                raise AccessDeniedException(f'Failed to select RFID tag with UID: {uid_str}')
            try:
                # Call the decorated function with the UID
                return func(raw_uid, *args, **kwargs)
            finally:
                # Ensure the crypto operation is stopped
                reader.stop_crypto1()

    return wrapper


@card_action
def test_auth(uid, key):
    return _test_auth(uid, key)


def _test_auth(uid, key):
    # Authenticate with the default key
    for isector in (SECTOR_META, SECTOR_USERNAME, SECTOR_COLLMEX_ID, SECTOR_PASSWORD):
        istart_block = get_start_block(isector)
        if reader.auth(reader.AUTH, istart_block, key, uid) != reader.OK:
            print(f"Cannot access sector {isector} with key {key}")
            return False
    return True


@card_action
def set_key(uid, sector, old_key, new_key):
    return _set_key(uid, sector, old_key, new_key)

    
def _set_key(uid, sector, old_key, new_key):
    # Authenticate with the default key
    access_block = get_sector_trailer(sector)
    if reader.auth(reader.AUTH, access_block, old_key, uid) != reader.OK:
        raise AuthenticationFailureException(f"Given key {old_key} does not work for sector {sector} or the card already has a custom key.")
        
    print(f"Given key works for sector {sector}. Resetting access block to new key.")
    
    # Construct the new sector trailer data
    new_key_data = bytes(new_key + [0xFF, 0x07, 0x80, 0x69] + new_key)

    # Write the new key and access conditions
    if reader.write(access_block, new_key_data) != reader.OK:
        raise ReadWriteFailureException(f"Failed to update the key for sector {sector}.")
    print(f"Key updated successfully for sector {sector}.")


@card_action
def set_key_for_all_sectors(uid, old_key, new_key):
    for isector in (SECTOR_META, SECTOR_USERNAME, SECTOR_COLLMEX_ID, SECTOR_PASSWORD):
        _set_key(uid, isector, old_key, new_key)


# Write data function
@card_action
def write_data(uid, username, ID, password, key=None, flags=None):
    if flags is None:
        flags = FLAG_DOOR | FLAG_CASH_REGISTER
        
    if key is None:
        if _test_auth(uid, config.get_hex('key')):
            print(f"Using custom key for writing data")
            key = config.get_hex('key')
        elif _test_auth(uid, DEFAULT_KEY):
            print(f"Using factory default key for writing data")
            key = DEFAULT_KEY
        else:
            raise AuthenticationFailureException("Cannot acccess RFID card with known keys!")

    meta_data = f"{config.get('meta_prefix')}_{flags}"
    for isector, idata in (
            (SECTOR_META, meta_data),
            (SECTOR_USERNAME, username),
            (SECTOR_COLLMEX_ID, ID),
            (SECTOR_PASSWORD, password)):
        write_multiple_blocks(isector, idata, uid, key)
    print("Data written successfully.")
        

# Read data function
@card_action
def read_data(uid, key=None):
    print(f'key={key}')
    if key is None:
        print(f'#1')
        if _test_auth(uid, config.get_hex('key')):
            print(f"Using custom key for reading data")
            key = config.get_hex('key')
        elif _test_auth(uid, DEFAULT_KEY):
            print(f"Using factory default key for writing data")
            key = DEFAULT_KEY
        else:
            raise AuthenticationFailureException("Cannot acccess RFID card with known keys!")
        print(f'key={key}')

    # check for the correct format and prefix of the meta data string
    # expected format is: <PREFiX>_<FLAGS>
    meta_data = read_multiple_blocks(SECTOR_META, uid, key)
    if "_" not in meta_data:
        raise UnexpectedMetaDataException('The meta data sector did not match the expected format!')
    meta_prefix, flags = meta_data.split("_", 1)
    flags = int(flags)
    if not meta_prefix == config.get('meta_prefix'):
        raise UnexpectedMetaDataException(f'The prefix in the meta data sector was {meta_prefix}, however, expected was {config.get("meta_prefix")}')
    
    # read more data from the other sectors
    username = read_multiple_blocks(SECTOR_USERNAME, uid, key)
    collmex_id = read_multiple_blocks(SECTOR_COLLMEX_ID, uid, key)
    password = read_multiple_blocks(SECTOR_PASSWORD, uid, key)
    print(f'Meta data: {meta_data}\nUsername: {username}\nCollmex ID: {collmex_id}')
    return dict(uid=uid, username=username, collmex_id=collmex_id, password=password, flags=flags, meta_prefix=meta_prefix)


async def open_cash_register():
    relay = Pin(13, Pin.OUT)
    relay.value(0)
    await asyncio.sleep_ms(300)
    relay.value(1)
    

def start_rfid_reading():
    asyncio.create_task(_rfid_reading())


async def _rfid_reading():
    while True:
        try:
            # TODO: Change key
            # TODO: Check blocking list
            rfid_data = await read_data(DEFAULT_KEY)
            has_acccess_to_cash_register = rfid_data["flags"] & FLAG_CASH_REGISTER
            if has_acccess_to_cash_register:
                print(f"Key {rfid_data['uid']} is authorized to open the cash register!")
                await open_cash_register()
                print("")
        except NoCardDetectedException as e:
            pass  # silent
        except RFIDException as e:
            print(f"Failed to read the RFID tag: {e}\n")
        await asyncio.sleep_ms(250)



