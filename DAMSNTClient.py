import os
import traceback
import optparse
import sys
import socket
import logging.config

if sys.version_info[0] < 3:
  import ConfigParser
else:
  import configparser as ConfigParser

from datetime import datetime,timedelta
from multiprocessing import Process, Queue, Event
import signal


class GracefulKiller:
  kill_now = False
  def __init__(self):
    signal.signal(signal.SIGINT, self.exit_gracefully)
    signal.signal(signal.SIGTERM, self.exit_gracefully)

  def exit_gracefully(self,signum, frame):
    self.kill_now = True

DAMS_PARITY_ERRORS = 0x0001
DAMS_BINARY_MESSAGE = 0x0002
DAMS_BINARY_MESSAGE_WITH_BIT_ERRORS = 0x0004
DAMS_LOSS_OF_LOCK_TERMINATION = 0x0008
DAMS_ADDITIONAL_MESSAGE_TIMES = 0x0010
DAMS_EXTENDED_QUALITY_STATS = 0x0020
class DAMSNTMessageHeader:
    def __init__(self, raw_message=None):
        # The start pattern can be provided by a host Client via the configuration command.  The default start pattern
        # is the.ASCII Characters SM followed by CR & LF.
        self._start_pattern = None
        #
        self._slot_num = None
        #DCS channel message was received from.
        self._channel = None
        #E or W: Other values may be implemented in the future
        self._spacecraft = None
        #0100, 0300, 1200
        self._baud = None
        #UTC Time of message start (i.e. frame synch)
        self._start_time = None
        #Signal strength in dB
        self._signal_strength = None
        #Sign character followed by 1 digit. In units of 50Hz
        self._freq_offset = None
        #N=normal, H=high, L=low
        self._modulation_index = None
        #N=normal, F=fair, P=poor
        self._data_quality = None
        #2 Characters representing error andmessage flags.
        '''
        Bit     ValueMeaning
        0x01    Message contains parity errors (for ASCII or pseudo-Binary messages only)
        0x02    Binary message (default = ASCII)
        0x04    Binary message with bit errors (reserved for future use).
        0x08    Loss of lock termination (i.e., no EOT)
        0x10    Message contains additional message times 
        0x20    Message contains extended quality statistics         
        '''
        self._error_flags = None
        #Original DCP Address Received from Platform
        self._orig_address = None
        #BCH corrected address. This field is always set, even if there were no errors.
        self._corrected_address = None
        #Number of message bytes to follow
        self._length = None
        if raw_message is not None:
            self.decipher_header(raw_message)

    def decipher_header(self, raw_message):
        self._start_pattern = raw_message[0:4].decode()
        self._slot_num = int(raw_message[4:7].decode())
        self._channel = int(raw_message[7:10].decode())
        self._spacecraft = raw_message[10:11].decode()
        self._baud = int(raw_message[11:15].decode())
        self._start_time = raw_message[15:26].decode()
        self._signal_strength = int(raw_message[26:28].decode())
        self._freq_offset = raw_message[28:30].decode()
        self._modulation_index = raw_message[30:31].decode()
        self._data_quality = raw_message[31:32].decode()
        self._error_flags = int(raw_message[32:34].decode())
        self._orig_address = raw_message[34:42].decode()
        self._corrected_address = raw_message[42:50].decode()
        self._length = int(raw_message[50:55].decode())

        return
    @property
    def start_pattern(self):
        return self._start_pattern
    @property
    def slot_num(self):
        return self._slot_num
    @property
    def channel(self):
        return self._channel
    @property
    def spacecraft(self):
        return self._spacecraft
    @property
    def baud(self):
        return self._baud
    @property
    def start_time(self):
        return self._start_time
    @property
    def signal_strength(self):
        return self._signal_strength
    @property
    def freq_offset(self):
        return self._freq_offset
    @property
    def modulation_index(self):
        return self._modulation_index
    @property
    def data_quality(self):
        return self._data_quality
    @property
    def error_flags(self):
        return self._error_flags
    @property
    def orig_address(self):
        return self._orig_address
    @property
    def corrected_address(self):
        return self._corrected_address
    @property
    def message_length(self):
        return int(self._length)

class DCPMessage:
    def __init__(self, raw_message):
        self._raw_message = None
        self._raw_header = None
        self._header = DAMSNTMessageHeader()
        self._msg_body = None
        self._msg_length = 0
    def decipher_raw(self, raw_bytes):
        try:
            self._raw_message = raw_bytes
            self._msg_length = len(self._raw_message)
            self._raw_header = self._raw_message[0:55]
            self._header.decipher_header(raw_bytes)
            end_msg_ndx = 55 + self._header.message_length
            self._msg_body = raw_bytes[55:end_msg_ndx]
            remainder = raw_bytes[end_msg_ndx:self._msg_length]
            #Check to see if message has additional message times.
            if self._header.error_flags & DAMS_ADDITIONAL_MESSAGE_TIMES:

                self._header.error_flags

            #Check to see if we have extended message stats.
            if self._header.error_flags & DAMS_EXTENDED_QUALITY_STATS:
                self._header.error_flags
            return True
        except Exception as e:
            traceback.print_exc()
        return False
    @property
    def header(self):
        return(self._header)
    @property
    def message(self):
        return(self._msg_body)
class DAPSMessageHeader:
    """
    DCP Message Format
    0 to 7 - 8 hex digit DCP Address
    8 to 19 - YYDDDHHMMSS
    20 1 character failure code
    21 to 22 2 decimal digit signal strength
    23 to 24 2 decimal digit frequency offset
    25 1 character modulation index
    26 1 character data quality indicator
    27 to 29 3 decimal digit GOES receive channel
    30 1 character GOES spacecraft indicator (E or W)
    31 to 32 2 character data source code Data Source Code Table
    33 to 37 5 decimal digit message data length
    """
    def __init__(self, raw_message):
        self._dcp_address = None
        self._message_time = None
        self._failure_code = None
        self._signal_strength = None
        self._freq_offset = None
        self._modulation_index = None
        self._quality_indicator = None
        self._channel = None
        self._spacecraft = None
        #Data source was never really implemented. It's now coopted to be used to indicate
        #where the message was received. If not set, it defaults to FF
        self._data_source = 'FF'
        self._message_length = None
        if raw_message is not None:
            self.decipher_header(raw_message)
        return
    def decipher_header(self, raw_message):
        return
    def create_from_damsheader(self, damsnt_header, data_source):
        try:
            self._dcp_address = damsnt_header.corrected_address
            self._message_time = damsnt_header.start_time
            self._failure_code = 'G'
            if damsnt_header.error_flags & DAMS_PARITY_ERRORS:
                self._failure_code = '?'
            self._signal_strength = damsnt_header.signal_strength
            self._freq_offset = damsnt_header.freq_offset
            self._modulation_index = damsnt_header.modulation_index
            self._quality_indicator = damsnt_header.data_quality
            self._channel = damsnt_header.channel
            self._spacecraft = damsnt_header.spacecraft
            #Data source was never really implemented. It's now coopted to be used to indicate
            #where the message was received.
            self._data_source = data_source
            self._message_length = damsnt_header.message_length
            return True
        except Exception as e:
            traceback.print_exc()
        return False
    @property
    def dcp_address(self):
        return self._dcp_address
    @property
    def message_time(self):
        return self._message_time
    @property
    def failure_code(self):
        return self._failure_code
    @property
    def signal_strength(self):
        return self._signal_strength
    @property
    def freq_offset(self):
        return self._freq_offset
    @property
    def modulation_index(self):
        return self._modulation_index
    @property
    def quality_indicator(self):
        return self._quality_indicator
    @property
    def channel(self):
        return self._channel
    @property
    def spacecraft(self):
        return self._spacecraft
    @property
    def data_source(self):
        return self._data_source
    @property
    def message_length(self):
        return self._message_length


class DAPSMessage:
    def __init__(self, raw_message):
        self._raw_message = None
        self._raw_header = None
        self._header = DAPSMessageHeader(raw_message=raw_message)
        self._msg_body = None
        self._msg_length = 0

    def decipher_message(self, raw_message):
        return

    def from_dams_message(self, dams_message, data_sources):
        self._header.create_from_damsheader(dams_message.header, data_sources)
        self._msg_body = dams_message.message[0:dams_message.header.message_length]

    def create_raw(self):
        header = "%8s%11s%1s%02d%2s%1s%1s%03d%1s%2s%05d" %\
                 (self._header.dcp_address,
                  self._header.message_time,
                  self._header.failure_code,
                  self._header.signal_strength,
                  self._header.freq_offset,
                  self._header.modulation_index,
                  self._header.quality_indicator,
                  self._header.channel,
                  self._header.spacecraft,
                  self._header.data_source,
                  self._header.message_length)
        msg = header + self._msg_body[0:self._header.message_length-1].decode()
        return msg
class DAMSComm(Process):
    def __init__(self, ip_address, port, data_queue, message_length, socket_timeout, socket_log_conf):
        Process.__init__(self)

        self._ip_address = ip_address
        self._port = port
        self._data_queue = data_queue
        self._message_length = message_length
        self._socket_timeout = socket_timeout
        self._socket_log_config = socket_log_conf
        self._shutdown_event = Event()

    def close(self):
        self._shutdown_event.set()
        return
    def connect(self):
        try:
            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM)
            sock.settimeout(self._socket_timeout)
            sock.connect((self._ip_address,self._port))
            return sock
        except Exception as e:
            raise e
        return None

    def run(self):
        reconnect_attempts = 10
        reconnect_cnt = 0
        process_data = True
        logger = None
        try:
            logging.config.fileConfig(self._socket_log_config)
            logger = logging.getLogger()
            logger.info('Socket logging file opened.')

            logger.info("Connecting to ip: %s port: %d" % (self._ip_address, self._port))
            try:
                sock = self.connect()
            except Exception as e:
                logger.error("Failed to connect to ip: %s port: %d" % (self._ip_address, self._port))
                logger.exception(e)
            while process_data:
                if not self._shutdown_event.is_set():
                    if sock is not None:
                        try:
                            data = sock.recv(self._message_length)
                            if len(data) > 0:
                                self._data_queue.put(data)
                            else:
                                sock.close()
                                logger.error("Disconnected, attempted reconnect.")
                                sock = None
                            reconnect_cnt = 0

                        except socket.timeout as e:
                            logger.error("Socket timed out. Closing for reconnect.")
                            sock.close()
                            sock = None
                            reconnect_cnt = 0

                        except Exception as e:
                            traceback.print_exc()
                    else:
                        if reconnect_cnt <= reconnect_attempts:
                            logger.error("Reconnect: %d to ip: %s port: %d"\
                                         % (reconnect_cnt, self._ip_address, self._port))
                            try:
                                sock = self.connect()
                            except Exception as e:
                                logger.error("Failed to connect to ip: %s port: %d" % (self._ip_address, self._port))
                                logger.exception(e)

                            reconnect_cnt += 1
                        else:
                            logger.error("Exceeded reconnect attempts, exiting.")
                            process_data = False
                else:
                    logger.info("Shutdown event signalled.")
                    process_data = False
                    sock.close()
        except Exception as e:
            if logger is not None:
                logger.debug(e)
            else:
                traceback.print_exc()

def daps_output(dcp_message, daps_output_file):
    #print("ID: %s Length: %d" % (dcp_message.header.corrected_address, dcp_message.header.message_length))
    daps_msg = DAPSMessage(raw_message=None)
    daps_msg.from_dams_message(dams_message=dcp_message, data_sources='SC')
    raw_message = daps_msg.create_raw()
    print(raw_message)
    if daps_output_file is not None:
        daps_output_file.write(raw_message)
        daps_output_file.write('\r\n')
        daps_output_file.flush()
    return

def main():
    MSGLEN=4096
    parser = optparse.OptionParser()

    parser.add_option("--ConfigFile", dest="config_file",
                      help="")
    (options, args) = parser.parse_args()
    try:
        config_file = ConfigParser.RawConfigParser()
        config_file.read(options.config_file)

        ip_address = config_file.get('network', 'ip')
        port = config_file.getint('network', 'port')
        socket_timeout= config_file.getint('network', 'socket_timeout')

        output_directory = config_file.get('output', 'directory')
        output_daps = config_file.getboolean('output', 'output_daps')
        output_damsnt = config_file.getboolean('output', 'output_damsnt')

        app_logging  = config_file.get('logging', 'app')
        socket_logging  = config_file.get('logging', 'socket')
    except Exception as e:
        traceback.print_exc()
    else:
        graceful_exit_handler = GracefulKiller()

        message_queue = Queue()
        #ip_address, port, data_queue, message_length):
        dams_sock = DAMSComm(ip_address=ip_address, port=port,
                             data_queue=message_queue,
                             message_length=MSGLEN,
                             socket_timeout=socket_timeout,
                             socket_log_conf=socket_logging)
        dams_sock.start()
        rec_count = 0
        now_time = datetime.now()
        #We want to create a new raw file each new day.
        today = datetime(year=now_time.year, month=now_time.month, day=now_time.day,
                         hour=0, minute=0, second=0)
        daps_output_file = None
        one_day_delta = timedelta(days=1)
        #while dams_sock.is_alive():
        while not graceful_exit_handler.kill_now:
            if dams_sock.is_alive():
                data_rec = message_queue.get()
                print(data_rec)
                dcp_message = DCPMessage(raw_message=None)
                dcp_message.decipher_raw(data_rec)
                new_file = False
                #Check if we're in a new day every hundred records.
                if (rec_count % 100) == 0:
                    #If it's the next day, we want to create a new output file.
                    if datetime.now() - today > one_day_delta:
                        new_file = True
                        now_time = datetime.now()
                        today = datetime(year=now_time.year, month=now_time.month, day=now_time.day,
                                 hour=0, minute=0, second=0)
                if output_daps:
                    if new_file or daps_output_file is None:
                        try:
                            if daps_output_file is not None:
                                daps_output_file.close()
                            daps_output_filename = os.path.join(output_directory, "daps_%s.RAW" % (now_time.strftime('%Y%m%d_%H%M%S')))
                            daps_output_file = open(daps_output_filename, "w")
                        except Exception as e:
                            traceback.print_exc(e)
                            daps_output_file = None
                    daps_output(dcp_message, daps_output_file)
                rec_count += 1

        dams_sock.close()
        if daps_output_file is not None:
            daps_output_file.close()
        dams_sock.join()
    return


if __name__=="__main__":
    main()