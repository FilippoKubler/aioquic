import logging.config
import sys, os
import logging

class Colors:
    """ ANSI color codes """
    BLACK = "\033[0;30m"
    RED = "\033[0;31m"
    GREEN = "\033[0;32m"
    BROWN = "\033[0;33m"
    BLUE = "\033[0;34m"
    PURPLE = "\033[0;35m"
    CYAN = "\033[0;36m"
    LIGHT_GRAY = "\033[0;37m"
    DARK_GRAY = "\033[1;30m"
    LIGHT_RED = "\033[1;31m"
    LIGHT_GREEN = "\033[1;32m"
    YELLOW = "\033[1;33m"
    LIGHT_BLUE = "\033[1;34m"
    LIGHT_PURPLE = "\033[1;35m"
    LIGHT_CYAN = "\033[1;36m"
    LIGHT_WHITE = "\033[1;37m"
    BOLD = "\033[1m"
    FAINT = "\033[2m"
    ITALIC = "\033[3m"
    UNDERLINE = "\033[4m"
    BLINK = "\033[5m"
    NEGATIVE = "\033[7m"
    CROSSED = "\033[9m"
    END = "\033[0m"


# Disable
def blockPrint():
    sys.stdout = open(os.devnull, 'w')

# Restore
def enablePrint():
    sys.stdout = sys.__stdout__


# Variables to handle fragmented packets
residual_peer                       = ''
residual_handshake_type             = ''
residual_packet_size                = 0
fragmented_plain_packet_payload     = b''
fragmented_encrypted_packet_payload = b''
fragmented_packet_size              = 0


# RFC 9000 16. Variable-Length Integer Encoding - Length and Offset fields are variable-length integers.
def quic_length_decoder(field: bytes) -> int:
    """
    Helper to decode how many bytes Length and Offset fields use in QUIC packets.

    :param field: Field to decode.

    :return: The number of bytes used by the field.
    """

    top_2_bits = ''.join(format(byte, '08b') for byte in bytes.fromhex(field.hex()))[:2]

    length_size = 0
    match(top_2_bits):
        case '00':
            length_size = 1
        case '01':
            length_size = 2
        case '10':
            length_size = 4
        case '11':
            length_size = 8
            
    return length_size


def quic_datagram_decomposer(peer: str, quic_logger_frames, plain_payload: bytes, encrypted_payload: bytes):
    """
    Decompose QUIC Datagram into Frames and extract TLS1.3 Hnadshake Packets and HTTP3 Requests and Responses.

    :param peer:                side of the communication (CLIENT or SERVER).
    :param quic_logger_frames:  List of Dicts where are saved which types of Frames are inside the QUIC Datagram.
    :param plain_payload:       QUIC Datagram Plaintext.
    :param encrypted_payload:   QUIC Datagram Ciphertext.
    """

    # Variables to handle fragmented packets
    global residual_packet_size, fragmented_packet_size, residual_handshake_type, fragmented_plain_packet_payload, fragmented_encrypted_packet_payload, residual_peer
    

    # Disable print if --verbose arg is not used
    if logging.root.level == logging.INFO:
        blockPrint()
    
    peer = (Colors.BLUE + peer) if peer == 'CLIENT' else (Colors.RED + peer)
    peer += Colors.END

    print('\n\n' + '~'*95)
    print('~'*23 + f'\t\t{peer} - Plaintext Packet\t\t'.ljust(35) + '~'*23)
    print('~'*95 + '\n')

    # Print info about which frame is fragmented and how many bytes are expected to complete the frame
    if residual_packet_size > 0 and peer in residual_peer:
        print('Residual bytes from previous QUIC Packet:', residual_handshake_type, residual_packet_size, end='\n\n')

    print(quic_logger_frames)
    
    # Lengths of the Frames of interest
    plain_length                = len(plain_payload)
    ack_length                  = 0
    crypto_length               = 0
    padding_length              = 0
    stream_length               = 0
    connection_close_length     = 0

    encrypted_string = ''

    for frame in quic_logger_frames:
        match(frame['frame_type']):
            case 'ack':
                if plain_payload[:1].hex() == '02': # ACK Frame
                    ack_length = 6 # All field are Variable-Length Integers
                    
                    print(f'{Colors.YELLOW}ACK{Colors.END}:', ack_length, plain_payload[:ack_length].hex(), '\n')
                    plain_payload = plain_payload[ack_length:]

                    encrypted_string += f'{Colors.YELLOW}ACK{Colors.END}: {ack_length} {encrypted_payload[:ack_length].hex()}\n\n'
                    encrypted_payload = encrypted_payload[ack_length:]
            
            case 'crypto':
                if plain_payload[:1].hex() == '06': # CRYPTO Frame

                    crypto_header_length = 1

                    offset_size = quic_length_decoder(plain_payload[crypto_header_length:crypto_header_length+1])
                    crypto_header_length += offset_size

                    length_size = quic_length_decoder(plain_payload[crypto_header_length:crypto_header_length+1])
                    crypto_header_length += length_size
                    
                    # CRYPTO Frame length
                    crypto_length               = crypto_header_length + frame['length']

                    # Plaintext and Ciphertext of CRYPTO Header and Payload
                    plain_crypto_header         = plain_payload[:crypto_header_length]
                    plain_crypto_payload        = plain_payload[crypto_header_length : crypto_length]
                    encrypted_crypto_header     = encrypted_payload[:crypto_header_length]
                    encrypted_crypto_payload    = encrypted_payload[crypto_header_length : crypto_length]

                    # Check if previous CRYPTO Frame was fragmented
                    if residual_packet_size > 0:

                        # Valutare caso in cui il nuovo CRYPTO non contenga tutti dati necessari a completare il pacchetto precedente

                        residual_plain_payload  = plain_crypto_payload[:residual_packet_size]
                        print(f'\n{Colors.BLACK}Residaul Packet Payload{Colors.END} | {residual_handshake_type}:', fragmented_packet_size, fragmented_plain_packet_payload.hex(), '-', residual_packet_size, residual_plain_payload.hex(), end=' .\n\n')

                        residual_encrypted_payload = encrypted_crypto_payload[:residual_packet_size]
                        encrypted_string += f'\n{Colors.BLACK}Residaul Packet Payload{Colors.END} | {residual_handshake_type}: {fragmented_packet_size} {fragmented_encrypted_packet_payload.hex()} - {residual_packet_size} {residual_encrypted_payload.hex()} .\n\n'
                        
                        # Remove residual bytes from Plaintext and Ciphertext
                        plain_crypto_payload                = plain_crypto_payload[residual_packet_size:]
                        encrypted_crypto_payload            = encrypted_crypto_payload[residual_packet_size:]

                        # RESET Parameters
                        residual_peer                       = ''
                        residual_handshake_type             = ''
                        residual_packet_size                = 0
                        fragmented_plain_packet_payload     = b''
                        fragmented_encrypted_packet_payload = b''
                        fragmented_packet_size              = 0


                    print(f'{Colors.GREEN}CRYPTO{Colors.END}:', crypto_header_length, plain_crypto_header.hex(), end=' | ')

                    encrypted_string += f'{Colors.GREEN}CRYPTO{Colors.END}: {crypto_header_length} {encrypted_crypto_header.hex()} | '
                    
                    # Loop to find all Packets inside CRYPTO Frame
                    while True:

                        # End when all Packets are categorized
                        if len(plain_crypto_payload) == 0:
                            break

                        handshake_type = Colors.LIGHT_BLUE if 'CLIENT' in peer else Colors.LIGHT_RED

                        match(plain_crypto_payload[:1].hex()):
                            case '01':
                                handshake_type += 'ClientHello'
                            case '02':
                                handshake_type += 'ServerHello'
                            case '04':
                                handshake_type += 'NewSessionTicket'
                            case '08':
                                handshake_type += 'EncryptedExtensions'
                            case '0b':
                                handshake_type += 'Certificate'
                            case '0f':
                                handshake_type += 'CertificateVerify'
                            case '14':
                                handshake_type += 'Finished'
                            case _:
                                handshake_type += 'NotFound'

                        handshake_type += Colors.END
                        
                        handshake_packet_length = (int(plain_crypto_payload[1:4].hex(), 16) + 4) # + 4 = 3 bytes of the length field + 1 byte of the type field

                        # Da gestire il caso in cui siano presenti più Pacchetti nello stesso Record Layer

                        # Check if Packet is Fragmented
                        if len(plain_crypto_payload) < handshake_packet_length:
                            residual_packet_size                = handshake_packet_length - len(plain_crypto_payload)
                            fragmented_packet_size              = len(plain_crypto_payload)
                            residual_handshake_type             = handshake_type
                            fragmented_plain_packet_payload     = plain_crypto_payload[:handshake_packet_length]
                            fragmented_encrypted_packet_payload = encrypted_crypto_payload[:handshake_packet_length]
                            residual_peer                       = peer

                            print(f'{Colors.BLACK}FRAGMENTED{Colors.END} - {residual_handshake_type}:', handshake_packet_length, fragmented_packet_size, fragmented_plain_packet_payload.hex(), residual_packet_size, end=' |\n')
                            plain_crypto_payload = plain_crypto_payload[handshake_packet_length:]

                            encrypted_string += f'{Colors.BLACK}FRAGMENTED{Colors.END} - {residual_handshake_type}: {handshake_packet_length} {fragmented_packet_size} {fragmented_encrypted_packet_payload.hex()} {residual_packet_size} |\n'
                            encrypted_crypto_payload = encrypted_crypto_payload[handshake_packet_length:]

                            continue

                        # Print detected Packets
                        if 'NotFound' not in handshake_type:
                            print(f'{handshake_type}:', handshake_packet_length, plain_crypto_payload[:handshake_packet_length].hex(), end=' | ')
                            plain_crypto_payload = plain_crypto_payload[handshake_packet_length:]

                            encrypted_string += f'{handshake_type}: {handshake_packet_length} {encrypted_crypto_payload[:handshake_packet_length].hex()} | '
                            encrypted_crypto_payload = encrypted_crypto_payload[handshake_packet_length:]

                    # Remove CRYPTO Frame from Plaintext and Ciphertext
                    plain_payload       = plain_payload[crypto_length:]
                    encrypted_payload   = encrypted_payload[crypto_length:]

                    print('\n')
                    encrypted_string += '\n\n'
            
            case 'padding':
                if plain_payload[:1].hex() == '00': # PADDING Frame
                    padding_length = plain_length - ack_length - crypto_length
                    print(f'{Colors.LIGHT_WHITE}PADDING{Colors.END}:', padding_length, plain_payload.hex(), '\n')

                    encrypted_string += f'{Colors.LIGHT_WHITE}PADDING{Colors.END}: {padding_length} {encrypted_payload.hex()}\n\n'
            
            case 'stream':
                if frame['stream_id'] == 0: # STREAM Frame for HTTP3

                    stream_header_length = 1

                    stream_size = quic_length_decoder(plain_payload[stream_header_length:stream_header_length+1])
                    stream_header_length += stream_size

                    offset_size = 0 if frame['offset'] == 0 else quic_length_decoder(plain_payload[stream_header_length:stream_header_length+1])
                    stream_header_length += offset_size

                    length_size = quic_length_decoder(plain_payload[stream_header_length:stream_header_length+1])
                    stream_header_length += length_size
                    
                    # STREAM Frame length
                    stream_length               = stream_header_length + frame['length']

                    # Plaintext and Ciphertext of FRAME Header and Payload
                    plain_stream_header         = plain_payload[:stream_header_length]
                    plain_stream_payload        = plain_payload[stream_header_length : stream_length]
                    encrypted_stream_header     = encrypted_payload[:stream_header_length]
                    encrypted_stream_payload    = encrypted_payload[stream_header_length : stream_length]

                    http3_direction = 'HTTP3 REQUEST' if 'CLIENT' in peer else 'HTTP3 RESPONSE'
                    print(f'{Colors.DARK_GRAY}STREAM{Colors.END}:', stream_header_length, plain_stream_header.hex(), f'| {Colors.LIGHT_GRAY}{http3_direction}{Colors.END}:', frame['length'], plain_stream_payload.hex(), '\n')
                    plain_payload       = plain_payload[stream_length:]

                    encrypted_string += f'{Colors.DARK_GRAY}STREAM{Colors.END}: {stream_header_length} {encrypted_stream_header.hex()} | {Colors.LIGHT_GRAY}{http3_direction}{Colors.END}: {frame["length"]} {encrypted_stream_payload.hex()}\n'
                    encrypted_payload   = encrypted_payload[stream_length:]

            case 'connection_close': # CONNECTION_CLOSE Frame (RFC 9000 19.19. CONNECTION_CLOSE Frames)

                connection_close_length = len(plain_payload)

                if plain_payload[:1].hex() == '1d': 
                    
                    print(f'{Colors.BLACK}CONNECTION CLOSE{Colors.END}:', connection_close_length, plain_payload.hex(), '| Error Code:', frame['error_code'], '' if frame["reason"] == '' else f'and Reason:{frame["reason"]}', '\n')

                    reason = '' if frame["reason"] == '' else f'and Reason:{frame["reason"]}'
                    encrypted_string += f'{Colors.BLACK}CONNECTION CLOSE{Colors.END}: {connection_close_length} {encrypted_payload.hex()} | Error Code: {frame["error_code"]} {reason}\n\n'

                elif plain_payload[:1].hex() == '1c':
                    
                    print(f'{Colors.BLACK}CONNECTION CLOSE{Colors.END}:', connection_close_length, plain_payload.hex(), '\n')

                    encrypted_string += f'{Colors.BLACK}CONNECTION CLOSE{Colors.END}: {connection_close_length} {encrypted_payload.hex()}\n\n'

    # Print of the encrypted parts
    print('\n' + '~'*95)
    print('~'*23 + f'\t\t{peer} - {Colors.UNDERLINE}Encrypted Packet{Colors.END}\t\t'.ljust(45) + '~'*23)
    print('~'*95 + '\n')
    print(encrypted_string + '\n\n')
    
    if logging.root.level == logging.INFO:
        enablePrint()