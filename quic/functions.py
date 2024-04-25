from colorama import Fore, Style
'''
Fore: BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE, RESET.
Style: DIM, NORMAL, BRIGHT, RESET_ALL
'''

residual_packet_size        = 0
residual_handshake_type     = ''
fragmented_packet_payload   = ''

def quic_length_decoder(length):
    length_size = 0
    match(length):
        case '00':
            length_size = 1
        case '01':
            length_size = 2
        case '10':
            length_size = 4
        case '11':
            length_size = 8
            
    return int(length_size)


def quic_packet_decompose(peer, quic_logger_frames, plain_payload, encrypted_payload):
    global residual_packet_size, residual_handshake_type, fragmented_packet_payload
    print('Residual bytes from previous QUIC Packet:', residual_handshake_type, residual_packet_size, end='\n')
    
    peer = (Fore.BLUE + peer) if peer == 'CLIENT' else (Fore.RED + peer)
    peer += Fore.RESET

    print(quic_logger_frames)
    
    plain_length        = len(plain_payload)
    ack_length          = 0
    crypto_length       = 0
    padding_length      = 0
    for frame in quic_logger_frames:
        match(frame['frame_type']):
            case 'ack': # da adattare negli casi in cui gli altri parametri sono presenti
                if plain_payload[:1].hex() == '02':
                    #if frame['acked_ranges'][0] == [0, 0] or frame['acked_ranges'][0] == [1, 1]:
                    ack_length = 6
                    
                    print(peer, f'- Plaintext Packet | {Fore.YELLOW}ACK:{Fore.RESET}', ack_length, plain_payload[:ack_length].hex(), '\n')
                    plain_payload = plain_payload[ack_length:]
            
            case 'crypto':
                if plain_payload[:1].hex() == '06':

                    # print(plain_payload.hex())

                    #  RFC 9000 16. Variable-Length Integer Encoding - i campi Length sono di dimensione variabile
                    offset_binary_string = ''.join(format(byte, '08b') for byte in bytes.fromhex(plain_payload[1:2].hex()))
                    # print(plain_payload[1:2].hex(), offset_binary_string)
                    offset_size = quic_length_decoder(offset_binary_string[:2])

                    length_binary_string = ''.join(format(byte, '08b') for byte in bytes.fromhex(plain_payload[1+offset_size : 2+offset_size].hex()))
                    # print(plain_payload[1+offset_size : 2+offset_size].hex(), length_binary_string)
                    length_size = quic_length_decoder(length_binary_string[:2])

                    # print(offset_size, length_size)
                    
                    crypto_length   = frame['length'] + 1 + offset_size + length_size
                    crypto_header   = plain_payload[:1 + offset_size + length_size].hex()
                    crypto_payload  = plain_payload[1 + offset_size + length_size : crypto_length].hex()

                    if residual_packet_size > 0:
                        residual_payload = crypto_payload[:residual_packet_size*2]
                        print(f'\n{Fore.BLACK}Residaul Packet Payload{Fore.RESET} | {residual_handshake_type}:', fragmented_packet_payload + residual_payload, end=' .\n\n')
                        crypto_payload = crypto_payload[residual_packet_size*2:]
                        residual_packet_size = 0

                    print(peer, f'- Plaintext Packet | {Fore.GREEN}CRYPTO:{Fore.RESET}', crypto_length, crypto_header, end=' |\n')

                    while True:

                        # print(crypto_payload)
                        # print(len(crypto_payload))

                        if len(crypto_payload) == 0:
                            break

                        handshake_type = Fore.CYAN if 'CLIENT' in peer else Fore.MAGENTA

                        match(crypto_payload[:2]):
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

                        handshake_type += Fore.RESET
                        
                        handshake_packet_length = (int(crypto_payload[2:8], 16) + 4) * 2
                        # print(handshake_packet_length)

                        if len(crypto_payload) < handshake_packet_length:
                            residual_packet_size        = int((handshake_packet_length - len(crypto_payload))/2)
                            residual_handshake_type     = handshake_type
                            fragmented_packet_payload   = crypto_payload[:handshake_packet_length]
                            print(f'{Fore.BLACK}FRAGMENTED{Fore.RESET} |', f'{residual_handshake_type}:', handshake_packet_length, len(crypto_payload), residual_packet_size, end=' |\n')
                            crypto_payload = crypto_payload[handshake_packet_length:]
                            continue

                        if 'NotFound' not in handshake_type:
                            print(f'{handshake_type}:', crypto_payload[:handshake_packet_length], end=' |\n')
                            crypto_payload = crypto_payload[handshake_packet_length:]

                    plain_payload = plain_payload[crypto_length:]
                    print()
            
            case 'padding':
                if plain_payload[:1].hex() == '00':
                    padding_length = plain_length - ack_length - crypto_length
                    print(peer, f'- Plaintext Packet | {Fore.WHITE}PADDING:{Fore.RESET}', padding_length, plain_payload.hex(), '\n')

    print(peer, f'- \033[4mEncrypted Packet\033[0m:', encrypted_payload.hex(), '\n\n')