

def quic_packet_decompose(peer, quic_logger_frames, plain_payload, encrypted_payload):

    print(quic_logger_frames)
    
    plain_length        = len(plain_payload)
    ack_length          = 0
    crypto_length       = 0
    padding_length      = 0
    for frame in quic_logger_frames:
        match(frame['frame_type']):
            case 'ack': # da adattare negli casi in cui gli altri parametri sono presenti
                if plain_payload[:1].hex() == '02':
                    if frame['acked_ranges'][0] == [0, 0] or frame['acked_ranges'][0] == [1, 1]:
                        ack_length = 6
                    
                    print(peer, '- Plaintext Packet - ACK:', ack_length, plain_payload[:ack_length].hex(), '\n')
                    plain_payload = plain_payload[ack_length:]
            
            case 'crypto':
                if plain_payload[:1].hex() == '06':
                    crypto_length = frame['length'] + 4
                    print(peer, '- Plaintext Packet - CRYPTO:', crypto_length, plain_payload[:crypto_length].hex(), '\n')
                    plain_payload = plain_payload[crypto_length:]
            
            case 'padding':
                if plain_payload[:1].hex() == '00':
                    padding_length = plain_length - ack_length - crypto_length
                    print(peer, '- Plaintext Packet - PADDING:', padding_length, plain_payload.hex(), '\n')

    print(peer, '- Encrypted Packet:', encrypted_payload.hex(), '\n\n')