import asn1

def encode(
    mod1, # mod - n
    mod2, 
    mod3,
    exp, # exp - e
    encrypted_key_s_1, 
    encrypted_key_s_2,
    encrypted_key_s_3,  
    iv,
    cipher_length, 
    cipher
    ):

    asn1_encoder = asn1.Encoder()

    asn1_encoder.start()

    # Sequence_1 start
    asn1_encoder.enter(asn1.Numbers.Sequence)

    # Set_1 start
    asn1_encoder.enter(asn1.Numbers.Set)

    # Sequence_2 start
    asn1_encoder.enter(asn1.Numbers.Sequence)

    # \x00\x01 - RSA
    asn1_encoder.write(b'\x00\x01', asn1.Numbers.OctetString)
    asn1_encoder.write(b'Data', asn1.Numbers.UTF8String)

    #
    asn1_encoder.enter(asn1.Numbers.Sequence)
    asn1_encoder.write(mod1, asn1.Numbers.Integer)
    asn1_encoder.write(mod2, asn1.Numbers.Integer)
    asn1_encoder.write(mod3, asn1.Numbers.Integer)
    asn1_encoder.write(exp, asn1.Numbers.Integer)
    asn1_encoder.leave()

    # Cryptographic parameters
    asn1_encoder.enter(asn1.Numbers.Sequence)
    asn1_encoder.leave()

    #
    asn1_encoder.enter(asn1.Numbers.Sequence)
    asn1_encoder.write(encrypted_key_s_1, asn1.Numbers.Integer)
    asn1_encoder.write(encrypted_key_s_2, asn1.Numbers.Integer)
    asn1_encoder.write(encrypted_key_s_3, asn1.Numbers.Integer)
    asn1_encoder.leave()

    # Sequence_2 end
    asn1_encoder.leave()

    # Set_1 end
    asn1_encoder.leave()

    #
    asn1_encoder.enter(asn1.Numbers.Sequence)
    # \x01\x32 - 3DES
    asn1_encoder.write(b'\x10\x81', asn1.Numbers.OctetString)
    asn1_encoder.write(iv, asn1.Numbers.OctetString)
    asn1_encoder.write(cipher_length, asn1.Numbers.Integer)
    asn1_encoder.leave()

    # Sequence_1 end
    asn1_encoder.leave()

    asn1_encoder.write(cipher)

    return asn1_encoder.output()

def parse(file, decoded_values):

    while not file.eof():
        try:
            tag = file.peek()

            if tag.nr == asn1.Numbers.Null:
                break

            if tag.typ == asn1.Types.Primitive:
                tag, value = file.read()

                if tag.nr == asn1.Numbers.Integer:
                    decoded_values.append(value)

            else:
                file.enter()
                decoded_values = parse(file, decoded_values)
                file.leave()

        except asn1.Error:
            break

    return decoded_values

def decode(filePath):

    decoded_parameters = []
    # decoded_parameters[0] is n (module)
    # decoded_parameters[1] is e (exponent)
    # decoded_parameters[2] is key (encrypted_AES_key)
    # decoded_parameters[3] is iv
    # decoded_parameters[4] is cipher_len (cipher_text length)
   
    data= open(filePath,'rb').read()
    #data = file.read()
    decoder = asn1.Decoder()
    decoder.start(data)
   # decoded_parameters = parse(decoder, decoded_parameters)
    
    decoder.enter()
    decoder.enter()
    decoder.enter()

    decoder.read() #b'\x00\x01'
    decoder.read() #b'Data'

    decoder.enter()
    n1 = decoder.read()[1]
    n2 = decoder.read()[1]
    n3 = decoder.read()[1]
    e = decoder.read()[1]
    decoder.leave()

    decoder.enter()
    decoder.leave()

    decoder.enter()
    enc_K_1 = decoder.read()[1]
    enc_K_2 = decoder.read()[1]
    enc_K_3 = decoder.read()[1]
    decoder.leave()

    decoder.leave()
    decoder.leave()

    decoder.enter()
    decoder.read()[1]
    iv = decoder.read()[1]
    kol = decoder.read()[1]
    decoder.leave()
    decoder.leave()
    data = decoder.read()[1]



    
    
    #data = bytearray(data)
    #cipher_len = decoded_parameters[-1]
    #cipher_bytes = bytearray()

    #for i in range(len(data) - cipher_len, len(data)):
      #  cipher_bytes.append(data[i])

    with open('~tmp'+filePath, 'wb') as file_cipher:
        file_cipher.write(data)#cipher_bytes)

    return n1, n2, n3, e, enc_K_1, enc_K_2, enc_K_3, iv, kol #decoded_parameters[0], decoded_parameters[1], decoded_parameters[2]

def encode_sign(
    mod, # mod - n
    exp, # exp - e
    sign_RSA
    ):

    asn1_encoder = asn1.Encoder()

    asn1_encoder.start()

    # Sequence_1 start
    asn1_encoder.enter(asn1.Numbers.Sequence)

    # Set_1 start
    asn1_encoder.enter(asn1.Numbers.Set)

    # Sequence_2 start
    asn1_encoder.enter(asn1.Numbers.Sequence)

    # \x00\x06 - RSA-SHA1
    asn1_encoder.write(b'\x00\x40', asn1.Numbers.OctetString)
    asn1_encoder.write(b'RSASignature ', asn1.Numbers.UTF8String)

    #
    asn1_encoder.enter(asn1.Numbers.Sequence)
    asn1_encoder.write(mod, asn1.Numbers.Integer)
    asn1_encoder.write(exp, asn1.Numbers.Integer)
    asn1_encoder.leave()

    #
    asn1_encoder.enter(asn1.Numbers.Sequence)
    asn1_encoder.leave()

    #
    asn1_encoder.enter(asn1.Numbers.Sequence)
    asn1_encoder.write(sign_RSA, asn1.Numbers.Integer)
    asn1_encoder.leave()

    # Sequence_2 start
    asn1_encoder.leave()

    # Set_1 end
    asn1_encoder.leave()

    # Additional data
    asn1_encoder.enter(asn1.Numbers.Sequence)
    asn1_encoder.leave()

    # Sequence_1 end
    asn1_encoder.leave()


    return asn1_encoder.output()


def decode_sign(filePath):

    decoded_parameters = []
    # decoded_parameters[0] is n (module)
    # decoded_parameters[1] is e (exponent)
    # decoded_parameters[2] is s (signature)

    with open(filePath, 'rb') as file:
        data = file.read()
        decoder = asn1.Decoder()
        decoder.start(data)

        decoder.enter()
        decoder.enter()
        decoder.enter()
        decoder.read()
        decoder.read()
        
        decoder.enter()
        n = decoder.read()[1]
        e = decoder.read()[1]
        decoder.leave()

        decoder.enter()
        decoder.leave()

        decoder.enter()
        sign_RSA = decoder.read()[1]
        decoder.leave()
        decoder.leave()
        decoder.leave()

        decoder.enter()
        decoder.leave()
        decoder.leave()


    return n, sign_RSA