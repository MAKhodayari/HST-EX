import utilities as utl


if __name__ == '__main__':
    # File Preparation
    known_traces, known_plain_text, known_cipher_text = utl.open_files(True, 200, 370000, 40000, 50000)
    unknown_traces, unknown_plain_text, unknown_cipher_text = utl.open_files(False, 150, 550000, 0, 30000)

    # DPA Attack
    known_key_dpa_lb, known_key_dpa_hw = utl.dpa_attack(known_traces, known_plain_text, 200)
    unknown_key_dpa_lb, unknown_key_dpa_hw = utl.dpa_attack(unknown_traces, unknown_plain_text, 150)

    # CPA Attack

    # Results
    print('Guessed Key For Known Traces & Plaintext:\n')
    print('Using Last Bit As Indicator for Ones & Zeros:')
    print(known_key_dpa_lb)
    print('Using Hamming Weight As Indicator for Ones & Zeros:')
    print(known_key_dpa_hw)

    print('─' * 150)

    print('Guessed Key For Unknown Traces & Plaintext:\n')
    print('Using Last Bit As Indicator for Ones & Zeros:')
    print(unknown_key_dpa_lb)
    print('Using Hamming Weight As Indicator for Ones & Zeros:')
    print(unknown_key_dpa_hw)
