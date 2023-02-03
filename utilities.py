import numpy as np


def open_files(n_traces, len_trace, power_start, power_len):
    with open('./data/traces-00112233445566778899aabbccddeeff.bin', 'rb') as trace_file:
        full_traces = np.fromfile(trace_file, np.uint8).reshape(n_traces, len_trace)
        power_traces = np.zeros((n_traces, power_len))
        for i in range(n_traces):
            power_traces[i] = full_traces[i][power_start:power_start + power_len]

    with open('./data/plaintext_00112233445566778899aabbccddeeff.txt', 'r') as plain_file:
        plain_dec = []
        for row in plain_file.readlines():
            for hex_dec in row.split():
                plain_dec.append(int(hex_dec, 16))

    with open('./data/ciphertext_00112233445566778899aabbccddeeff.txt', 'r') as cipher_file:
        cipher_dec = []
        for row in cipher_file.readlines():
            for hex_dec in row.split():
                cipher_dec.append(int(hex_dec, 16))

    return power_traces, plain_dec, cipher_dec


def dpa_attack(s_box, traces, plain_text):
    n_traces, _ = traces.shape
    guess_key_lb = []
    guess_key_hw = []
    for byte in range(16):
        power_hypothesis_lb = []
        power_hypothesis_hw = []
        for k in range(256):
            ones_lb, zeros_lb = [], []
            ones_hw, zeros_hw = [], []
            for n in range(n_traces):
                s_box_input = plain_text[16 * n + byte] ^ k
                s_box_output = s_box[s_box_input]
                if s_box_output % 2 == 1:
                    ones_lb.append(traces[n])
                else:
                    zeros_lb.append(traces[n])
                hamming_weight = np.binary_repr(s_box_output).count('1')
                if hamming_weight > 4:
                    ones_hw.append(traces[n])
                else:
                    zeros_hw.append(traces[n])
            diff_lb = abs(np.mean(ones_lb, axis=0) - np.mean(zeros_lb, axis=0))
            diff_hw = abs(np.mean(ones_hw, axis=0) - np.mean(zeros_hw, axis=0))
            power_hypothesis_lb.append(np.max(diff_lb))
            power_hypothesis_hw.append(np.max(diff_hw))
        guess_key_lb.append(hex(np.argmax(power_hypothesis_lb)))
        guess_key_hw.append(hex(np.argmax(power_hypothesis_hw)))
    return guess_key_lb, guess_key_hw


def cpa_attack(s_box, traces, plain_text):
    n_traces, m_points = traces.shape
    guess_key = []
    for byte in range(16):
        hypothesis = []
        for k in range(256):
            hw_list = []
            correlation = []
            for n in range(n_traces):
                s_box_input = plain_text[16 * n + byte] ^ k
                s_box_output = s_box[s_box_input]
                hw = np.binary_repr(s_box_output).count('1')
                hw_list.append(hw)
            for m in range(m_points):
                correlation.append(np.corrcoef(hw_list, traces[:, m])[0, 1])
            hypothesis.append(np.max(correlation))
        guess_key.append(hex(np.argmax(hypothesis)))
    return guess_key
