import random


def random_bits(word_size, hamming_weight):
    number = 0
    for bit in random.sample(range(word_size), hamming_weight):
        number |= 1 << bit
    return number


def gray(str):
    return "\033[90m{}\033[0m".format(str)


def red(str):
    return "\033[91m{}\033[0m".format(str)


def green(str):
    return "\033[92m{}\033[0m".format(str)


def yellow(str):
    return "\033[93m{}\033[0m".format(str)


def cyan(str):
    return "\033[96m{}\033[0m".format(str)
