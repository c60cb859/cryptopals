#!/usr/bin/env python3


class MersenneTwister19937:
    def __init__(self, seed=5489):
        (self.w, self.n, self.m, self.r) = (32, 624, 397, 31)
        self.a = 0x9908B0DF
        (self.u, self.d) = (11, 0xFFFFFFFF)
        (self.s, self.b) = (7, 0x9D2C5680)
        (self.t, self.c) = (15, 0xEFC60000)
        self.l = 18
        self.f = 1812433253

        # masks (to apply with an '&' operator)
        # ---------------------------------------
        # zeroes out all bits except "the w-r highest bits"
        # (i.e. with our parameters the single highest bit, since w-r=1)
        self.high_mask = ((1 << self.w) - 1) - ((1 << self.r) - 1)
        # zeroes out all bits excepts "the r lowest bits"
        self.low_mask = (1 << self.r) - 1

        self.state = list()
        self.state.append(seed)

        for i in range(1, self.n):
            prev = self.state[-1]
            # the "& d" is to take only the lowest 32 bits of the result
            x = (self.f * (prev ^ (prev >> (self.w - 2))) + i) & self.d
            self.state.append(x)

    def twist(self, x):
        if x % 2 == 1:
            return (x >> 1) ^ self.a
        return x >> 1

    def __iter__(self):
        return self

    def __next__(self):
        while True:
            x = self.state[self.m] ^ self.twist((self.state[0] & self.high_mask) + (self.state[1] & self.low_mask))

            # tempering transform and output
            y = x ^ ((x >> self.u) & self.d)
            y = y ^ ((y << self.s) & self.b)
            y = y ^ ((y << self.t) & self.c)
            y = y ^ (y >> self.l)

            # note that it's the 'x' value
            # that we insert in the state
            self.state.pop(0)
            self.state.append(x)
            return y
