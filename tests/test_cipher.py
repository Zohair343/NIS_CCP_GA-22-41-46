"""Unit tests. Run from the project root:  python -m unittest discover tests -v"""
import os
import random
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import attacks
import cipher
from cipher import CipherError


class TestCipher(unittest.TestCase):
    def test_known_vector(self):
        # Hand-computed: P=HELLO, a=5,b=8 -> affine RCLLA; key 'ABCDEFGHIJ' (shifts 0,1,2,3,4)
        self.assertEqual(cipher.affine_encrypt("HELLO", 5, 8), "RCLLA")
        self.assertEqual(cipher.encrypt("hello", 5, 8, "ABCDEFGHIJ"), "RDNOE")

    def test_round_trip_random(self):
        rng = random.Random(1)
        for _ in range(300):
            n = rng.randint(1, 400)
            pt = "".join(rng.choice(cipher.ALPHABET) for _ in range(n))
            a, b = rng.choice(cipher.VALID_A), rng.randrange(26)
            key = "".join(rng.choice(cipher.ALPHABET) for _ in range(rng.randint(10, 20)))
            self.assertEqual(cipher.decrypt(cipher.encrypt(pt, a, b, key), a, b, key), pt)

    def test_normalisation(self):
        self.assertEqual(cipher.normalize_text("Hi, there! 123")[0], "HITHERE")
        self.assertEqual(cipher.normalize_text("Hi, there! 123")[1], 7)

    def test_invalid_inputs(self):
        with self.assertRaises(CipherError): cipher.encrypt("hello", 2, 3, "ABCDEFGHIJ")   # a not coprime
        with self.assertRaises(CipherError): cipher.encrypt("hello", 3, 30, "ABCDEFGHIJ")  # b out of range
        with self.assertRaises(CipherError): cipher.encrypt("hello", 3, 3, "SHORT")        # key too short
        with self.assertRaises(CipherError): cipher.encrypt("hello", 3, 3, "ABCDE12345")   # non-letters
        with self.assertRaises(CipherError): cipher.encrypt("123 !!", 3, 3, "ABCDEFGHIJ")  # nothing to encrypt
        with self.assertRaises(CipherError): cipher.decrypt("AB1CD", 3, 3, "ABCDEFGHIJ")   # bad ciphertext
        with self.assertRaises(CipherError): cipher.decrypt("", 3, 3, "ABCDEFGHIJ")

    def test_mod_inverse(self):
        for a in cipher.VALID_A:
            self.assertEqual((a * cipher.mod_inverse(a)) % 26, 1)

    def test_effective_key_equivalence(self):
        a, b, key = 9, 4, "SECURITYKEY"
        pt = "ATTACKATDAWNONTHEEASTERNFRONT"
        ct = cipher.encrypt(pt, a, b, key)
        shifts = cipher.effective_shifts(a, b, key)
        self.assertEqual(attacks.decrypt_with_effective_key(ct, a, shifts), pt)


class TestAttacks(unittest.TestCase):
    def test_kpa_recovers_everything_with_enough_known_text(self):
        import experiments
        pt = experiments.CORPUS[:300]
        ct = cipher.encrypt(pt, 11, 6, "LONGERKEYWORD")
        res = attacks.known_plaintext_attack(ct, pt[:30], 0)
        self.assertEqual(res["recovered"], pt)
        self.assertEqual(res["a"], 11)

    def test_frequency_attack_on_long_text(self):
        import experiments
        pt = experiments.CORPUS[:1000]
        ct = cipher.encrypt(pt, 7, 3, "NETWORKSEC")
        res = attacks.frequency_analysis_attack(ct)
        self.assertGreater(attacks.accuracy(res["recovered"], pt), 0.95)


if __name__ == "__main__":
    unittest.main()
