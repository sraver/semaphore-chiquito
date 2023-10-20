import unittest

from chiquito.util import F

from src.mimc7 import Mimc7SuperCircuit


class Mimc7Tests(unittest.TestCase):
    def test_basic(self):
        mimc7 = Mimc7SuperCircuit()
        mimc7_super_witness = mimc7.gen_witness(F(1), F(2))
        try:
            mimc7.halo2_mock_prover(mimc7_super_witness)
        except Exception:
            assert False, "Proof failed"


if __name__ == '__main__':
    unittest.main()
