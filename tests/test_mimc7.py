import unittest

from chiquito.util import F

from src.mimc7 import Mimc7SuperCircuit
from tests.test_mimc7_multi import MIMC7_HASHES


class Mimc7Tests(unittest.TestCase):
    def test_basic(self):
        mimc7 = Mimc7SuperCircuit()
        mimc7_super_witness = mimc7.gen_witness(F(20), F(10))

        step_instances = list(mimc7_super_witness.values())[0].step_instances
        result = list(step_instances[len(step_instances) - 1].assignments.values())[3]
        assert result == MIMC7_HASHES[19]

        try:
            mimc7.halo2_mock_prover(mimc7_super_witness)
        except Exception:
            assert False, "Proof failed"


if __name__ == '__main__':
    unittest.main()
