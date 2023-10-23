import unittest

from chiquito.util import F

from src.inclusion_proof import MtipSuperCircuit


class MtipTests(unittest.TestCase):
    def test_basic(self):
        mtip = MtipSuperCircuit()
        mtip_witness = mtip.gen_witness(
            F(1),
            [
                F(1), F(2), F(1), F(2), F(1), F(2), F(1), F(2), F(1), F(2),
                F(1), F(2), F(1), F(2), F(1), F(2), F(1), F(2), F(1), F(2),
                F(1), F(2), F(1), F(2), F(1), F(2), F(1), F(2), F(1), F(2),
                F(1), F(2), F(1), F(2), F(1), F(2), F(1), F(2), F(1), F(2),
            ],
            [
                F(1), F(0), F(1), F(0), F(1), F(0), F(1), F(0), F(1), F(0),
                F(1), F(0), F(1), F(0), F(1), F(0), F(1), F(0), F(1), F(0),
                F(1), F(0), F(1), F(0), F(1), F(0), F(1), F(0), F(1), F(0),
                F(1), F(0), F(1), F(0), F(1), F(0), F(1), F(0), F(1), F(0),
            ],
            F(1),
        )

        expected_root = 1080737476473719184328627128176865779770106858406730302444086876071322708942

        step_instances = list(mtip_witness.values())[1].step_instances
        result = list(step_instances[len(step_instances) - 1].assignments.values())[0]

        assert result == expected_root

        try:
            mtip.halo2_mock_prover(mtip_witness)
        except Exception:
            assert False, "Proof failed"


if __name__ == '__main__':
    unittest.main()
