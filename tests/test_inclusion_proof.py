import unittest

from chiquito.util import F

from src.inclusion_proof import MtipSuperCircuit


class MtipTests(unittest.TestCase):
    def test_basic(self):
        # Arrange
        leaf = F(1)
        siblings = [
            F(1), F(2), F(3), F(4), F(5), F(6), F(7), F(8), F(9), F(10),
            F(11), F(12), F(13), F(14), F(15), F(16), F(17), F(18), F(19), F(20),
        ]
        path_indices = [
            F(1), F(1), F(1), F(0), F(0), F(0), F(0), F(0), F(0), F(0),
            F(0), F(0), F(0), F(0), F(0), F(0), F(0), F(0), F(0), F(0),
        ]
        k_value = F(1)

        # Act
        mtip = MtipSuperCircuit()
        mtip_witness = mtip.gen_witness(
            leaf,
            siblings,
            path_indices,
            k_value,
        )

        # Assert
        expected_root = 9718292343045174462399285270549165738345190962147124001263109326266001332162
        step_instances = list(mtip_witness.values())[1].step_instances
        computed_root = list(step_instances[len(step_instances) - 1].assignments.values())[0]
        assert computed_root == expected_root, "Roots do not match"

        try:
            mtip.halo2_mock_prover(mtip_witness)
        except Exception:
            assert False, "Proof failed"


if __name__ == '__main__':
    unittest.main()
