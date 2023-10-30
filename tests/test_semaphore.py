import unittest

from chiquito.util import F

from src.semaphore import SemaphoreSuperCircuit


class SemaphoreTests(unittest.TestCase):
    def test_basic(self):
        # Arrange
        identity_nullifier = F(8651960274441310489225017096417668083399439888492565663442738198004033520384)
        identity_trapdoor = F(10508389592535728861185052047957562223060287304681057908654687548873603573619)
        signal_hash = F(123)
        external_nullifier = F(1)
        siblings = [
            F(1), F(2), F(1), F(2), F(1), F(2), F(1), F(2), F(1), F(2),
            F(1), F(2), F(1), F(2), F(1), F(2), F(1), F(2), F(1), F(2),
        ]
        path_indices = [
            F(1), F(1), F(1), F(1), F(1), F(1), F(1), F(1), F(1), F(1),
            F(1), F(1), F(1), F(1), F(1), F(1), F(1), F(1), F(1), F(1),
        ]

        # Act
        semaphore = SemaphoreSuperCircuit()
        semaphore_witness = semaphore.gen_witness(
            identity_nullifier,
            identity_trapdoor,
            siblings,
            path_indices,
            signal_hash,
            external_nullifier,
        )

        # Assert
        try:
            semaphore.halo2_mock_prover(semaphore_witness)
        except Exception:
            assert False, "Proof failed"


if __name__ == '__main__':
    unittest.main()
