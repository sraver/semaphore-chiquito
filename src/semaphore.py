from __future__ import annotations

from chiquito.cb import eq
from chiquito.dsl import SuperCircuit, Circuit, StepType
from chiquito.util import F

from src.mimc7_constants import ROUND_CONSTANTS
from src.mimc7_multi import ROUNDS, Mimc7Constants, Mimc7MultiCircuit
from src.inclusion_proof import MtipCircuit

N_LEVELS = 20


class SemaphoreSignalStep(StepType):
    def setup(self):
        self.signal = self.internal("signal")
        self.signal_squared = self.internal("signal_squared")
        self.constr(eq(self.signal_squared, self.signal * self.signal))

    def wg(self, signal):
        self.assign(self.signal, F(signal))
        self.assign(self.signal_squared, F(signal * signal))


class SemaphoreHashes(StepType):
    def setup(self):
        self.result = self.internal("result")
        self.input = self.internal("input")
        self.add_lookup(self.circuit.hashes_table.apply(1).apply(self.result))
        # TODO add inputs to lookup table

    def wg(self, clear_text, hash_result):
        self.assign(self.input, F(clear_text))
        self.assign(self.result, F(hash_result))


class SemaphoreCircuit(Circuit):
    def setup(self):
        self.hashes_step = self.step_type(SemaphoreHashes(self, "hashes_step"))
        self.signal_step = self.step_type(SemaphoreSignalStep(self, "signal_step"))

        self.pragma_first_step(self.hashes_step)
        self.pragma_last_step(self.hashes_step)

        self.pragma_num_steps(4)

    def trace(
            self,
            identity_nullifier,
            identity_trapdoor,
            secret,
            commitment,
            external_nullifier,
            nullifier_hash,
            signal_hash
    ):
        self.add(self.signal_step, signal_hash)
        self.add(self.hashes_step, identity_nullifier + identity_trapdoor, secret)
        self.add(self.hashes_step, secret, commitment)
        self.add(self.hashes_step, identity_nullifier + external_nullifier, nullifier_hash)


class SemaphoreSuperCircuit(SuperCircuit):
    def setup(self):
        self.mimc7_constants = self.sub_circuit(Mimc7Constants(self))
        self.mimc7_multi_circuit = self.sub_circuit(
            Mimc7MultiCircuit(self, constants_table=self.mimc7_constants.lookup_table)
        )
        self.mtip_circuit = self.sub_circuit(
            MtipCircuit(self, hashes_table=self.mimc7_multi_circuit.hashes_table)
        )
        self.semaphore_circuit = self.sub_circuit(
            SemaphoreCircuit(self, hashes_table=self.mimc7_multi_circuit.hashes_table)
        )

    def mapping(self, identity_nullifier, identity_trapdoor, siblings, path_indices, signal_hash, external_nullifier):
        k_value = 10

        secret = self.mimc7(identity_nullifier + identity_trapdoor, k_value)
        commitment = self.mimc7(secret, k_value)
        nullifier_hash = self.mimc7(identity_nullifier + external_nullifier, k_value)

        leaf = commitment
        hashes = [leaf]

        x_values = [
            identity_nullifier + identity_trapdoor,
            secret,
            identity_nullifier + external_nullifier
        ]

        for i in range(0, N_LEVELS):
            input_1 = ((siblings[i] - hashes[i]) * path_indices[i]) + hashes[i]
            input_2 = ((hashes[i] - siblings[i]) * path_indices[i]) + siblings[i]
            x_values.append(input_1 + input_2)
            result = self.mimc7(x_values[i], k_value)
            hashes.append(result)

        self.map(self.mimc7_multi_circuit, x_values, k_value)
        self.map(self.mtip_circuit, path_indices, hashes)
        self.map(
            self.semaphore_circuit,
            identity_nullifier,
            identity_trapdoor,
            secret,
            commitment,
            external_nullifier,
            nullifier_hash,
            signal_hash
        )

    def mimc7(self, x_in_value, k_value):
        c_value = F(ROUND_CONSTANTS[0])
        x_value = F(x_in_value)
        row_value = F(0)

        for i in range(1, ROUNDS):
            row_value += F(1)
            x_value += F(k_value + c_value)
            x_value = F(x_value ** 7)
            c_value = F(ROUND_CONSTANTS[i])

        row_value += F(1)
        x_value += F(k_value + c_value)
        x_value = F(x_value ** 7)

        return x_value + k_value
