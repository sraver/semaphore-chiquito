from __future__ import annotations

from chiquito.cb import eq
from chiquito.chiquito_ast import Last
from chiquito.dsl import SuperCircuit, Circuit, StepType
from chiquito.util import F

from src.mimc7_constants import ROUND_CONSTANTS
from src.mimc7_multi import ROUNDS, Mimc7Constants, Mimc7MultiCircuit
from src.inclusion_proof import MtipCircuit

N_LEVELS = 20


class SemaphoreSignalStep(StepType):
    """
    This step will make sure the signal is not tampered
    """

    def setup(self):
        # define internal signals
        self.signal_squared = self.internal("signal_squared")
        # constraints the signal squared the signal
        self.constr(eq(self.signal_squared, self.circuit.signal * self.circuit.signal))

    def wg(self, signal):
        self.assign(self.circuit.signal, F(signal))
        self.assign(self.signal_squared, F(signal * signal))


class SemaphoreHashes(StepType):
    """
    This step verifies that the given pair "clear_input <> hash" exist on the lookup table
    """

    def setup(self):
        # define internal signals
        self.hash = self.internal("hash")
        self.clear_input = self.internal("clear_input")

        # add a lookup table constraint to verify that used hashes are valid
        self.add_lookup(
            self.circuit.hashes_table
            .apply(1)  # enable_lookup
            .apply(99)  # x // TODO : this hardcoded value should make it fail
            .apply(self.hash)  # out
        )

    def wg(self, clear_input, hash_result):
        self.assign(self.clear_input, F(clear_input))
        self.assign(self.hash, F(hash_result))


class SemaphoreCircuit(Circuit):
    def setup(self):
        # define circuit signals
        self.signal = self.forward("signal")

        # define necessary step types
        self.hashes_step = self.step_type(SemaphoreHashes(self, "hashes_step"))
        self.signal_step = self.step_type(SemaphoreSignalStep(self, "signal_step"))

        # define circuit constraints
        self.pragma_first_step(self.hashes_step)
        self.pragma_last_step(self.hashes_step)
        self.pragma_num_steps(4)

        # define exposed signals
        self.expose(self.signal, Last())

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
        # constrains and expose the signal
        self.add(self.signal_step, signal_hash)

        # constrains that `secret` is the resulting hash of `identity_nullifier + identity_trapdoor`
        self.add(self.hashes_step, identity_nullifier + identity_trapdoor, secret)

        # constrains that `commitment` is the resulting hash of `secret`
        self.add(self.hashes_step, secret, commitment)

        # constrains that `nullifier_hash` is the resulting hash of `identity_nullifier + external_nullifier`
        self.add(self.hashes_step, identity_nullifier + external_nullifier, nullifier_hash)


class SemaphoreSuperCircuit(SuperCircuit):
    def setup(self):
        # define MIMC7 constants sub-circuit
        self.mimc7_constants = self.sub_circuit(Mimc7Constants(self))
        # define MIMC7 Multi sub-circuit
        self.mimc7_multi_circuit = self.sub_circuit(
            Mimc7MultiCircuit(self, constants_table=self.mimc7_constants.lookup_table)
        )
        # define Merkle Tree Inclusion Proof Multi sub-circuit
        self.mtip_circuit = self.sub_circuit(
            MtipCircuit(self, hashes_table=self.mimc7_multi_circuit.hashes_table)
        )
        # define Semaphore circuit
        self.semaphore_circuit = self.sub_circuit(
            SemaphoreCircuit(self, hashes_table=self.mimc7_multi_circuit.hashes_table)
        )

    def mapping(self, identity_nullifier, identity_trapdoor, siblings, path_indices, signal_hash, external_nullifier):
        k_value = 10

        # compute hashes from input values
        secret = self.mimc7(identity_nullifier + identity_trapdoor, k_value)
        commitment = self.mimc7(secret, k_value)
        nullifier_hash = self.mimc7(identity_nullifier + external_nullifier, k_value)

        # initialize hashes array with leaf element
        leaf = commitment
        hashes = [leaf]

        # add input values of computed hashes
        # this will allow us to constrain the values by checking a lookup table
        x_values = [
            identity_nullifier + identity_trapdoor,
            secret,
            identity_nullifier + external_nullifier
        ]

        for i in range(0, N_LEVELS):
            # compute the MIMC7 hash of this level
            input_1 = ((siblings[i] - hashes[i]) * path_indices[i]) + hashes[i]
            input_2 = ((hashes[i] - siblings[i]) * path_indices[i]) + siblings[i]
            x_values.append(input_1 + input_2)
            result = self.mimc7(x_values[i], k_value)
            # append the hash to the list
            hashes.append(result)

        # this first circuit will compute and store all the hashes on a lookup table,
        # that will allow the next circuit to add lookup constraints to verify that the given
        # values are correct by checking their existence on the table.
        self.map(self.mimc7_multi_circuit, x_values, k_value)

        # next circuit constraints the given hashes to exist on the lookup table,
        # that protects the MTIP circuit from using crafted hashes
        self.map(self.mtip_circuit, path_indices, x_values, hashes)

        # next circuit constraints that the computed hashes for the signal and commitment
        # are correctly used
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
