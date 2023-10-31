from __future__ import annotations

from chiquito.cb import eq
from chiquito.chiquito_ast import Last
from chiquito.dsl import SuperCircuit, Circuit, StepType
from chiquito.util import F

from src.mimc7_constants import ROUND_CONSTANTS
from src.mimc7_multi import ROUNDS, Mimc7Constants, Mimc7MultiCircuit
from src.inclusion_proof import MtipCircuit

N_LEVELS = 20


class SemaphoreStep(StepType):
    def setup(self):
        # define internal signals
        self.secret_input = self.internal("secret_input")
        self.secret = self.internal("secret")
        self.commitment = self.internal("commitment")
        self.nullifier_input = self.internal("nullifier_input")
        self.nullifier_hash = self.internal("nullifier_hash")
        self.signal_squared = self.internal("signal_squared")

        # constraints the signal squared the signal
        self.constr(eq(self.signal_squared, self.circuit.signal * self.circuit.signal))

        # add lookup table constraints to verify that used hashes are valid
        self.add_lookup(
            self.circuit.hashes_table
            .apply(1)  # enable_lookup
            # .apply(self.secret_input)  # x
            .apply(99)  # x // TODO : this hardcoded value should make it fail
            .apply(self.secret)  # out
        )
        self.add_lookup(
            self.circuit.hashes_table
            .apply(1)  # enable_lookup
            .apply(self.secret)  # x
            .apply(self.commitment)  # out
        )
        self.add_lookup(
            self.circuit.hashes_table
            .apply(1)  # enable_lookup
            .apply(self.nullifier_input)  # x
            .apply(self.nullifier_hash)  # out
        )

    def wg(
            self,
            identity_nullifier,
            identity_trapdoor,
            external_nullifier,
            nullifier_hash,
            signal_hash,
            secret,
            commitment
    ):
        # assign signal values
        self.assign(self.circuit.signal, F(signal_hash))
        self.assign(self.signal_squared, F(signal_hash * signal_hash))
        # assign secret values
        self.assign(self.secret_input, F(identity_nullifier + identity_trapdoor))
        self.assign(self.secret, F(secret))
        # assign commitment values
        self.assign(self.commitment, F(commitment))
        # assign nullifier values
        self.assign(self.nullifier_input, F(identity_nullifier + external_nullifier))
        self.assign(self.nullifier_hash, F(nullifier_hash))


class SemaphoreCircuit(Circuit):
    def setup(self):
        # define circuit signals
        self.signal = self.forward("signal")

        # define necessary step types
        self.step = self.step_type(SemaphoreStep(self, "semaphore_step"))

        # define circuit constraints
        self.pragma_first_step(self.step)
        self.pragma_num_steps(1)

        # define exposed signals
        self.expose(self.signal, Last())

    def trace(
            self,
            identity_nullifier,
            identity_trapdoor,
            external_nullifier,
            nullifier_hash,
            signal_hash,
            secret,
            commitment,
    ):
        self.add(
            self.step,
            identity_nullifier,
            identity_trapdoor,
            external_nullifier,
            nullifier_hash,
            signal_hash,
            secret,
            commitment
        )
        

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
