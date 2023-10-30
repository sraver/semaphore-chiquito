from __future__ import annotations

from chiquito.chiquito_ast import Last
from chiquito.dsl import Circuit, StepType, SuperCircuit
from chiquito.cb import eq
from chiquito.expr import to_expr
from chiquito.util import F

from src.mimc7_constants import ROUND_CONSTANTS, ROUNDS
from src.mimc7_multi import Mimc7MultiCircuit, Mimc7Constants

N_LEVELS = 20


class MtipStep(StepType):
    def setup(self):
        self.index = self.internal("index")
        self.input = self.internal("input")
        self.result = self.internal("result")
        self.constr(eq(self.index * (to_expr(1) - self.index), 0))

        self.transition(eq(self.result, self.circuit.hash.next()))

        self.add_lookup(
            self.circuit.hashes_table
            .apply(1)  # enable_lookup
            .apply(1)  # TODO : this hardcoded value should make it fail
            .apply(self.result)  # out
        )

    def wg(self, index_value, result_value, hash_value, input_value):
        self.assign(self.input, F(input_value))
        self.assign(self.index, F(index_value))
        self.assign(self.result, F(result_value))
        self.assign(self.circuit.hash, F(hash_value))


class MtipLastStep(StepType):
    def setup(self):
        self.transition(eq(self.circuit.hash, self.circuit.hash.next()))

    def wg(self, hash_value):
        self.assign(self.circuit.hash, F(hash_value))


class MtipCircuit(Circuit):
    def setup(self):
        self.hash = self.forward("hash")

        self.step = self.step_type(MtipStep(self, "step"))
        self.last_step = self.step_type(MtipLastStep(self, "last_step"))

        self.pragma_num_steps(N_LEVELS + 1)
        self.pragma_first_step(self.step)
        self.pragma_last_step(self.last_step)
        self.expose(self.hash, Last())

    def trace(self, path_indices, inputs, hashes):
        for i in range(0, N_LEVELS):
            self.add(self.step, path_indices[i], hashes[i + 1], hashes[i], inputs[i])
        self.add(self.last_step, hashes[N_LEVELS])


class MtipSuperCircuit(SuperCircuit):
    def setup(self):
        self.mimc7_constants = self.sub_circuit(Mimc7Constants(self))
        self.mimc7_multi_circuit = self.sub_circuit(
            Mimc7MultiCircuit(self, constants_table=self.mimc7_constants.lookup_table)
        )
        self.mtip_circuit = self.sub_circuit(
            MtipCircuit(self, hashes_table=self.mimc7_multi_circuit.hashes_table)
        )

    def mapping(self, leaf, siblings, path_indices, k_value):
        x_values = []
        hashes = [leaf]
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

    def mimc7(self, x_in_value, k_value):
        """
        this helper allows us to compute the MIMC7 hash values from the trace
        """
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
