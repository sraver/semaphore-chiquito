from __future__ import annotations

from chiquito.dsl import SuperCircuit, Circuit, StepType
from chiquito.cb import table, eq
from chiquito.util import F

from src.mimc7_constants import ROUND_CONSTANTS, ROUNDS

MAX_LEVELS = 100


# It's the best practice to wrap all values in F, even though the `assign` functions automatically wrap values in F.
class Mimc7Constants(Circuit):
    def setup(self):
        self.pragma_num_steps(ROUNDS)
        self.lookup_row = self.fixed("constant row")
        self.lookup_c = self.fixed("constant value")
        self.lookup_table = self.new_table(
            table().add(self.lookup_row).add(self.lookup_c)
        )

    def fixed_gen(self):
        for i, round_key in enumerate(ROUND_CONSTANTS):
            self.assign(i, self.lookup_row, F(i))
            self.assign(i, self.lookup_c, F(round_key))


class Mimc7FirstStep(StepType):
    def setup(self):
        self.xkc = self.internal("xkc")
        self.y = self.internal("y")
        self.c = self.internal("c")

        self.constr(eq(self.circuit.enable_lookup, 0))
        self.constr(eq(self.circuit.x + self.circuit.k + self.c, self.xkc))
        self.constr(
            eq(
                self.xkc
                * self.xkc
                * self.xkc
                * self.xkc
                * self.xkc
                * self.xkc
                * self.xkc,
                self.y,
            )
        )

        self.transition(eq(self.y, self.circuit.x.next()))
        self.transition(eq(self.circuit.k, self.circuit.k.next()))
        self.transition(eq(self.circuit.row, 0))
        self.transition(eq(self.circuit.row + 1, self.circuit.row.next()))

        self.add_lookup(
            self.circuit.constants_table.apply(self.circuit.row).apply(self.c)
        )

    def wg(self, i_value, x_value, k_value, c_value, row_value):
        self.assign(self.circuit.original_input, F(i_value))
        self.assign(self.circuit.x, F(x_value))
        self.assign(self.circuit.k, F(k_value))
        self.assign(self.c, F(c_value))
        self.assign(self.circuit.row, F(row_value))

        xkc_value = F(x_value + k_value + c_value)
        self.assign(self.xkc, F(xkc_value))
        self.assign(self.y, F(xkc_value ** 7))
        self.assign(self.circuit.enable_lookup, F(0))


class Mimc7Step(StepType):
    def setup(self):
        self.xkc = self.internal("xkc")
        self.y = self.internal("y")
        self.c = self.internal("c")

        self.constr(eq(self.circuit.enable_lookup, 0))
        self.constr(eq(self.circuit.x + self.circuit.k + self.c, self.xkc))
        self.constr(
            eq(
                self.xkc
                * self.xkc
                * self.xkc
                * self.xkc
                * self.xkc
                * self.xkc
                * self.xkc,
                self.y,
            )
        )

        self.transition(eq(self.y, self.circuit.x.next()))
        self.transition(eq(self.circuit.k, self.circuit.k.next()))
        self.transition(eq(self.circuit.row + 1, self.circuit.row.next()))

        self.add_lookup(
            self.circuit.constants_table.apply(self.circuit.row).apply(self.c)
        )

    def wg(self, i_value, x_value, k_value, c_value, row_value):
        self.assign(self.circuit.original_input, F(i_value))
        self.assign(self.circuit.x, F(x_value))
        self.assign(self.circuit.k, F(k_value))
        self.assign(self.c, F(c_value))
        self.assign(self.circuit.row, F(row_value))

        xkc_value = F(x_value + k_value + c_value)
        self.assign(self.xkc, F(xkc_value))
        self.assign(self.y, F(xkc_value ** 7))
        self.assign(self.circuit.enable_lookup, F(0))


class Mimc7LastStep(StepType):
    def setup(self):
        self.constr(eq(self.circuit.x + self.circuit.k, self.circuit.out))
        self.constr(eq(self.circuit.enable_lookup, 1))

    def wg(self, i_value, x_value, k_value, _, row_value):
        self.assign(self.circuit.original_input, F(i_value))
        self.assign(self.circuit.x, F(x_value))
        self.assign(self.circuit.k, F(k_value))
        self.assign(self.circuit.row, F(row_value))
        self.assign(self.circuit.out, F(x_value + k_value))
        self.assign(self.circuit.enable_lookup, F(1))


class Mimc7Padding(StepType):
    def setup(self):
        self.constr(eq(self.circuit.enable_lookup, F(0)))

    def wg(self):
        self.assign(self.circuit.enable_lookup, F(0))


# It's the best practice to wrap all values in F, even though the `assign` functions automatically wrap values in F.
class Mimc7MultiCircuit(Circuit):
    def setup(self):
        # defines signals
        self.x = self.forward("x")
        self.k = self.forward("k")
        self.row = self.forward("row")
        self.out = self.forward("out")
        self.enable_lookup = self.forward("enable_lookup")
        self.original_input = self.forward("original_input")

        # define necessary step types
        self.mimc7_first_step = self.step_type(Mimc7FirstStep(self, "mimc7_first_step"))
        self.mimc7_step = self.step_type(Mimc7Step(self, "mimc7_step"))
        self.mimc7_last_step = self.step_type(Mimc7LastStep(self, "mimc7_last_step"))
        self.mimc7_padding = self.step_type(Mimc7Padding(self, "mimc7_padding"))

        # define circuit constraints
        self.pragma_first_step(self.mimc7_first_step)
        self.pragma_last_step(self.mimc7_padding)
        self.pragma_num_steps((ROUNDS + 2 - 1) * MAX_LEVELS)

        # define lookup table to store the hashes and the inputs that generate them
        self.hashes_table = self.new_table(
            table()
            .add(self.enable_lookup)
            .add(self.original_input)
            .add(self.out)
        )

    def trace(self, x_values, k_value):
        # compute hashes for every input
        for x_value in x_values:
            self.trace_single(x_value, k_value)
        # fill with padding
        while self.needs_padding():
            self.add(self.mimc7_padding)

    def trace_single(self, x_in_value, k_value):
        """
        performs the hash logic, and adds all the necessary steps of a single compute
        """
        c_value = F(ROUND_CONSTANTS[0])
        i_value = F(x_in_value)
        x_value = F(x_in_value)
        row_value = F(0)

        self.add(self.mimc7_first_step, i_value, x_value, k_value, c_value, row_value)

        for i in range(1, ROUNDS):
            row_value += F(1)
            x_value += F(k_value + c_value)
            x_value = F(x_value ** 7)
            c_value = F(ROUND_CONSTANTS[i])

            self.add(self.mimc7_step, i_value, x_value, k_value, c_value, row_value)

        row_value += F(1)
        x_value += F(k_value + c_value)
        x_value = F(x_value ** 7)

        self.add(self.mimc7_last_step, i_value, x_value, k_value, c_value, row_value)


class Mimc7MultiSuperCircuit(SuperCircuit):
    def setup(self):
        self.mimc7_constants = self.sub_circuit(Mimc7Constants(self))
        self.mimc7_multi_circuit = self.sub_circuit(
            Mimc7MultiCircuit(self, constants_table=self.mimc7_constants.lookup_table)
        )

    def mapping(self, x_values, k_value):
        self.map(self.mimc7_multi_circuit, x_values, k_value)
