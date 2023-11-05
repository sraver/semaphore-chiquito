import unittest

from chiquito.util import F

from src.mimc7_multi import Mimc7MultiSuperCircuit

MIMC7_HASHES = [
    14567011075557169046979057478056029787674128426930277880058661460711427052125,
    11692199054940982092615924479170387654172957671167590511022002236183207976922,
    395906054129026022008845057780348852833099401379158805459513453018521692617,
    19130493425692465471846861066180574644938572620727138458073405427305790109396,
    3560224277096965087217247791371399647679779267609378004249118430431546034735,
    16356810660390430619643899229153018147591389571005035478107028055630550406583,
    16317902005975350413999538525661726963370788482516314498549194021155088989003,
    18043786089447731025868873103151703717420776635572365980060571896677015351579,
    1796113884154008951672518836034755227981159464296270078744543022432226412808,
    11660809654206505375783665500896737515384441100205794512144881665216603698919,
    13663520286129382300354630221412806469488120978894588450678096560482112481541,
    9743153325934800683751206147816815217693000749515771300051805147857600961285,
    13978034732292628078270001900051843265218683642214020320364289535464977380610,
    12648960424779329852521490204681455049995907161886185258277012781238255926462,
    3833031029499238470605699803512275908948538421065956659262283443783815981466,
    13563636626610849212448828114230007385304311723483555262594481116967116958086,
    8721465236568608391406922046845674170503807470683656794651999255945152390389,
    907466447928468216894186829106037717688223349127153633758733942177029706137,
    21452013957464035935863935157262482937248205350455390135654460714722833461130,
    15689410596481412546314975882626940181901311864195148750573666258208089354029
]


class Mimc7MultiTests(unittest.TestCase):
    def test_basic(self):
        # Arrange
        inputs = [
            F(1), F(2), F(3), F(4), F(5), F(6), F(7), F(8), F(9), F(10),
            F(11), F(12), F(13), F(14), F(15), F(16), F(17), F(18), F(19), F(20),
        ]
        k_value = F(10)

        # Act
        mimc7 = Mimc7MultiSuperCircuit()
        mimc7_multi_super_witness = mimc7.gen_witness(inputs, k_value)

        # Assert
        columns = []
        step_instances = list(mimc7_multi_super_witness.values())[0].step_instances
        for step_index, step in enumerate(step_instances):
            for i, signal in enumerate(step.assignments):
                if signal.__str__() == "enable_lookup":
                    if list(step.assignments.values())[i] == 1:
                        columns.append(step_index)

        for i, column in enumerate(columns):
            row_result = list(step_instances[column].assignments.values())[4]
            assert row_result == MIMC7_HASHES[i]

        try:
            mimc7.halo2_mock_prover(mimc7_multi_super_witness)
        except Exception:
            assert False, "Proof failed"


if __name__ == '__main__':
    unittest.main()
