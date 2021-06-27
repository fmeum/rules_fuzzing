import sys
import fuzzing_example

import atheris_no_libfuzzer as atheris

print(sys.path)
atheris.Setup(sys.argv, fuzzing_example.test_one_input)
atheris.Fuzz()
