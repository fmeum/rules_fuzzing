import sys
import fuzzed_data_provider_example

import atheris_no_libfuzzer as atheris

def test_one_input(data):
    fdp = atheris.FuzzedDataProvider(data)
    fuzzed_data_provider_example.TestOneInput(fdp)

print(sys.path)
atheris.Setup(sys.argv, test_one_input)
atheris.Fuzz()
