from textwrap import dedent

from sigma.backends.logpoint import Logpoint
from sigma.collection import SigmaCollection


SAMPLE_RULES = [
    (
        "Single selection",
        """
        title: Simple equality
        status: test
        logsource:
            product: test_product
            category: test_category
        detection:
            sel:
                fieldA: valueA
            condition: sel
        """,
    ),
    (
        "OR combination",
        """
        title: OR combination
        status: test
        logsource:
            product: test_product
            category: test_category
        detection:
            sel1:
                fieldA: valueA
            sel2:
                fieldB: valueB
            condition: 1 of sel*
        """,
    ),
    (
        "AND with lists",
        """
        title: List expansion
        status: test
        logsource:
            product: test_product
            category: test_category
        detection:
            sel:
                fieldA:
                    - valueA1
                    - valueA2
                fieldB:
                    - valueB1
                    - valueB2
            condition: sel
        """,
    ),
    (
        "Field name with whitespace",
        """
        title: Whitespace field
        status: test
        logsource:
            product: test_product
            category: test_category
        detection:
            sel:
                field name: value
            condition: sel
        """,
    ),
    (
        "Compact NOT",
        """
        title: Compact NOT
        status: test
        logsource:
            product: test_product
            category: test_category
        detection:
            sel1:
                fieldA: valueA
            sel2:
                fieldB: valueB
            condition: not (sel1 or sel2)
        """,
    ),
    (
        "Null filter",
        """
        title: Null filter
        status: test
        logsource:
            product: test_product
            category: test_category
        detection:
            filter:
                fieldA: null
            condition: not filter
        """,
    ),
    (
        "Endswith and null filters",
        """
        title: Endswith null filters
        status: test
        logsource:
            product: test_product
            category: test_category
        detection:
            selection:
                FieldA|endswith: 'valueA'
            filter_1:
                FieldB: null
            filter_2:
                FieldB: ''
            condition: selection and not filter_1 and not filter_2
        """,
    ),
    (
        "CIDR",
        """
        title: CIDR filter
        status: test
        logsource:
            product: test_product
            category: test_category
        detection:
            sel:
                field|cidr:
                    - 192.168.0.0/16
                    - 10.0.0.0/8
                fieldB: foo
                fieldC: bar
            condition: sel
        """,
    ),
    (
        "Regex",
        """
        title: Regex test
        status: test
        logsource:
            product: test_product
            category: test_category
        detection:
            sel:
                fieldA|re: foo.*bar
                fieldB: foo
            condition: sel
        """,
    ),
    (
        "Contains all",
        """
        title: Contains all
        status: test
        logsource:
            product: test_product
            category: test_category
        detection:
            sel:
                fieldA|contains|all:
                    - valueA
                    - valueB
            condition: sel
        """,
    ),
]


def convert_samples() -> None:
    backend = Logpoint()
    for index, (title, yaml_rule) in enumerate(SAMPLE_RULES, start=1):
        collection = SigmaCollection.from_yaml(dedent(yaml_rule))
        conversions = backend.convert(collection)
        print(f"{index}. {title}:")
        for conversion in conversions:
            print(f"   {conversion}")
        print()


if __name__ == "__main__":
    convert_samples()
