"""
cvss40.py — CVSS v4.0 calculator.

Pure-Python port of cvss40.js (RedHat / FIRST reference implementation).
Zero external dependencies.

Usage
-----
    from cvss40 import CVSS40, Vector

    vuln = CVSS40("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N/E:A/MAV:A")
    print(vuln.score)      # 8.7
    print(vuln.severity)   # High
    print(vuln.vector.nomenclature)   # CVSS-BTE
    print(vuln.vector.raw)
"""

from __future__ import annotations

import math
from typing import Dict, List, Optional, Union


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _round_to_decimal_places(value: float) -> float:
    """Round Half Up to 1 decimal place (matches JS EPSILON trick)."""
    EPSILON = 10 ** -6
    return math.floor((value + EPSILON) * 10 + 0.5) / 10


# ---------------------------------------------------------------------------
# Vector
# ---------------------------------------------------------------------------

class Vector:
    """Encapsulates a CVSS v4.0 vector string and its metrics."""

    METRICS: Dict[str, Dict[str, List[str]]] = {
        # Base (11 metrics)
        "BASE": {
            "AV": ["N", "A", "L", "P"],
            "AC": ["L", "H"],
            "AT": ["N", "P"],
            "PR": ["N", "L", "H"],
            "UI": ["N", "P", "A"],
            "VC": ["N", "L", "H"],
            "VI": ["N", "L", "H"],
            "VA": ["N", "L", "H"],
            "SC": ["N", "L", "H"],
            "SI": ["N", "L", "H"],
            "SA": ["N", "L", "H"],
        },
        # Threat (1 metric)
        "THREAT": {
            "E": ["X", "A", "P", "U"],
        },
        # Environmental (14 metrics)
        "ENVIRONMENTAL": {
            "CR":  ["X", "H", "M", "L"],
            "IR":  ["X", "H", "M", "L"],
            "AR":  ["X", "H", "M", "L"],
            "MAV": ["X", "N", "A", "L", "P"],
            "MAC": ["X", "L", "H"],
            "MAT": ["X", "N", "P"],
            "MPR": ["X", "N", "L", "H"],
            "MUI": ["X", "N", "P", "A"],
            "MVC": ["X", "H", "L", "N"],
            "MVI": ["X", "H", "L", "N"],
            "MVA": ["X", "H", "L", "N"],
            "MSC": ["X", "H", "L", "N"],
            "MSI": ["X", "S", "H", "L", "N"],
            "MSA": ["X", "S", "H", "L", "N"],
        },
        # Supplemental (6 metrics)
        "SUPPLEMENTAL": {
            "S":  ["X", "N", "P"],
            "AU": ["X", "N", "Y"],
            "R":  ["X", "A", "U", "I"],
            "V":  ["X", "D", "C"],
            "RE": ["X", "L", "M", "H"],
            "U":  ["X", "Clear", "Green", "Amber", "Red"],
        },
    }

    # Flattened ordered dict of all metric → allowed values
    ALL_METRICS: Dict[str, List[str]] = {}
    for _cat in METRICS.values():
        ALL_METRICS.update(_cat)

    BASE_NOMENCLATURE = "CVSS-B"

    def __init__(self, vector_string: str = "") -> None:
        # Initialise with defaults (first value in each allowed list)
        self.metrics: Dict[str, str] = {}
        for cat in self.METRICS.values():
            for key, allowed in cat.items():
                self.metrics[key] = allowed[0]

        if vector_string:
            if vector_string.startswith("#"):
                vector_string = vector_string[1:]
            self.update_metrics_from_vector_string(vector_string)

    # ------------------------------------------------------------------
    # raw property
    # ------------------------------------------------------------------

    @property
    def raw(self) -> str:
        parts = [f"/{k}:{v}" for k, v in self.metrics.items() if v != "X"]
        return "CVSS:4.0" + "".join(parts)

    # ------------------------------------------------------------------
    # equivalent_classes
    # ------------------------------------------------------------------

    @property
    def equivalent_classes(self) -> str:
        def eq1() -> str:
            av = self.get_effective_metric_value("AV")
            pr = self.get_effective_metric_value("PR")
            ui = self.get_effective_metric_value("UI")
            if av == "N" and pr == "N" and ui == "N":
                return "0"
            if (av == "N" or pr == "N" or ui == "N") and not (av == "N" and pr == "N" and ui == "N") and av != "P":
                return "1"
            return "2"

        def eq2() -> str:
            ac = self.get_effective_metric_value("AC")
            at = self.get_effective_metric_value("AT")
            return "0" if (ac == "L" and at == "N") else "1"

        def eq3() -> str:
            vc = self.get_effective_metric_value("VC")
            vi = self.get_effective_metric_value("VI")
            va = self.get_effective_metric_value("VA")
            if vc == "H" and vi == "H":
                return "0"
            if not (vc == "H" and vi == "H") and (vc == "H" or vi == "H" or va == "H"):
                return "1"
            return "2"

        def eq4() -> str:
            msi = self.get_effective_metric_value("MSI")
            msa = self.get_effective_metric_value("MSA")
            sc  = self.get_effective_metric_value("SC")
            si  = self.get_effective_metric_value("SI")
            sa  = self.get_effective_metric_value("SA")
            if msi == "S" or msa == "S":
                return "0"
            if not (msi == "S" or msa == "S") and (sc == "H" or si == "H" or sa == "H"):
                return "1"
            return "2"

        def eq5() -> str:
            e = self.get_effective_metric_value("E")
            if e == "A": return "0"
            if e == "P": return "1"
            return "2"

        def eq6() -> str:
            cr = self.get_effective_metric_value("CR")
            vc = self.get_effective_metric_value("VC")
            ir = self.get_effective_metric_value("IR")
            vi = self.get_effective_metric_value("VI")
            ar = self.get_effective_metric_value("AR")
            va = self.get_effective_metric_value("VA")
            if (cr == "H" and vc == "H") or (ir == "H" and vi == "H") or (ar == "H" and va == "H"):
                return "0"
            return "1"

        return eq1() + eq2() + eq3() + eq4() + eq5() + eq6()

    # ------------------------------------------------------------------
    # nomenclature
    # ------------------------------------------------------------------

    @property
    def nomenclature(self) -> str:
        name = self.BASE_NOMENCLATURE
        if any(self.metrics.get(k) != "X" for k in self.METRICS["THREAT"]):
            name += "T"
        if any(self.metrics.get(k) != "X" for k in self.METRICS["ENVIRONMENTAL"]):
            name += "E"
        return name

    # ------------------------------------------------------------------
    # severity_breakdown
    # ------------------------------------------------------------------

    @property
    def severity_breakdown(self) -> Dict[str, str]:
        mv = self.equivalent_classes
        details = [
            "Exploitability",
            "Complexity",
            "Vulnerable system",
            "Subsequent system",
            "Exploitation",
            "Security requirements",
        ]
        two_only = {"Complexity", "Security requirements"}
        three_sev = ["High", "Medium", "Low"]
        two_sev   = ["High", "Low"]

        result = {}
        for i, desc in enumerate(details):
            opts = two_sev if desc in two_only else three_sev
            result[desc] = opts[int(mv[i])]
        return result

    # ------------------------------------------------------------------
    # get_effective_metric_value
    # ------------------------------------------------------------------

    def get_effective_metric_value(self, metric: str) -> str:
        worst_case_defaults = {"E": "A", "CR": "H", "IR": "H", "AR": "H"}

        if self.metrics.get(metric) == "X" and metric in worst_case_defaults:
            return worst_case_defaults[metric]

        modified = "M" + metric
        if modified in self.metrics and self.metrics[modified] != "X":
            return self.metrics[modified]

        return self.metrics[metric]

    # ------------------------------------------------------------------
    # validate_string_vector
    # ------------------------------------------------------------------

    def validate_string_vector(self, vector: str) -> bool:
        parts = vector.split("/")

        if parts[0] != "CVSS:4.0":
            return False

        expected = list(self.ALL_METRICS.items())   # [(key, allowed_values), ...]
        idx = 0

        for metric_str in parts[1:]:
            if ":" not in metric_str:
                return False
            key, value = metric_str.split(":", 1)

            if idx >= len(expected):
                return False

            # Advance idx to find this key
            while idx < len(expected) and expected[idx][0] != key:
                if idx < 11:  # mandatory base metrics
                    return False
                idx += 1

            if idx >= len(expected):
                return False

            if value not in expected[idx][1]:
                return False

            idx += 1

        return True

    # ------------------------------------------------------------------
    # update_metrics_from_vector_string
    # ------------------------------------------------------------------

    def update_metrics_from_vector_string(self, vector: str) -> None:
        if not vector:
            raise ValueError("Vector string cannot be empty.")
        if not self.validate_string_vector(vector):
            raise ValueError(f"Invalid CVSS v4.0 vector: {vector}")

        parts = vector.split("/")[1:]  # skip "CVSS:4.0"
        for part in parts:
            key, value = part.split(":", 1)
            self.metrics[key] = value

    # ------------------------------------------------------------------
    # update_metric
    # ------------------------------------------------------------------

    def update_metric(self, metric: str, value: str) -> None:
        if metric in self.metrics:
            self.metrics[metric] = value


# ---------------------------------------------------------------------------
# CVSS40
# ---------------------------------------------------------------------------

class CVSS40:
    """CVSS v4.0 scorer."""

    LOOKUP_TABLE: Dict[str, float] = {
        "000000": 10,   "000001": 9.9,  "000010": 9.8,  "000011": 9.5,
        "000020": 9.5,  "000021": 9.2,  "000100": 10,   "000101": 9.6,
        "000110": 9.3,  "000111": 8.7,  "000120": 9.1,  "000121": 8.1,
        "000200": 9.3,  "000201": 9.0,  "000210": 8.9,  "000211": 8.0,
        "000220": 8.1,  "000221": 6.8,  "001000": 9.8,  "001001": 9.5,
        "001010": 9.5,  "001011": 9.2,  "001020": 9.0,  "001021": 8.4,
        "001100": 9.3,  "001101": 9.2,  "001110": 8.9,  "001111": 8.1,
        "001120": 8.1,  "001121": 6.5,  "001200": 8.8,  "001201": 8.0,
        "001210": 7.8,  "001211": 7.0,  "001220": 6.9,  "001221": 4.8,
        "002001": 9.2,  "002011": 8.2,  "002021": 7.2,  "002101": 7.9,
        "002111": 6.9,  "002121": 5.0,  "002201": 6.9,  "002211": 5.5,
        "002221": 2.7,  "010000": 9.9,  "010001": 9.7,  "010010": 9.5,
        "010011": 9.2,  "010020": 9.2,  "010021": 8.5,  "010100": 9.5,
        "010101": 9.1,  "010110": 9.0,  "010111": 8.3,  "010120": 8.4,
        "010121": 7.1,  "010200": 9.2,  "010201": 8.1,  "010210": 8.2,
        "010211": 7.1,  "010220": 7.2,  "010221": 5.3,  "011000": 9.5,
        "011001": 9.3,  "011010": 9.2,  "011011": 8.5,  "011020": 8.5,
        "011021": 7.3,  "011100": 9.2,  "011101": 8.2,  "011110": 8.0,
        "011111": 7.2,  "011120": 7.0,  "011121": 5.9,  "011200": 8.4,
        "011201": 7.0,  "011210": 7.1,  "011211": 5.2,  "011220": 5.0,
        "011221": 3.0,  "012001": 8.6,  "012011": 7.5,  "012021": 5.2,
        "012101": 7.1,  "012111": 5.2,  "012121": 2.9,  "012201": 6.3,
        "012211": 2.9,  "012221": 1.7,  "100000": 9.8,  "100001": 9.5,
        "100010": 9.4,  "100011": 8.7,  "100020": 9.1,  "100021": 8.1,
        "100100": 9.4,  "100101": 8.9,  "100110": 8.6,  "100111": 7.4,
        "100120": 7.7,  "100121": 6.4,  "100200": 8.7,  "100201": 7.5,
        "100210": 7.4,  "100211": 6.3,  "100220": 6.3,  "100221": 4.9,
        "101000": 9.4,  "101001": 8.9,  "101010": 8.8,  "101011": 7.7,
        "101020": 7.6,  "101021": 6.7,  "101100": 8.6,  "101101": 7.6,
        "101110": 7.4,  "101111": 5.8,  "101120": 5.9,  "101121": 5.0,
        "101200": 7.2,  "101201": 5.7,  "101210": 5.7,  "101211": 5.2,
        "101220": 5.2,  "101221": 2.5,  "102001": 8.3,  "102011": 7.0,
        "102021": 5.4,  "102101": 6.5,  "102111": 5.8,  "102121": 2.6,
        "102201": 5.3,  "102211": 2.1,  "102221": 1.3,  "110000": 9.5,
        "110001": 9.0,  "110010": 8.8,  "110011": 7.6,  "110020": 7.6,
        "110021": 7.0,  "110100": 9.0,  "110101": 7.7,  "110110": 7.5,
        "110111": 6.2,  "110120": 6.1,  "110121": 5.3,  "110200": 7.7,
        "110201": 6.6,  "110210": 6.8,  "110211": 5.9,  "110220": 5.2,
        "110221": 3.0,  "111000": 8.9,  "111001": 7.8,  "111010": 7.6,
        "111011": 6.7,  "111020": 6.2,  "111021": 5.8,  "111100": 7.4,
        "111101": 5.9,  "111110": 5.7,  "111111": 5.7,  "111120": 4.7,
        "111121": 2.3,  "111200": 6.1,  "111201": 5.2,  "111210": 5.7,
        "111211": 2.9,  "111220": 2.4,  "111221": 1.6,  "112001": 7.1,
        "112011": 5.9,  "112021": 3.0,  "112101": 5.8,  "112111": 2.6,
        "112121": 1.5,  "112201": 2.3,  "112211": 1.3,  "112221": 0.6,
        "200000": 9.3,  "200001": 8.7,  "200010": 8.6,  "200011": 7.2,
        "200020": 7.5,  "200021": 5.8,  "200100": 8.6,  "200101": 7.4,
        "200110": 7.4,  "200111": 6.1,  "200120": 5.6,  "200121": 3.4,
        "200200": 7.0,  "200201": 5.4,  "200210": 5.2,  "200211": 4.0,
        "200220": 4.0,  "200221": 2.2,  "201000": 8.5,  "201001": 7.5,
        "201010": 7.4,  "201011": 5.5,  "201020": 6.2,  "201021": 5.1,
        "201100": 7.2,  "201101": 5.7,  "201110": 5.5,  "201111": 4.1,
        "201120": 4.6,  "201121": 1.9,  "201200": 5.3,  "201201": 3.6,
        "201210": 3.4,  "201211": 1.9,  "201220": 1.9,  "201221": 0.8,
        "202001": 6.4,  "202011": 5.1,  "202021": 2.0,  "202101": 4.7,
        "202111": 2.1,  "202121": 1.1,  "202201": 2.4,  "202211": 0.9,
        "202221": 0.4,  "210000": 8.8,  "210001": 7.5,  "210010": 7.3,
        "210011": 5.3,  "210020": 6.0,  "210021": 5.0,  "210100": 7.3,
        "210101": 5.5,  "210110": 5.9,  "210111": 4.0,  "210120": 4.1,
        "210121": 2.0,  "210200": 5.4,  "210201": 4.3,  "210210": 4.5,
        "210211": 2.2,  "210220": 2.0,  "210221": 1.1,  "211000": 7.5,
        "211001": 5.5,  "211010": 5.8,  "211011": 4.5,  "211020": 4.0,
        "211021": 2.1,  "211100": 6.1,  "211101": 5.1,  "211110": 4.8,
        "211111": 1.8,  "211120": 2.0,  "211121": 0.9,  "211200": 4.6,
        "211201": 1.8,  "211210": 1.7,  "211211": 0.7,  "211220": 0.8,
        "211221": 0.2,  "212001": 5.3,  "212011": 2.4,  "212021": 1.4,
        "212101": 2.4,  "212111": 1.2,  "212121": 0.5,  "212201": 1.0,
        "212211": 0.3,  "212221": 0.1,
    }

    METRIC_LEVELS: Dict[str, Dict[str, float]] = {
        "AV": {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3},
        "PR": {"N": 0.0, "L": 0.1, "H": 0.2},
        "UI": {"N": 0.0, "P": 0.1, "A": 0.2},
        "AC": {"L": 0.0, "H": 0.1},
        "AT": {"N": 0.0, "P": 0.1},
        "VC": {"H": 0.0, "L": 0.1, "N": 0.2},
        "VI": {"H": 0.0, "L": 0.1, "N": 0.2},
        "VA": {"H": 0.0, "L": 0.1, "N": 0.2},
        "SC": {"H": 0.1, "L": 0.2, "N": 0.3},
        "SI": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
        "SA": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
        "CR": {"H": 0.0, "M": 0.1, "L": 0.2},
        "IR": {"H": 0.0, "M": 0.1, "L": 0.2},
        "AR": {"H": 0.0, "M": 0.1, "L": 0.2},
        "E":  {"U": 0.2, "P": 0.1, "A": 0.0},
    }

    MAX_COMPOSED: Dict[str, Dict] = {
        "eq1": {
            "0": ["AV:N/PR:N/UI:N/"],
            "1": ["AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"],
            "2": ["AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"],
        },
        "eq2": {
            "0": ["AC:L/AT:N/"],
            "1": ["AC:H/AT:N/", "AC:L/AT:P/"],
        },
        "eq3": {
            "0": {
                "0": ["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"],
                "1": ["VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"],
            },
            "1": {
                "0": ["VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"],
                "1": ["VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/", "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/",
                      "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/", "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/",
                      "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/"],
            },
            "2": {
                "1": ["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"],
            },
        },
        "eq4": {
            "0": ["SC:H/SI:S/SA:S/"],
            "1": ["SC:H/SI:H/SA:H/"],
            "2": ["SC:L/SI:L/SA:L/"],
        },
        "eq5": {
            "0": ["E:A/"],
            "1": ["E:P/"],
            "2": ["E:U/"],
        },
    }

    MAX_SEVERITY: Dict[str, Dict] = {
        "eq1":    {"0": 1, "1": 4, "2": 5},
        "eq2":    {"0": 1, "1": 2},
        "eq3eq6": {
            "0": {"0": 7, "1": 6},
            "1": {"0": 8, "1": 8},
            "2": {"1": 10},
        },
        "eq4":    {"0": 6, "1": 5, "2": 4},
        "eq5":    {"0": 1, "1": 1, "2": 1},
    }

    # ------------------------------------------------------------------
    # constructor
    # ------------------------------------------------------------------

    def __init__(self, input_: Union[str, Vector] = "") -> None:
        if isinstance(input_, Vector):
            self.vector = input_
        elif isinstance(input_, str):
            self.vector = Vector(input_)
        else:
            raise TypeError(f"Expected str or Vector, got {type(input_)}")

        self.score    = self.calculate_score()
        self.severity = self.calculate_severity_rating(self.score)

    # ------------------------------------------------------------------
    # calculate_severity_rating
    # ------------------------------------------------------------------

    @staticmethod
    def calculate_severity_rating(score: float) -> str:
        if score == 0.0:       return "None"
        if score <= 3.9:       return "Low"
        if score <= 6.9:       return "Medium"
        if score <= 8.9:       return "High"
        if score <= 10.0:      return "Critical"
        return "Unknown"

    # ------------------------------------------------------------------
    # extract_value_metric
    # ------------------------------------------------------------------

    @staticmethod
    def extract_value_metric(metric: str, s: str) -> str:
        idx = s.index(metric) + len(metric) + 1
        extracted = s[idx:]
        slash = extracted.find("/")
        return extracted[:slash] if slash > 0 else extracted

    # ------------------------------------------------------------------
    # calculate_severity_distances
    # ------------------------------------------------------------------

    def calculate_severity_distances(self, max_vector: str) -> Dict[str, float]:
        distances: Dict[str, float] = {}
        for metric in self.METRIC_LEVELS:
            effective = self.vector.get_effective_metric_value(metric)
            extracted = self.extract_value_metric(metric, max_vector)
            distances[metric] = (
                self.METRIC_LEVELS[metric][effective]
                - self.METRIC_LEVELS[metric][extracted]
            )
        return distances

    # ------------------------------------------------------------------
    # get_max_severity_vectors_for_eq
    # ------------------------------------------------------------------

    def get_max_severity_vectors_for_eq(self, macro_vector: str, eq_number: int) -> List[str]:
        key = str(macro_vector[eq_number - 1])
        return self.MAX_COMPOSED[f"eq{eq_number}"][key]

    # ------------------------------------------------------------------
    # calculate_score
    # ------------------------------------------------------------------

    def calculate_score(self) -> float:
        NO_IMPACT = ["VC", "VI", "VA", "SC", "SI", "SA"]
        STEP = 0.1

        if all(self.vector.get_effective_metric_value(m) == "N" for m in NO_IMPACT):
            return 0.0

        eq_classes = self.vector.equivalent_classes
        value = self.LOOKUP_TABLE[eq_classes]

        eq1, eq2, eq3, eq4, eq5, eq6 = (int(c) for c in eq_classes)

        # Next-lower macrovectors
        eq1_nlm = f"{eq1+1}{eq2}{eq3}{eq4}{eq5}{eq6}"
        eq2_nlm = f"{eq1}{eq2+1}{eq3}{eq4}{eq5}{eq6}"
        eq4_nlm = f"{eq1}{eq2}{eq3}{eq4+1}{eq5}{eq6}"
        eq5_nlm = f"{eq1}{eq2}{eq3}{eq4}{eq5+1}{eq6}"

        # eq3+eq6 combined
        if eq3 == 1 and eq6 == 1:
            eq3eq6_nlm        = f"{eq1}{eq2}{eq3+1}{eq4}{eq5}{eq6}"
            eq3eq6_nlm_left   = None
            eq3eq6_nlm_right  = None
        elif eq3 == 0 and eq6 == 1:
            eq3eq6_nlm        = f"{eq1}{eq2}{eq3+1}{eq4}{eq5}{eq6}"
            eq3eq6_nlm_left   = None
            eq3eq6_nlm_right  = None
        elif eq3 == 1 and eq6 == 0:
            eq3eq6_nlm        = f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6+1}"
            eq3eq6_nlm_left   = None
            eq3eq6_nlm_right  = None
        elif eq3 == 0 and eq6 == 0:
            eq3eq6_nlm        = None
            eq3eq6_nlm_left   = f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6+1}"
            eq3eq6_nlm_right  = f"{eq1}{eq2}{eq3+1}{eq4}{eq5}{eq6}"
        else:
            eq3eq6_nlm        = f"{eq1}{eq2}{eq3+1}{eq4}{eq5}{eq6+1}"
            eq3eq6_nlm_left   = None
            eq3eq6_nlm_right  = None

        _nan = float("nan")

        score_eq1_nlm = self.LOOKUP_TABLE.get(eq1_nlm, _nan)
        score_eq2_nlm = self.LOOKUP_TABLE.get(eq2_nlm, _nan)
        score_eq4_nlm = self.LOOKUP_TABLE.get(eq4_nlm, _nan)
        score_eq5_nlm = self.LOOKUP_TABLE.get(eq5_nlm, _nan)

        if eq3 == 0 and eq6 == 0:
            left  = self.LOOKUP_TABLE.get(eq3eq6_nlm_left,  _nan)
            right = self.LOOKUP_TABLE.get(eq3eq6_nlm_right, _nan)
            # max, ignoring NaN by treating it as -inf for max purposes
            candidates = [x for x in (left, right) if not math.isnan(x)]
            score_eq3eq6_nlm = max(candidates) if candidates else _nan
        else:
            score_eq3eq6_nlm = self.LOOKUP_TABLE.get(eq3eq6_nlm, _nan)

        # Max severity vectors
        eq_str6 = str(eq6)
        eq_maxes = [
            self.get_max_severity_vectors_for_eq(eq_classes, 1),
            self.get_max_severity_vectors_for_eq(eq_classes, 2),
            self.MAX_COMPOSED["eq3"][str(eq3)][eq_str6],
            self.get_max_severity_vectors_for_eq(eq_classes, 4),
            self.get_max_severity_vectors_for_eq(eq_classes, 5),
        ]

        # Build max vectors (cartesian product)
        max_vectors: List[str] = []
        for a in eq_maxes[0]:
            for b in eq_maxes[1]:
                for c in eq_maxes[2]:
                    for d in eq_maxes[3]:
                        for e in eq_maxes[4]:
                            max_vectors.append(a + b + c + d + e)

        # Find the first max vector where all distances ≥ 0
        distances: Optional[Dict[str, float]] = None
        for mv in max_vectors:
            d = self.calculate_severity_distances(mv)
            if all(v >= 0 for v in d.values()):
                distances = d
                break

        if distances is None:
            distances = {}

        csd_eq1     = distances.get("AV", 0) + distances.get("PR", 0) + distances.get("UI", 0)
        csd_eq2     = distances.get("AC", 0) + distances.get("AT", 0)
        csd_eq3eq6  = (distances.get("VC", 0) + distances.get("VI", 0) + distances.get("VA", 0)
                       + distances.get("CR", 0) + distances.get("IR", 0) + distances.get("AR", 0))
        csd_eq4     = distances.get("SC", 0) + distances.get("SI", 0) + distances.get("SA", 0)

        avail_eq1    = value - score_eq1_nlm
        avail_eq2    = value - score_eq2_nlm
        avail_eq3eq6 = value - score_eq3eq6_nlm
        avail_eq4    = value - score_eq4_nlm
        avail_eq5    = value - score_eq5_nlm

        maxsev_eq1    = self.MAX_SEVERITY["eq1"][str(eq1)]    * STEP
        maxsev_eq2    = self.MAX_SEVERITY["eq2"][str(eq2)]    * STEP
        maxsev_eq3eq6 = self.MAX_SEVERITY["eq3eq6"][str(eq3)][str(eq6)] * STEP
        maxsev_eq4    = self.MAX_SEVERITY["eq4"][str(eq4)]    * STEP

        n_existing = 0
        norm_eq1 = norm_eq2 = norm_eq3eq6 = norm_eq4 = norm_eq5 = 0.0

        if not math.isnan(avail_eq1):
            n_existing += 1
            pct = csd_eq1 / maxsev_eq1 if maxsev_eq1 else 0
            norm_eq1 = avail_eq1 * pct

        if not math.isnan(avail_eq2):
            n_existing += 1
            pct = csd_eq2 / maxsev_eq2 if maxsev_eq2 else 0
            norm_eq2 = avail_eq2 * pct

        if not math.isnan(avail_eq3eq6):
            n_existing += 1
            pct = csd_eq3eq6 / maxsev_eq3eq6 if maxsev_eq3eq6 else 0
            norm_eq3eq6 = avail_eq3eq6 * pct

        if not math.isnan(avail_eq4):
            n_existing += 1
            pct = csd_eq4 / maxsev_eq4 if maxsev_eq4 else 0
            norm_eq4 = avail_eq4 * pct

        if not math.isnan(avail_eq5):
            n_existing += 1
            # EQ5 percentage is always 0
            norm_eq5 = 0.0

        mean_distance = (
            0.0 if n_existing == 0
            else (norm_eq1 + norm_eq2 + norm_eq3eq6 + norm_eq4 + norm_eq5) / n_existing
        )

        return _round_to_decimal_places(max(0.0, min(10.0, value - mean_distance)))