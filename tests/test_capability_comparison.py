import unittest

from dlms_enum.capability_comparison import (
    build_workflow_comparison,
    compare_role_capabilities,
    render_comparison_markdown,
)


def snapshot(role, objects):
    return {
        "identity": {"role": role, "meter_identity": "METER-1"},
        "objects": objects,
    }


def object_record(class_id, logical_name, *, attributes=(), methods=()):
    return {
        "class_id": class_id,
        "logical_name": logical_name,
        "object_version": 3,
        "attributes": list(attributes),
        "methods": list(methods),
    }


def attribute(index, *, read=False, write=False, requirements=()):
    return {
        "attribute_id": index,
        "name": f"Attribute {index}",
        "access_rights": {
            "read": read,
            "write": write,
            "mode": "read_write" if read and write else "read" if read else "write",
            "requirements": list(requirements),
            "raw": 3,
        },
    }


def method(index, *, requirements=()):
    return {
        "method_id": index,
        "name": f"Method {index}",
        "access_rights": {
            "action": True,
            "mode": "access",
            "requirements": list(requirements),
            "raw": 1,
        },
    }


class CapabilityComparisonTests(unittest.TestCase):
    def test_all_operations_and_access_requirements_are_compared(self):
        public = snapshot(
            "public",
            [
                object_record(
                    64,
                    "0.0.43.0.0.255",
                    attributes=(
                        attribute(2, read=True),
                        attribute(3, write=True),
                    ),
                ),
                object_record(1, "0.0.96.1.0.255", attributes=(attribute(2, read=True),)),
            ],
        )
        secure = snapshot(
            "client4",
            [
                object_record(
                    64,
                    "0.0.43.0.0.255",
                    attributes=(
                        attribute(2, read=True, requirements=("encrypted_request",)),
                    ),
                    methods=(method(2, requirements=("authenticated_request",)),),
                ),
                object_record(18, "0.0.44.0.0.255", attributes=(attribute(5, read=True),)),
            ],
        )
        role_report = {
            "public_union_test": {
                "results": [
                    {
                        "class_id": 18,
                        "logical_name": "0.0.44.0.0.255",
                        "attribute_id": 5,
                        "attempt_count": 1,
                        "outcome": "SUCCESS",
                        "access_assessment": "UNEXPECTED_PUBLIC_ACCESS",
                    }
                ]
            }
        }

        result = compare_role_capabilities(public, secure, role_report=role_report)
        rows = {
            (item["operation"], item["class_id"], item["member_id"]): item
            for item in result["capabilities"]
        }
        self.assertEqual(rows[("GET", 64, 2)]["classification"], "public_broader")
        self.assertEqual(rows[("SET", 64, 3)]["classification"], "public_only")
        self.assertEqual(rows[("ACTION", 64, 2)]["classification"], "authenticated_only")
        self.assertEqual(rows[("GET", 18, 5)]["classification"], "authenticated_only")
        self.assertEqual(
            rows[("GET", 18, 5)]["public_get_verification"]["assessment"],
            "UNEXPECTED_PUBLIC_ACCESS",
        )
        self.assertEqual(result["object_presence"]["shared"], 1)
        self.assertEqual(len(result["object_presence"]["only_public"]), 1)
        self.assertEqual(len(result["object_presence"]["only_authenticated"]), 1)

    def test_workflow_and_markdown_include_each_authenticated_role(self):
        public = snapshot(
            "public",
            [object_record(1, "0.0.42.0.0.255", attributes=(attribute(2, read=True),))],
        )
        secure = snapshot(
            "client4",
            [object_record(1, "0.0.42.0.0.255", attributes=(attribute(2, read=True),))],
        )
        report = build_workflow_comparison(public, [(secure, None)])
        markdown = render_comparison_markdown(report)
        self.assertEqual(report["comparisons"][0]["authenticated_role"], "client4")
        self.assertIn("Public versus `client4`", markdown)
        self.assertIn("| GET |", markdown)

    def test_markdown_omits_authenticated_only_detail_but_json_model_keeps_it(self):
        public = snapshot("public", [])
        secure = snapshot(
            "client4",
            [
                object_record(
                    18,
                    "0.0.44.0.0.255",
                    attributes=(attribute(5, read=True),),
                )
            ],
        )
        report = build_workflow_comparison(public, [(secure, None)])

        markdown = render_comparison_markdown(report)

        self.assertEqual(len(report["comparisons"][0]["capabilities"]), 1)
        self.assertIn("1 authenticated-only rows are omitted", markdown)
        self.assertNotIn("0.0.44.0.0.255", markdown)


if __name__ == "__main__":
    unittest.main()
