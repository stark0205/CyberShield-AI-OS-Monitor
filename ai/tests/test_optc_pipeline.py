import csv
import json
import tempfile
import unittest
from pathlib import Path

from ai.prepare_optc import prepare_dataset
from ai.generate_demo_dataset import generate_dataset
from ai.train_optc_model import train_model
from backend.ai import classifier as risk_classifier


class OptcPipelineTests(unittest.TestCase):
    def test_synthetic_demo_dataset_is_balanced_and_reproducible(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            first_output = root / "first.csv"
            second_output = root / "second.csv"

            generate_dataset(first_output, rows_per_class=5, seed=7)
            generate_dataset(second_output, rows_per_class=5, seed=7)

            self.assertEqual(first_output.read_bytes(), second_output.read_bytes())
            with first_output.open(newline="", encoding="utf-8") as csv_file:
                counts = {}
                for row in csv.DictReader(csv_file):
                    counts[row["risk_lvl"]] = counts.get(row["risk_lvl"], 0) + 1
                    self.assertEqual(row["data_origin"], "synthetic_scenario")
            self.assertEqual(counts, {"Normal": 5, "Suspicious": 5, "High Risk": 5})

    def test_prepare_and_train_labeled_subset(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            events_path = root / "events.jsonl"
            labels_path = root / "labels.csv"
            dataset_path = root / "prepared.csv"
            model_path = root / "model.pkl"
            records = []
            labels = []

            for host_number in range(4):
                for index, risk_level in enumerate(("Normal", "High Risk")):
                    event_id = f"{host_number}-{index}"
                    records.append(
                        {
                            "id": event_id,
                            "hostname": f"host-{host_number}",
                            "object": "PROCESS",
                            "action": "CREATE",
                            "ppid": 1,
                            "properties": {
                                "image_path": (
                                    "C:\\Windows\\System32\\svchost.exe"
                                    if risk_level == "Normal"
                                    else "C:\\Users\\Public\\ransom.exe"
                                )
                            },
                        }
                    )
                    labels.append({"id": event_id, "risk_lvl": risk_level})

            events_path.write_text(
                "".join(json.dumps(record) + "\n" for record in records),
                encoding="utf-8",
            )
            with labels_path.open("w", newline="", encoding="utf-8") as csv_file:
                writer = csv.DictWriter(csv_file, fieldnames=["id", "risk_lvl"])
                writer.writeheader()
                writer.writerows(labels)

            counts = prepare_dataset(events_path, labels_path, dataset_path)
            self.assertEqual(counts["Normal"], 4)
            self.assertEqual(counts["High Risk"], 4)

            artifact = train_model(dataset_path, model_path)
            self.assertEqual(artifact["source"], "DARPA OpTC eCAR labeled subset")
            self.assertEqual(set(artifact["classes"]), {"Normal", "High Risk"})
            self.assertTrue(model_path.is_file())

            original_path = risk_classifier.OPTC_MODEL_PATH
            original_model = risk_classifier._model
            try:
                risk_classifier.OPTC_MODEL_PATH = model_path
                risk_classifier._model = None
                prediction, confidence = risk_classifier.predict_risk(
                    0,
                    0,
                    "new_proc",
                    exe_name=r"C:\Windows\System32\svchost.exe",
                    ppid=1,
                )
                self.assertIn(prediction, artifact["classes"])
                self.assertGreaterEqual(confidence, 0)
                self.assertLessEqual(confidence, 1)
            finally:
                risk_classifier.OPTC_MODEL_PATH = original_path
                risk_classifier._model = original_model


if __name__ == "__main__":
    unittest.main()
