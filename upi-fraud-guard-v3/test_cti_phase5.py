"""
Automated Integration & Unit Test Suite for Phase 5: Continuous ML Pipeline & Model Registry.

Tests:
- Quality-controlled dataset preparation and splitting
- Candidate model training (RandomForest, GradientBoosting, LogisticRegression)
- Metric evaluation (Precision, Recall, F1, ROC-AUC, PR-AUC, Confusion Matrix)
- Model Registry CRUD and approval status transitions
- Controlled deployment workflow (Pending Approval -> Approved -> Deployed)
- Model version rollback workflow
- Model registry REST API endpoints
"""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from fastapi.testclient import TestClient

from api.main import app
from cti_database import CTIDatabase
from cti_ml_pipeline import CandidateModelEvaluator, DatasetPreparer, ModelRegistryManager


class TestCTIPhase5MLPipeline(unittest.TestCase):

    def setUp(self) -> None:
        self.client = TestClient(app)
        self.temp_db_file = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self.temp_db_file.close()
        self.db = CTIDatabase(db_path=Path(self.temp_db_file.name))
        self.preparer = DatasetPreparer()
        self.evaluator = CandidateModelEvaluator()
        self.registry = ModelRegistryManager()

    def tearDown(self) -> None:
        try:
            os.unlink(self.temp_db_file.name)
        except Exception:
            pass

    # 1. Dataset Preparation Test
    def test_01_dataset_preparation(self) -> None:
        dataset = self.preparer.prepare_dataset(version="v1.1.0")
        self.assertEqual(dataset["version"], "v1.1.0")
        self.assertEqual(len(dataset["X_train"]) + len(dataset["X_test"]), dataset["total_samples"])
        self.assertGreater(dataset["positive_count"], 0)
        self.assertGreater(dataset["negative_count"], 0)
        self.assertFalse(dataset["temporal_evaluation"])
        self.assertTrue(dataset["dataset_sha256"])

    # 2. Candidate Model Training & Evaluation Test
    def test_02_candidate_model_training(self) -> None:
        res = self.evaluator.train_and_evaluate(algorithm="RandomForest", dataset_version="v1.1.0")
        self.assertIn("model_id", res)
        self.assertEqual(res["approval_status"], "Pending Approval")
        self.assertIn("metrics", res)
        self.assertIn("precision", res["metrics"])
        self.assertIn("recall", res["metrics"])
        self.assertIn("f1_score", res["metrics"])

    # 3. Model Registry & Approval Workflow Test
    def test_03_model_approval_and_deployment_workflow(self) -> None:
        res = self.evaluator.train_and_evaluate(algorithm="GradientBoosting", dataset_version="v1.1.0")
        model_id = res["model_id"]

        # 1. Check initial status is Pending Approval
        model_info = self.registry.get_model(model_id)
        self.assertIsNotNone(model_info)
        self.assertEqual(model_info["approval_status"], "Pending Approval")

        # 2. Deploy directly should fail (must be Approved first)
        deploy_fail = self.registry.deploy_model(model_id)
        self.assertFalse(deploy_fail)

        # 3. Approve model
        approved = self.registry.approve_model(model_id)
        self.assertTrue(approved)
        model_info_app = self.registry.get_model(model_id)
        self.assertEqual(model_info_app["approval_status"], "Approved")

        # 4. Deploy approved model
        # Processed project data has no trustworthy timestamp, so deployment is fail-closed.
        deployed = self.registry.deploy_model(model_id)
        self.assertFalse(deployed)
        model_info_dep = self.registry.get_model(model_id)
        self.assertEqual(model_info_dep["approval_status"], "Approved")
        self.assertEqual(model_info_dep["is_active"], 0)

    # 4. Model Version Rollback Test
    def test_04_model_version_rollback(self) -> None:
        # Train model 1 and deploy
        res1 = self.evaluator.train_and_evaluate(algorithm="RandomForest", dataset_version="v1.1.0", version_tag="v1.0")
        self.registry.approve_model(res1["model_id"])
        self.assertFalse(self.registry.deploy_model(res1["model_id"]))

        # Train model 2 and deploy
        res2 = self.evaluator.train_and_evaluate(algorithm="LogisticRegression", dataset_version="v1.1.0", version_tag="v2.0")
        self.registry.approve_model(res2["model_id"])
        self.assertFalse(self.registry.deploy_model(res2["model_id"]))
        self.assertFalse(self.registry.rollback_model(res2["model_id"]))

    # 5. Model Registry REST API Test
    def test_05_model_registry_api(self) -> None:
        # Train model via API endpoint
        train_res = self.client.post("/api/intelligence/models/train", json={"algorithm": "RandomForest", "dataset_version": "v1.1.0"})
        self.assertEqual(train_res.status_code, 200)
        model_id = train_res.json()["candidate"]["model_id"]

        # List models
        models_res = self.client.get("/api/intelligence/models")
        self.assertEqual(models_res.status_code, 200)
        self.assertIsInstance(models_res.json(), list)

        # Get evaluations
        eval_res = self.client.get("/api/intelligence/models/evaluations")
        self.assertEqual(eval_res.status_code, 200)

        # Approve model via API
        app_res = self.client.post(f"/api/intelligence/models/{model_id}/approve")
        self.assertEqual(app_res.status_code, 200)

        # Deployment must be rejected until a timestamped temporal evaluation exists.
        dep_res = self.client.post(f"/api/intelligence/models/{model_id}/deploy")
        self.assertEqual(dep_res.status_code, 422)

        roll_res = self.client.post(f"/api/intelligence/models/{model_id}/rollback")
        self.assertEqual(roll_res.status_code, 422)


if __name__ == "__main__":
    unittest.main()
