"""Real-data transaction model candidate training and audited activation registry."""
from __future__ import annotations

import hashlib
import json
import logging
import uuid
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import joblib
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import auc, confusion_matrix, f1_score, precision_recall_curve, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit

from cti_database import cti_db
from transaction_module.transaction_features import extract_features, FEATURE_NAMES

logger = logging.getLogger("upi_fraud_guard.cti_ml_pipeline")
_BASE_DIR = Path(__file__).resolve().parent
_MODELS_DIR = _BASE_DIR / "models"
_CANDIDATES_DIR = _MODELS_DIR / "candidates"
_DATASET = _BASE_DIR / "data" / "transactions_dataset.csv"

def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

class DatasetPreparer:
    """Loads the bundled, labelled PaySim-derived rows in the live transaction feature schema."""
    def prepare_dataset(self, version: str = "paysim-processed-v1") -> Dict[str, Any]:
        if not _DATASET.is_file():
            raise FileNotFoundError(f"Required labelled project dataset is missing: {_DATASET}")
        frame = pd.read_csv(_DATASET)
        required = {"amount","is_new_recipient","payments_last_hour","hour_of_day","target"}
        if not required.issubset(frame.columns):
            raise ValueError(f"Dataset is missing required columns: {sorted(required - set(frame.columns))}")
        if frame.empty or frame["target"].nunique() != 2:
            raise ValueError("Dataset must contain labelled examples for both classes")
        features = frame.apply(
            lambda row: extract_features(row["amount"], row["is_new_recipient"], row["payments_last_hour"], row["hour_of_day"]),
            axis=1,
        ).apply(pd.Series)[FEATURE_NAMES]
        labels = frame["target"].astype(int)
        # Prevent exact duplicate feature rows crossing the validation boundary.
        groups = pd.util.hash_pandas_object(features, index=False).astype(str)
        split = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=42)
        train_idx, test_idx = next(split.split(features, labels, groups))
        return {
            "version": version, "dataset_path": str(_DATASET), "dataset_sha256": _sha256(_DATASET),
            "total_samples": int(len(frame)), "positive_count": int(labels.sum()),
            "negative_count": int((labels == 0).sum()), "features": list(FEATURE_NAMES),
            "evaluation_mode": "grouped_random_holdout", "temporal_evaluation": False,
            "X_train": features.iloc[train_idx], "X_test": features.iloc[test_idx],
            "y_train": labels.iloc[train_idx], "y_test": labels.iloc[test_idx],
        }

class CandidateModelEvaluator:
    def train_and_evaluate(self, algorithm: str="RandomForest", dataset_version: str="paysim-processed-v1",
                           version_tag: Optional[str]=None) -> Dict[str, Any]:
        data = DatasetPreparer().prepare_dataset(dataset_version)
        constructors = {
            "RandomForest": lambda: RandomForestClassifier(n_estimators=200,max_depth=8,class_weight="balanced",random_state=42,n_jobs=1),
            "GradientBoosting": lambda: GradientBoostingClassifier(n_estimators=100,random_state=42),
            "LogisticRegression": lambda: LogisticRegression(class_weight="balanced",random_state=42,max_iter=1000),
        }
        if algorithm not in constructors:
            raise ValueError(f"Unsupported algorithm '{algorithm}'")
        model = constructors[algorithm]()
        model.fit(data["X_train"], data["y_train"])
        pred = model.predict(data["X_test"])
        proba = model.predict_proba(data["X_test"])[:,1]
        tn,fp,fn,tp = confusion_matrix(data["y_test"],pred,labels=[0,1]).ravel()
        precision=precision_score(data["y_test"],pred,zero_division=0)
        recall=recall_score(data["y_test"],pred,zero_division=0)
        p_curve,r_curve,_=precision_recall_curve(data["y_test"],proba)
        metrics={
            "precision":round(float(precision),4),"recall":round(float(recall),4),
            "f1_score":round(float(f1_score(data["y_test"],pred,zero_division=0)),4),
            "roc_auc":round(float(roc_auc_score(data["y_test"],proba)),4),
            "pr_auc":round(float(auc(r_curve,p_curve)),4),
            "false_positive_rate":round(float(fp/(fp+tn)),4) if fp+tn else 0,
            "false_negative_rate":round(float(fn/(fn+tp)),4) if fn+tp else 0,
            "confusion_matrix":{"tn":int(tn),"fp":int(fp),"fn":int(fn),"tp":int(tp)},
            "evaluation_mode":data["evaluation_mode"],"evaluation_samples":int(len(data["y_test"])),
        }
        _CANDIDATES_DIR.mkdir(parents=True,exist_ok=True)
        version=version_tag or f"v{datetime.now(timezone.utc):%Y%m%d%H%M%S}-{uuid.uuid4().hex[:6]}"
        model_id=f"MODEL-TRANSACTION-{version}"
        artifact=_CANDIDATES_DIR/f"{model_id}.joblib"
        joblib.dump(model,artifact)
        checksum=_sha256(artifact)
        config={"algorithm":algorithm,"artifact_location":str(artifact),"sha256":checksum,
                "feature_schema":list(FEATURE_NAMES),"dataset_path":str(_DATASET),
                "dataset_sha256":data["dataset_sha256"],"dataset_rows":data["total_samples"],
                "positive_count":data["positive_count"],"negative_count":data["negative_count"],
                "evaluation_mode":data["evaluation_mode"],"temporal_evaluation":False,
                "deployment_eligible":False}
        self._register(model_id,version,dataset_version,config,metrics)
        return {"model_id":model_id,"version":version,"algorithm":algorithm,"dataset_version":dataset_version,
                "metrics":metrics,"approval_status":"Pending Approval","artifact_location":str(artifact),
                "sha256":checksum,"deployment_eligible":False,
                "limitation":"The bundled processed dataset has no trustworthy timestamp; temporal evaluation is unavailable."}

    @staticmethod
    def _register(model_id,version,dataset_version,config,metrics):
        with closing(cti_db._get_connection()) as conn:
            conn.execute("""INSERT INTO cti_model_registry
                (model_id,model_name,version,trained_at,dataset_version,training_config,metrics,approval_status,is_active)
                VALUES (?,?,?,?,?,?,?,'Pending Approval',0)
                ON CONFLICT(version) DO UPDATE SET
                    model_id=excluded.model_id,
                    trained_at=excluded.trained_at,
                    dataset_version=excluded.dataset_version,
                    training_config=excluded.training_config,
                    metrics=excluded.metrics,
                    approval_status='Pending Approval',
                    is_active=0""",
                (model_id,"Transaction Candidate",version,datetime.now(timezone.utc).isoformat(),
                 dataset_version,json.dumps(config),json.dumps(metrics)))
            conn.execute("INSERT INTO cti_model_audit(model_id,actor,action,created_at,details) VALUES(?,?,?,?,?)",
                (model_id,"training-service","trained",datetime.now(timezone.utc).isoformat(),json.dumps({"dataset_sha256":config["dataset_sha256"]})))
            conn.commit()

class ModelRegistryManager:
    def list_models(self):
        with closing(cti_db._get_connection()) as conn:
            rows=conn.execute("SELECT * FROM cti_model_registry ORDER BY trained_at DESC").fetchall()
            cols=[c[1] for c in conn.execute("PRAGMA table_info(cti_model_registry)")]
            out=[]
            for row in rows:
                item=dict(zip(cols,row)); item["training_config"]=json.loads(item["training_config"]); item["metrics"]=json.loads(item["metrics"]); out.append(item)
            return out
    def get_model(self,model_id):
        return next((m for m in self.list_models() if m["model_id"]==model_id),None)
    def _audit(self,conn,model_id,actor,action,details=None):
        conn.execute("INSERT INTO cti_model_audit(model_id,actor,action,created_at,details) VALUES(?,?,?,?,?)",
                     (model_id,actor,action,datetime.now(timezone.utc).isoformat(),json.dumps(details or {})))
    def approve_model(self,model_id,actor="local-system"):
        with closing(cti_db._get_connection()) as conn:
            cur=conn.execute("UPDATE cti_model_registry SET approval_status='Approved' WHERE model_id=? AND approval_status='Pending Approval'",(model_id,))
            if cur.rowcount:
                self._audit(conn,model_id,actor,"approved")
            conn.commit()
            return cur.rowcount>0
    def deploy_model(self,model_id,actor="local-system"):
        info=self.get_model(model_id)
        if not info or info["approval_status"]!="Approved":
            return False
        config=info["training_config"]
        if not config.get("temporal_evaluation") or not config.get("deployment_eligible"):
            logger.warning("Refusing model deployment: candidate lacks eligible temporal evaluation.")
            return False
        from transaction_module.analyzer import activate_runtime_model, get_active_model_state
        artifact=Path(config.get("artifact_location","")).resolve()
        if not artifact.is_file() or _sha256(artifact)!=config.get("sha256"):
            return False
        if config.get("feature_schema")!=list(FEATURE_NAMES):
            return False
        previous=get_active_model_state()
        if not activate_runtime_model(artifact,config["sha256"]):
            return False
        try:
            with closing(cti_db._get_connection()) as conn:
                conn.execute("UPDATE cti_model_registry SET is_active=0,approval_status='Approved' WHERE is_active=1")
                conn.execute("UPDATE cti_model_registry SET is_active=1,approval_status='Deployed' WHERE model_id=?",(model_id,))
                conn.execute("""INSERT INTO cti_model_deployments(model_id,actor,deployed_at,action,previous_model_id,
                    previous_artifact,previous_checksum,artifact,checksum) VALUES(?,?,?,?,?,?,?,?,?)""",
                    (model_id,actor,datetime.now(timezone.utc).isoformat(),"deploy",previous.get("model_id"),
                     previous["artifact"],previous["sha256"],str(artifact),config["sha256"]))
                self._audit(conn,model_id,actor,"deployed",{"previous":previous})
                conn.commit()
        except Exception:
            activate_runtime_model(Path(previous["artifact"]),previous["sha256"])
            raise
        return True
    def rollback_model(self,model_id,actor="local-system"):
        info=self.get_model(model_id)
        if not info or not info.get("is_active"):
            return False
        with closing(cti_db._get_connection()) as conn:
            row=conn.execute("""SELECT previous_model_id,previous_artifact,previous_checksum
                FROM cti_model_deployments WHERE model_id=? AND action='deploy'
                ORDER BY deployment_id DESC LIMIT 1""",(model_id,)).fetchone()
        if not row:
            return False
        previous_id,previous_artifact,previous_checksum=row
        from transaction_module.analyzer import activate_runtime_model
        if not activate_runtime_model(Path(previous_artifact),previous_checksum):
            return False
        with closing(cti_db._get_connection()) as conn:
            conn.execute("UPDATE cti_model_registry SET is_active=0,approval_status='Rolled Back' WHERE model_id=?",(model_id,))
            if previous_id:
                conn.execute("UPDATE cti_model_registry SET is_active=1,approval_status='Deployed' WHERE model_id=?",(previous_id,))
            conn.execute("""INSERT INTO cti_model_deployments(model_id,actor,deployed_at,action,previous_model_id,
                previous_artifact,previous_checksum,artifact,checksum) VALUES(?,?,?,?,?,?,?,?,?)""",
                (model_id,actor,datetime.now(timezone.utc).isoformat(),"rollback",previous_id,
                 previous_artifact,previous_checksum,previous_artifact,previous_checksum))
            self._audit(conn,model_id,actor,"rolled_back",{"restored_model_id":previous_id})
            conn.commit()
        return True

cti_evaluator=CandidateModelEvaluator()
cti_registry=ModelRegistryManager()
