import os
import json
import pickle
import pandas as pd
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse
from sklearn.preprocessing import LabelEncoder, StandardScaler
import xgboost as xgb
import uvicorn
import os
import json
from datetime import datetime
from typing import Dict, Any, List
from fastapi import FastAPI, UploadFile, File, HTTPException, Body
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
from dataclasses import dataclass
from typing import Dict, Any, Tuple, Optional
import numpy as np
import torch
import torch.nn as nn
# Neo4j and LangChain imports
from neo4j import GraphDatabase
from langchain_neo4j import GraphCypherQAChain, Neo4jGraph
from langchain_openai import ChatOpenAI

# Load environment variables
load_dotenv()
import json
import re
import math
from datetime import datetime
from typing import Dict, Any, List
from fastapi import UploadFile, File, HTTPException
from fastapi.responses import JSONResponse

app = FastAPI(title="Alert Classifier API", version="1.0")

import json
import re
import math
from datetime import datetime
from typing import Dict, Any, List

# ----------------- GNN defaults -----------------
DEFAULT_GNN_CKPT = os.getenv("RGCN_CKPT", "models/rgcn_nodgl.pt")
try:
    DEFAULT_GNN_HOPS = int(os.getenv("RGCN_HOPS", "5"))
except Exception:
    DEFAULT_GNN_HOPS = 5
    
class BaseAgent:
    def __init__(self, role: str, tools: List[str]):
        self.role = role
        self.tools = tools
        self.context = {}
        
class ScoringTool:
    """Tool for scoring alerts based on heuristic rules and VirusTotal data"""
    
    EVIL_PATH_REGEX = re.compile(
        r'(\\AppData\\|\\Downloads\\|\\Users\\Public|\\Windows\\[^\\]+\\|\$Recycle\.Bin)',
        re.I
    )
    
    LOLBINS = {
        "powershell.exe", "pwsh.exe", "cmd.exe", "wmic.exe", "regsvr32.exe",
        "mshta.exe", "python.exe", "wscript.exe", "cscript.exe", "rundll32.exe",
        "curl.exe", "wget.exe"
    }
    
    SUSP_ARGS_RE = re.compile(r'(-enc\b|FromBase64String|Invoke-Expression|curl\s+http)', re.I)
    
    ENGINE_WEIGHTS = {
        "SentinelOne Cloud": 25,
        "on-write static ai": 15,
        "user": 10,
        "behavioral": 5
    }
    
    ASSET_WEIGHTS = {
        "server": 15,
        "laptop": 5
    }
    
    CONF_WEIGHTS = {
        "malicious": 10,
        "suspicious": 5
    }

    @classmethod
    def weight_engine(cls, name: str) -> int:
        if not name:
            return 0
        low = name.strip().lower()
        for key, w in cls.ENGINE_WEIGHTS.items():
            if key.lower() == low:
                return w
        return 0

    @classmethod
    def flatten_alert(cls, raw: Any, parent_key: str = "") -> Dict[str, Any]:
        """
        Recursively flattens dicts/lists into dotted keys and list indices:
        e.g. {"enrichments":[{"data":{"positives":5}}]}
             => {"enrichments[0].data.positives": 5}
        """
        flat: Dict[str, Any] = {}
        # Root type guard
        if parent_key == "" and not isinstance(raw, (dict, list)):
            print(f"WARNING: Alert data is not a dict/list, type: {type(raw)}")
            return flat

        if isinstance(raw, dict):
            if parent_key == "":
                print(f"DEBUG: flatten_alert - received {len(raw)} top-level keys")
            for k, v in raw.items():
                nk = f"{parent_key}.{k}" if parent_key else k
                flat.update(cls.flatten_alert(v, nk))
        elif isinstance(raw, list):
            for i, v in enumerate(raw):
                nk = f"{parent_key}[{i}]"
                flat.update(cls.flatten_alert(v, nk))
        else:
            flat[parent_key] = raw

        return flat
    @classmethod
    def score_agent1(cls, flat: Dict[str, Any]) -> Dict[str, dict]:
        """Agent1: Heuristic-based scoring"""
        scores = {}
        
        print("=== AGENT1 SCORING START ===")
        print(f"Available keys: {list(flat.keys())}")

        # 1. Severity scoring
        sev = int(flat.get("severity_id", 0))
        scores["severity"] = {
            "value": sev,
            "risk_score": sev * 10,
            "description": f"Severity level {sev}"
        }
        print(f"Severity: {sev} -> score: {sev * 10}")

        # 2. File signing verification
        fv = (flat.get("file.verification.type") or "").lower()
        vc = bool(flat.get("file.signature.certificate.status", False))
        
        if fv == "notsigned":
            scores["file_signing"] = {
                "value": fv,
                "risk_score": 25,
                "description": "File is not signed"
            }
            print(f"File signing: {fv} -> score: 25")
        elif fv == "signed" and not vc:
            scores["file_signing"] = {
                "value": "signed/invalid",
                "risk_score": 15,
                "description": "File signed but certificate is invalid"
            }
            print(f"File signing: signed/invalid -> score: 15")
        elif fv == "signed" and vc:
            scores["file_signing"] = {
                "value": "signed/valid",
                "risk_score": -10,
                "description": "File properly signed with valid certificate"
            }
            print(f"File signing: signed/valid -> score: -10")

        # 3. Suspicious file path
        fp = flat.get("file.path", "")
        if cls.EVIL_PATH_REGEX.search(fp):
            scores["file_path"] = {
                "value": fp,
                "risk_score": 15,
                "description": "File located in suspicious directory"
            }
            print(f"Suspicious file path: {fp} -> score: 15")

        # 4. Parent process (LOLBins)
        parent = (flat.get("process.name") or "").lower()
        if any(bin_name in parent for bin_name in cls.LOLBINS):
            scores["parent_process"] = {
                "value": parent,
                "risk_score": 20,
                "description": "Parent process is a known LOLBin"
            }
            print(f"LOLBin parent process: {parent} -> score: 20")

        # 5. Command line patterns
        cli = flat.get("process.cmd.args") 
        if cls.SUSP_ARGS_RE.search(cli):
            scores["command_line"] = {
                "value": cli,
                "risk_score": 15,
                "description": "Contains suspicious command line patterns"
            }
            print(f"Suspicious command line -> score: 15")

        # 6. Threat confidence
        conf = (flat.get("threat.confidence") or "").lower()
        risk_score = cls.CONF_WEIGHTS.get(conf, -20)
        scores["confidence_level"] = {
            "value": conf,
            "risk_score": risk_score,
            "description": f"Vendor confidence: {conf}"
        }
        print(f"Threat confidence: {conf} -> score: {risk_score}")

        # 7. Detection engine
        engs = flat.get("metadata.product.feature.name") or []
        e_name = "unknown"
        if engs and isinstance(engs, list) and len(engs) > 0:
            if isinstance(engs[0], dict) and "title" in engs[0]:
                e_name = engs[0]["title"]
        
        engine_score = cls.weight_engine(e_name)
        scores["detection_engine"] = {
            "value": e_name,
            "risk_score": engine_score,
            "description": f"Detected by: {e_name}"
        }
        print(f"Detection engine: {e_name} -> score: {engine_score}")

        # 8. Asset type
        asset = (flat.get("device.type") or "").lower()
        asset_score = cls.ASSET_WEIGHTS.get(asset, 0)
        scores["asset_type"] = {
            "value": asset,
            "risk_score": asset_score,
            "description": f"Asset type: {asset}"
        }
        print(f"Asset type: {asset} -> score: {asset_score}")

        # 9. Process user privileges
        process_user = flat.get("actor.process.user.name", "")
        if process_user.lower() in ["system", "administrator", "root"]:
            scores["process_user"] = {
                "value": process_user,
                "risk_score": 10,
                "description": "Process running with elevated privileges"
            }
            print(f"Elevated process user: {process_user} -> score: 10")
        elif process_user:
            scores["process_user"] = {
                "value": process_user,
                "risk_score": 0,
                "description": "Process running with normal user privileges"
            }
            print(f"Normal process user: {process_user} -> score: 0")

        agent1_total = sum(score_data.get("risk_score", 0) for score_data in scores.values())
        print(f"=== AGENT1 TOTAL SCORE: {agent1_total} ===")
        return scores

    @classmethod
    def score_agent2(cls, flat: Dict[str, Any]) -> Dict[str, dict]:
        """Agent2: VirusTotal-based scoring using enrichment data structure"""
        scores = {}
        
        print("=== AGENT2 SCORING START ===")
        print(f"Checking VirusTotal enrichment data...")
        
        # Debug: Print all enrichment-related keys

        # Debug: Print all enrichment-related keys
        enrichment_keys = [k for k in flat.keys() if 'enrichments' in k or 'data.' in k]
        print(f"Found enrichment keys: {enrichment_keys}")

        # Dynamically locate VirusTotal enrichment without hard-coding an index
        import re
        buckets: Dict[int, Dict[str, Any]] = {}
        pat = re.compile(r'^enrichments\[(\d+)\]\.data\.(.+)$')
        for k, v in flat.items():
            m = pat.match(k)
            if not m:
                continue
            idx = int(m.group(1))
            subkey = m.group(2)  # e.g., "positives", "stats.malicious"
            buckets.setdefault(idx, {})[subkey] = v

        vt_values: Dict[str, Any] = {}
        if buckets:
            def _to_int(x):
                try:
                    return int(x)
                except Exception:
                    return 0

            def _vt_signal(d: Dict[str, Any]) -> int:
                return (
                    _to_int(d.get("positives", 0)) +
                    _to_int(d.get("malicious", 0)) +
                    _to_int(d.get("suspicious", 0)) +
                    _to_int(d.get("stats.malicious", 0)) +
                    _to_int(d.get("stats.suspicious", 0))
                )

            chosen = max(buckets.values(), key=_vt_signal)
            print(f"Chosen VT enrichment bucket keys: {list(chosen.keys())}")

            # Normalize chosen bucket keys into vt_values expected by downstream scoring
            key_map = {
                "positives": "positives",
                "total": "total",
                "malicious": "malicious",
                "suspicious": "suspicious",
                "stats.malicious": "stats_malicious",
                "stats.suspicious": "stats_suspicious",
                "stats.undetected": "stats_undetected",
                "stats.harmless": "stats_harmless",
                "stats.unsupported": "stats_unsupported",
                "stats.timeout": "stats_timeout",
                "stats.confirmed-timeout": "stats_confirmed_timeout",
                "stats.failure": "stats_failure",
                "scan_time": "scan_time",
            }
            for key, alias in key_map.items():
                raw_value = chosen.get(key)
                if raw_value is None:
                    continue
                if alias == "scan_time":
                    vt_values[alias] = str(raw_value)
                else:
                    try:
                        vt_values[alias] = int(raw_value)
                    except (ValueError, TypeError):
                        vt_values[alias] = 0
        else:
            # Initialize defaults if no enrichments present
            for alias in [
                "positives","total","malicious","suspicious",
                "stats_malicious","stats_suspicious","stats_undetected",
                "stats_harmless","stats_unsupported","stats_timeout",
                "stats_confirmed_timeout","stats_failure"
            ]:
                vt_values[alias] = 0
            vt_values["scan_time"] = None

        print(f"Extracted VT values: {vt_values}")


        # 1. VirusTotal positive detections
        positives = vt_values.get("positives", 0)
        if positives > 0:
            risk_score = min(10 * math.log2(positives + 1), 40)
            scores["vt_positives"] = {
                "value": positives,
                "risk_score": risk_score,
                "description": f"VirusTotal positive detections: {positives}"
            }
            print(f"VT Positives: {positives} -> score: {risk_score}")

        # 2. Total engines analyzed
        total = vt_values.get("total", 0)
        if total > 0 and positives > 0:
            detection_ratio = positives / total
            risk_score = min(50 * detection_ratio, 50)
            scores["vt_detection_ratio"] = {
                "value": f"{positives}/{total}",
                "risk_score": risk_score,
                "description": f"VirusTotal detection ratio: {positives}/{total} ({detection_ratio:.2%})"
            }
            print(f"VT Detection Ratio: {positives}/{total} -> score: {risk_score}")

        # 3. Malicious verdict count
        malicious = vt_values.get("malicious", 0)
        if malicious > 0:
            risk_score = min(15 * math.log2(malicious + 1), 45)
            scores["vt_malicious"] = {
                "value": malicious,
                "risk_score": risk_score,
                "description": f"VirusTotal malicious verdicts: {malicious}"
            }
            print(f"VT Malicious: {malicious} -> score: {risk_score}")

        # 4. Suspicious verdict count
        suspicious = vt_values.get("suspicious", 0)
        if suspicious > 0:
            risk_score = min(8 * math.log2(suspicious + 1), 25)
            scores["vt_suspicious"] = {
                "value": suspicious,
                "risk_score": risk_score,
                "description": f"VirusTotal suspicious verdicts: {suspicious}"
            }
            print(f"VT Suspicious: {suspicious} -> score: {risk_score}")

        # 5. Analysis stats - malicious
        stats_malicious = vt_values.get("stats_malicious", 0)
        if stats_malicious > 0:
            risk_score = min(12 * math.log2(stats_malicious + 1), 35)
            scores["vt_stats_malicious"] = {
                "value": stats_malicious,
                "risk_score": risk_score,
                "description": f"VirusTotal analysis stats - malicious: {stats_malicious}"
            }
            print(f"VT Stats Malicious: {stats_malicious} -> score: {risk_score}")

        # 6. Analysis stats - suspicious
        stats_suspicious = vt_values.get("stats_suspicious", 0)
        if stats_suspicious > 0:
            risk_score = min(6 * math.log2(stats_suspicious + 1), 20)
            scores["vt_stats_suspicious"] = {
                "value": stats_suspicious,
                "risk_score": risk_score,
                "description": f"VirusTotal analysis stats - suspicious: {stats_suspicious}"
            }
            print(f"VT Stats Suspicious: {stats_suspicious} -> score: {risk_score}")

        # 7. Analysis stats - harmless (reduces risk)
        stats_harmless = vt_values.get("stats_harmless", 0)
        if stats_harmless > 0:
            risk_score = -min(2 * math.log2(stats_harmless + 1), 10)
            scores["vt_stats_harmless"] = {
                "value": stats_harmless,
                "risk_score": risk_score,
                "description": f"VirusTotal analysis stats - harmless: {stats_harmless}"
            }
            print(f"VT Stats Harmless: {stats_harmless} -> score: {risk_score}")

        # 8. Analysis stats - timeout (indicates potential evasion)
        stats_timeout = vt_values.get("stats_timeout", 0)
        if stats_timeout > 0:
            risk_score = min(5 * math.log2(stats_timeout + 1), 15)
            scores["vt_stats_timeout"] = {
                "value": stats_timeout,
                "risk_score": risk_score,
                "description": f"VirusTotal analysis stats - timeout: {stats_timeout}"
            }
            print(f"VT Stats Timeout: {stats_timeout} -> score: {risk_score}")

        # 9. Analysis stats - confirmed timeout
        stats_confirmed_timeout = vt_values.get("stats_confirmed_timeout", 0)
        if stats_confirmed_timeout > 0:
            risk_score = min(8 * math.log2(stats_confirmed_timeout + 1), 20)
            scores["vt_stats_confirmed_timeout"] = {
                "value": stats_confirmed_timeout,
                "risk_score": risk_score,
                "description": f"VirusTotal analysis stats - confirmed timeout: {stats_confirmed_timeout}"
            }
            print(f"VT Stats Confirmed Timeout: {stats_confirmed_timeout} -> score: {risk_score}")

        # 10. Analysis stats - failure
        stats_failure = vt_values.get("stats_failure", 0)
        if stats_failure > 0:
            risk_score = min(4 * math.log2(stats_failure + 1), 12)
            scores["vt_stats_failure"] = {
                "value": stats_failure,
                "risk_score": risk_score,
                "description": f"VirusTotal analysis stats - failure: {stats_failure}"
            }
            print(f"VT Stats Failure: {stats_failure} -> score: {risk_score}")

        # 11. Scan age analysis
        scan_time = vt_values.get("scan_time")
        if scan_time:
            try:
                if isinstance(scan_time, str):
                    scan_timestamp = int(datetime.fromisoformat(scan_time.replace('Z', '+00:00')).timestamp())
                else:
                    scan_timestamp = int(scan_time)
                
                import time
                current_timestamp = int(time.time())
                days_old = (current_timestamp - scan_timestamp) / (24 * 3600)
                
                if days_old > 90:
                    risk_score = min(days_old / 30, 10)
                    scores["vt_scan_age"] = {
                        "value": f"{days_old:.0f} days old",
                        "risk_score": risk_score,
                        "description": f"VirusTotal scan is {days_old:.0f} days old"
                    }
                    print(f"VT Scan Age: {days_old:.0f} days -> score: {risk_score}")
            except (ValueError, TypeError) as e:
                print(f"Error processing scan time: {e}")

        # 12. High detection count bonus
        total_detections = positives + malicious + suspicious + stats_malicious + stats_suspicious
        if total_detections > 10:
            scores["vt_high_detection_count"] = {
                "value": total_detections,
                "risk_score": 30,
                "description": f"High total detection count across all VirusTotal metrics: {total_detections}"
            }
            print(f"VT High Detection Count: {total_detections} -> score: 30")

        agent2_total = sum(score_data.get("risk_score", 0) for score_data in scores.values())
        print(f"=== AGENT2 TOTAL SCORE: {agent2_total} ===")
        print(f"=== AGENT2 SCORES CREATED: {list(scores.keys())} ===")
        
        return scores

class TriageAgent(BaseAgent):
    """Agent specialized in initial alert triage and risk scoring"""
    
    def __init__(self):
        super().__init__(
            role="Alert Triage Specialist - Performs comprehensive risk assessment using heuristic analysis (Agent1) and VirusTotal enrichment (Agent2)",
            tools=["ScoringTool"]
        )
        self.scoring_tool = ScoringTool()

    def analyze_alert(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze alert using both Agent1 (heuristic) and Agent2 (VirusTotal) scoring"""
        
        print("=" * 60)
        print("STARTING TRIAGE ANALYSIS")
        print("=" * 60)
        
        # Flatten and validate data
        flat_data = self.scoring_tool.flatten_alert(alert_data)
        
        if not flat_data:
            print("ERROR: No valid alert data received")
            return {
                "error": "No valid alert data provided",
                "timestamp": datetime.utcnow().isoformat()
            }
        
        print(f"Processing alert with {len(flat_data)} fields")
        
        # Run both scoring agents
        print("\n" + "="*40 + " AGENT1 " + "="*40)
        agent1_scores = self.scoring_tool.score_agent1(flat_data)
        
        print("\n" + "="*40 + " AGENT2 " + "="*40)
        agent2_scores = self.scoring_tool.score_agent2(flat_data)
        
        # Calculate totals
        agent1_total = sum(attr_data.get("risk_score", 0) for attr_data in agent1_scores.values())
        agent2_total = sum(attr_data.get("risk_score", 0) for attr_data in agent2_scores.values())
        
        print(f"\n" + "="*40 + " FINAL CALCULATION " + "="*40)
        print(f"Agent1 Raw Total: {agent1_total}")
        print(f"Agent2 Raw Total: {agent2_total}")
        
        # Apply weightings: 40% Agent1, 60% Agent2
        weighted_agent1 = agent1_total * 0.4
        weighted_agent2 = agent2_total * 0.6
        total_weighted_score = weighted_agent1 + weighted_agent2
        
        print(f"Agent1 Weighted (40%): {weighted_agent1}")
        print(f"Agent2 Weighted (60%): {weighted_agent2}")
        print(f"Total Weighted Score: {total_weighted_score}")
        
        # Normalize score to 0-100
        normalized_score = max(0, min(total_weighted_score, 100))
        confidence = normalized_score / 100.0
        
        # Determine verdict based on risk score thresholds
        if normalized_score >= 80:
            verdict = "True Positive"
        elif normalized_score >= 25:
            verdict = "Escalate"
        else:
            verdict = "False Positive"
        
        print(f"Normalized Score: {normalized_score}")
        print(f"Final Verdict: {verdict}")
        print(f"Risk Score: {confidence * 100}")
        
        # Combine all attribute analyses
        all_attributes = {}
        all_attributes.update(agent1_scores)
        all_attributes.update(agent2_scores)
        
        result = {
            "prediction": {
                "predicted_verdict": verdict,
                "risk_score": confidence * 100
            },
            "metadata": {
                "total_risk_score": normalized_score,
                "agent1_score": {
                    "raw_score": agent1_total,
                    "weighted_score": weighted_agent1,
                    "weight_percentage": 40,
                    "attributes": agent1_scores
                },
                "agent2_score": {
                    "raw_score": agent2_total,
                    "weighted_score": weighted_agent2,
                    "weight_percentage": 60,
                    "attributes": agent2_scores
                },
                "combined_attribute_analysis": all_attributes,
                "scoring_breakdown": {
                    "agent1_contribution": f"{weighted_agent1:.2f} points (40% weight)",
                    "agent2_contribution": f"{weighted_agent2:.2f} points (60% weight)",
                    "total_weighted": f"{total_weighted_score:.2f} points"
                },
                "agent_role": self.role,
                "tools_used": self.tools
            },
            "timestamp": datetime.utcnow().isoformat(),
            "model_version": "1.0"
        }
        
        print("=" * 60)
        print("TRIAGE ANALYSIS COMPLETE")
        print("=" * 60)
        
        return result
    
triage_agent = TriageAgent()
@app.post("/triage")
async def triage_alert(file: UploadFile = File(...)):
    """
    Upload a JSON alert file and get triage analysis with risk scoring.
    """
    global triage_agent
    try:
        if not file.filename.endswith(".json"):
            raise HTTPException(status_code=400, detail="Only JSON files are supported.")

        # Read and parse JSON
        content = await file.read()
        try:
            alert_data = json.loads(content.decode("utf-8"))
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="Invalid JSON format.")

        # TEST: Verify new code is loaded
        print("=== CODE VERSION CHECK ===")
        print("New scoring code loaded successfully!")
        
        # Run triage analysis using the agent
        results = triage_agent.analyze_alert(alert_data)

        return JSONResponse(content=results)

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
                               
class AlertClassifier:
    def __init__(self, model_folder="./models-50"):
        self.model_folder = model_folder
        self.model = None
        self.label_encoders = {}
        self.scaler = None
        self.feature_names = []

    def load_model(self):
        """Load model and preprocessing artifacts"""
        try:
            model_path = os.path.join(self.model_folder, 'xgb_alert_classifier.pkl')
            with open(model_path, 'rb') as f:
                self.model = pickle.load(f)

            encoders_path = os.path.join(self.model_folder, 'label_encoders.pkl')
            with open(encoders_path, 'rb') as f:
                self.label_encoders = pickle.load(f)

            scaler_path = os.path.join(self.model_folder, 'scaler.pkl')
            with open(scaler_path, 'rb') as f:
                self.scaler = pickle.load(f)

            features_path = os.path.join(self.model_folder, 'feature_names.pkl')
            with open(features_path, 'rb') as f:
                self.feature_names = pickle.load(f)

            print("✅ Model and preprocessing components loaded successfully")
            return True
        except Exception as e:
            print(f"❌ Error loading model: {e}")
            return False

    def predict(self, input_data):
        """Make predictions on new alert JSON data with metadata included"""
        if self.model is None:
            raise RuntimeError("Model not loaded!")

        if isinstance(input_data, dict):
            df = pd.DataFrame([input_data])
        elif isinstance(input_data, list):
            df = pd.DataFrame(input_data)
        else:
            raise ValueError("Input must be dict or list of dicts")

        df = df.fillna('unknown')
        for feature in self.feature_names:
            if feature not in df.columns:
                df[feature] = 'unknown'
        df_features = df[self.feature_names].copy() 
        for col in df_features.columns:
            if col in self.label_encoders and col != 'target':
                le = self.label_encoders[col]

                if df_features[col].dtype == bool:
                    df_features[col] = df_features[col].to_numpy(dtype="int64")

                elif pd.api.types.is_numeric_dtype(df_features[col]):
                    continue
                else:
                    df_features.loc[:, col] = df_features[col].astype(str)
                    mask = df_features[col].isin(le.classes_)
                    df_features.loc[~mask, col] = 'unknown'

                    if 'unknown' not in le.classes_:
                        df_features.loc[~mask, col] = le.classes_[0]

                    df_features.loc[:, col] = le.transform(df_features[col])

        # Scale features
        X_scaled = self.scaler.transform(df_features)

        # Predict
        predictions = self.model.predict(X_scaled)
        probabilities = self.model.predict_proba(X_scaled)

        target_le = self.label_encoders['target']
        predicted_labels = target_le.inverse_transform(predictions)

        results = []
        for i, (pred_label, probs) in enumerate(zip(predicted_labels, probabilities)):
            # feature importance * input values = contribution
            feature_importance = self.model.feature_importances_
            contributions = {
                feat: {
                    "value": float(X_scaled[i][idx]),
                    "importance_weight": float(feature_importance[idx]),
                    "contribution_score": float(feature_importance[idx] * abs(X_scaled[i][idx]))
                }
                for idx, feat in enumerate(self.feature_names)
            }

            # sort contributions
            sorted_features = sorted(
                contributions.items(),
                key=lambda x: x[1]["contribution_score"],
                reverse=True
            )
            top_features = dict(sorted_features[:5])

            results.append({
                "prediction": {
                    "predicted_verdict": pred_label,
                    "confidence": float(max(probs)),
                    "probabilities": {
                        target_le.classes_[j]: float(probs[j]) for j in range(len(target_le.classes_))
                    }
                },
                "metadata": {
                    "top_contributing_features": top_features,
                    "all_features": contributions
                }
            })

        return results if len(results) > 1 else results[0]





classifier = AlertClassifier()
if not classifier.load_model():
    raise RuntimeError("Failed to load model. Train the model first and save artifacts.")

@app.post("/predict")
async def predict_alert(file: UploadFile = File(...)):
    """
    Upload a JSON alert file and get prediction results.
    """
    try:
        if not file.filename.endswith(".json"):
            raise HTTPException(status_code=400, detail="Only JSON files are supported.")

        # Read and parse JSON
        content = await file.read()
        try:
            data = json.loads(content.decode("utf-8"))
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="Invalid JSON format.")

        # Run prediction
        results = classifier.predict(data)

        return JSONResponse(content=results)

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



# Configuration from .env
NEO4J_URI = os.getenv("NEO4J_URI")
NEO4J_USERNAME = os.getenv("NEO4J_USERNAME") 
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")
NEO4J_DATABASE = os.getenv("NEO4J_DATABASE", "neo4j")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

neo4j_driver = None
try:
    if all([NEO4J_URI, NEO4J_USERNAME, NEO4J_PASSWORD]):
        neo4j_driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USERNAME, NEO4J_PASSWORD))
        neo4j_driver.verify_connectivity()
        print("Neo4j connection established successfully")
    else:
        print("Missing Neo4j environment variables")
except Exception as e:
    print(f"Failed to connect to Neo4j: {e}")
    neo4j_driver = None

class Neo4jGraphManager:
    """Manages Neo4j graph operations for alert data following OCSF mapping"""
    
    def __init__(self, driver):
        self.driver = driver
        self.database = NEO4J_DATABASE
        
    def create_alert_graph(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create comprehensive alert graph following EXACT 18 nodes + 20 relationships specification"""
        
        print("Creating alert knowledge graph in Neo4j following strict schema...")
        
        # Create unique alert ID
        alert_id = alert_data.get('alert', {}).get('id', f"alert_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        
        with self.driver.session(database=self.database) as session:
            try:
                # Reset counters for this alert
                self.nodes_created = {}
                self.relationships_created = []
                
                # Create constraints and indexes first
                print("🔧 Creating constraints and indexes...")
                self.create_constraints_and_indexes()
                
                # CREATE NODES (18 total as per specification)
                self._create_node_1_alert(session, alert_data)
                self._create_node_19_scores(session, alert_data)
                self._create_node_2_file(session, alert_data)
                self._create_node_3_hash_sha256(session, alert_data)
                self._create_node_4_hash_sha1(session, alert_data)
                self._create_node_5_process(session, alert_data)
                self._create_node_6_user(session, alert_data)
                self._create_node_7_host(session, alert_data)
                self._create_node_8_network_interface(session, alert_data)
                self._create_node_9_external_ip(session, alert_data)
                self._create_node_10_threat_intel_checkpoint(session, alert_data)
                self._create_node_11_threat_intel_virustotal(session, alert_data)
                self._create_node_12_mitigation_action(session, alert_data)
                self._create_node_13_engine_merged(session, alert_data)
                self._create_node_14_site(session, alert_data)
                self._create_node_15_group(session, alert_data)
                self._create_node_16_incident(session, alert_data)
                self._create_node_17_os_version(session, alert_data)
                self._create_node_18_whitening_rule(session, alert_data)
                
                # CREATE RELATIONSHIPS (20 total as per specification)
                self._create_rel_1_alert_refers_to_file(session, alert_data)
                self._create_rel_2_file_has_hash_sha256(session, alert_data)
                self._create_rel_3_file_has_hash_sha1(session, alert_data)
                self._create_rel_4_alert_triggered_by(session, alert_data)
                self._create_rel_5_process_executed_by(session, alert_data)
                self._create_rel_6_process_on_host(session, alert_data)
                self._create_rel_7_file_resides_on(session, alert_data)
                self._create_rel_8_hash_enriched_by_ti_cp(session, alert_data)
                self._create_rel_9_hash_enriched_by_ti_vt(session, alert_data)
                self._create_rel_10_host_connects_to(session, alert_data)
                self._create_rel_11_alert_mitigated_via(session, alert_data)
                self._create_rel_12_action_applied_on(session, alert_data)
                self._create_rel_13_alert_detected_by(session, alert_data)
                self._create_rel_14_alert_belongs_to_site(session, alert_data)
                self._create_rel_15_host_in_group(session, alert_data)
                self._create_rel_16_host_has_interface(session, alert_data)
                self._create_rel_17_alert_in_incident(session, alert_data)
                self._create_rel_18_host_has_os(session, alert_data)
                self._create_rel_19_alert_whitelisted_by(session, alert_data)
                self._create_rel_20_alert_has_score(session, alert_data)
                
                result = {
                    "success": True,
                    "graph_created": True,
                    "alert_id": alert_id,
                    "nodes_created": sum(self.nodes_created.values()),
                    "relationships_created": len(self.relationships_created),
                    "node_breakdown": self.nodes_created,
                    "timestamp": datetime.now().isoformat()
                }
                
                print(f"Graph created successfully: {sum(self.nodes_created.values())} nodes, {len(self.relationships_created)} relationships")
                return result
                
            except Exception as e:
                print(f"Error creating graph: {e}")
                raise e
    
    
    # ==================== NODE CREATION METHODS (18 nodes) ====================
    
    def _create_node_1_alert(self, session, data):
        """1. Alert — key: threat.id"""
        query = """
        MERGE (a:Alert {threat_id: $threat_id})
        SET a.time = $time,
            a.detected_time = $detected_time,
            a.alert_id = $alert_id,
            a.name = $name,
            a.classification = $classification,
            a.confidence = $confidence,
            a.verdict = $verdict,
            a.incident_status = $incident_status,
            a.remediation_status = $remediation_status
        """
        session.run(query,
            threat_id=data['threat']['id'],
            alert_id=data['alert']['id'],
            time=data['time'],
            detected_time=data['threat']['detected_time'],
            name=data['threat']['name'],
            classification=data['threat']['classification'],
            confidence=data['threat']['confidence'],
            verdict=data['threat']['verdict'],
            incident_status=data['incident']['status'],
            remediation_status=data['remediation']['status']
        )
        self.nodes_created['Alert'] = self.nodes_created.get('Alert', 0) + 1

    def _create_node_19_scores(self, session, data):
        """19. Scores — stores ML/GNN/Rule scores for the alert"""
        query = """
        MERGE (s:Scores {alert_id: $alert_id})
        SET s.ml_score_fp = $ml_score_fp,
            s.gnn_score_fp = $gnn_score_fp,
            s.rule_score_fp = $rule_score_fp
        """
        session.run(query,
            alert_id=data['alert']['id'],
            ml_score_fp=data['ml_score'].get('False Positive'),
            gnn_score_fp=data['gnn_score'].get('False Positive'),
            rule_score_fp=data['rule_base_score'].get('False Positive')
        )
        self.nodes_created['Scores'] = self.nodes_created.get('Scores', 0) + 1

    def _create_node_2_file(self, session, data):
        """2. File — key: file.uid"""
        query = """
        MERGE (f:File {uid: $uid})
        SET f.path = $path,
            f.extension = $extension,
            f.size = $size,
            f.verification_type = $verification_type,
            f.certificate_status = $certificate_status,
            f.certificate_issuer = $certificate_issuer,
            f.reputation_score = $reputation_score
        """
        session.run(query,
            uid=data['file']['uid'],
            path=data['file']['path'],
            extension=data['file']['extension'],
            size=data['file']['size'],
            verification_type=data['file']['verification']['type'],
            certificate_status=data['file']['signature']['certificate']['status'],
            certificate_issuer=data['file']['signature']['certificate']['issuer'],
            reputation_score=data['file']['reputation']['score']
        )
        self.nodes_created['File'] = self.nodes_created.get('File', 0) + 1
    
    def _create_node_3_hash_sha256(self, session, data):
        """3. Hash (sha256) — key: file.hashes.sha256"""
        if data['file']['hashes'].get('sha256'):
            query = """
            MERGE (h:Hash {algorithm: 'sha256', value: $value})
            """
            session.run(query, value=data['file']['hashes']['sha256'])
            self.nodes_created['Hash(SHA256)'] = self.nodes_created.get('Hash(SHA256)', 0) + 1
    
    def _create_node_4_hash_sha1(self, session, data):
        """4. Hash (sha1) — key: file.hashes.sha1"""
        if data['file']['hashes'].get('sha1'):
            query = """
            MERGE (h:Hash {algorithm: 'sha1', value: $value})
            """
            session.run(query, value=data['file']['hashes']['sha1'])
            self.nodes_created['Hash(SHA1)'] = self.nodes_created.get('Hash(SHA1)', 0) + 1
    
    def _create_node_5_process(self, session, data):
        """5. Process — key: (threat.id, process.name)"""
        query = """
        MERGE (p:Process {threat_id: $threat_id, name: $name})
        SET p.cmd_args = $cmd_args,
            p.isFileless = $isFileless,
            p.detection_type = $detection_type
        """
        session.run(query,
            threat_id=data['threat']['id'],
            name=data['process']['name'],
            cmd_args=data['process']['cmd']['args'],
            isFileless=data['process']['isFileless'],
            detection_type=data['threat']['detection']['type']
        )
        self.nodes_created['Process'] = self.nodes_created.get('Process', 0) + 1
    
    def _create_node_6_user(self, session, data):
        """6. User — key: actor.process.user.name"""
        if data['actor']['process']['user']['name']:
            query = """
            MERGE (u:User {name: $name})
            SET u.domain = $domain
            """
            session.run(query,
                name=data['actor']['process']['user']['name'],
                domain=data['actor']['process']['user']['domain']
            )
            self.nodes_created['User'] = self.nodes_created.get('User', 0) + 1
    
    def _create_node_7_host(self, session, data):
        """7. Host — key: device.uuid"""
        query = """
        MERGE (h:Host {uuid: $uuid})
        SET h.hostname = $hostname,
            h.domain = $domain,
            h.ipv4_addresses = $ipv4_addresses,
            h.network_status = $network_status,
            h.is_active = $is_active
        """
        session.run(query,
            uuid=data['device']['uuid'],
            hostname=data['device']['hostname'],
            domain=data['device']['domain'],
            ipv4_addresses=data['device']['ipv4_addresses'],
            network_status=data['device']['network']['status'],
            is_active=data['device']['is_active']
        )
        self.nodes_created['Host'] = self.nodes_created.get('Host', 0) + 1
    
    def _create_node_8_network_interface(self, session, data):
        """8. NetworkInterface — key: (device.uuid, device.interface.mac)"""
        interface = data['device']['interface']
        query = """
        MERGE (n:NetworkInterface {device_uuid: $device_uuid, mac: $mac})
        SET n.name = $name,
            n.ip = $ip
        """
        session.run(query,
            device_uuid=data['device']['uuid'],
            mac=interface['mac'],
            name=interface['name'],
            ip=interface['ip']
        )
        self.nodes_created['NetworkInterface'] = self.nodes_created.get('NetworkInterface', 0) + 1
    
    def _create_node_9_external_ip(self, session, data):
        """9. ExternalIP — key: device.interface.ip"""
        query = """
        MERGE (e:ExternalIP {ip: $ip})
        """
        session.run(query, ip=data['device']['interface']['ip'])
        self.nodes_created['ExternalIP'] = self.nodes_created.get('ExternalIP', 0) + 1
    
    def _create_node_10_threat_intel_checkpoint(self, session, data):
        """10. ThreatIntel (Check Point) — key: enrichments[0].data.resource"""
        if 'enrichments' in data and len(data['enrichments']) > 0:
            cp_data = data['enrichments'][0]['data']
            if 'resource' in cp_data:
                query = """
                MERGE (t:ThreatIntel {resource: $resource, provider: 'Check Point'})
                SET t.classification = $classification,
                    t.confidence = $confidence,
                    t.severity = $severity,
                    t.risk_score = $risk_score,
                    t.name = $name,
                    t.type = $type,
                    t.size = $size,
                    t.first_seen_time = $first_seen_time,
                    t.positives = $positives,
                    t.total = $total
                """
                session.run(query,
                    resource=cp_data['resource'],
                    classification=cp_data.get('classification'),
                    confidence=cp_data.get('confidence'),
                    severity=cp_data.get('severity'),
                    risk_score=cp_data.get('risk_score'),
                    name=cp_data.get('name'),
                    type=cp_data.get('type'),
                    size=cp_data.get('size'),
                    first_seen_time=cp_data.get('first_seen_time'),
                    positives=cp_data.get('positives'),
                    total=cp_data.get('total')
                )
                self.nodes_created['ThreatIntel(CheckPoint)'] = self.nodes_created.get('ThreatIntel(CheckPoint)', 0) + 1
    
    def _create_node_11_threat_intel_virustotal(self, session, data):
        """11. ThreatIntel (VirusTotal) — key: ("VirusTotal", enrichments[1].data.total, enrichments[1].data.positives)"""
        if 'enrichments' in data and len(data['enrichments']) > 1:
            vt_data = data['enrichments'][1]['data']
            composite_key = f"VirusTotal_{vt_data.get('total', 0)}_{vt_data.get('positives', 0)}"
            query = """
            MERGE (t:ThreatIntel {composite_key: $composite_key, provider: 'VirusTotal'})
            SET t.positives = $positives,
                t.total = $total,
                t.malicious = $malicious,
                t.suspicious = $suspicious,
                t.scan_time = $scan_time,
                t.stats_malicious = $stats_malicious,
                t.stats_suspicious = $stats_suspicious,
                t.stats_undetected = $stats_undetected,
                t.stats_harmless = $stats_harmless,
                t.stats_unsupported = $stats_unsupported,
                t.stats_timeout = $stats_timeout,
                t.stats_confirmed_timeout = $stats_confirmed_timeout,
                t.stats_failure = $stats_failure
            """
            stats = vt_data.get('stats', {})
            session.run(query,
                composite_key=composite_key,
                positives=vt_data.get('positives'),
                total=vt_data.get('total'),
                malicious=vt_data.get('malicious'),
                suspicious=vt_data.get('suspicious'),
                scan_time=vt_data.get('scan_time'),
                stats_malicious=stats.get('malicious'),
                stats_suspicious=stats.get('suspicious'),
                stats_undetected=stats.get('undetected'),
                stats_harmless=stats.get('harmless'),
                stats_unsupported=stats.get('unsupported'),
                stats_timeout=stats.get('timeout'),
                stats_confirmed_timeout=stats.get('confirmed-timeout'),
                stats_failure=stats.get('failure')
            )
            self.nodes_created['ThreatIntel(VirusTotal)'] = self.nodes_created.get('ThreatIntel(VirusTotal)', 0) + 1
    
    def _create_node_12_mitigation_action(self, session, data):
        """12. MitigationAction — key: remediation.uid"""
        query = """
        MERGE (m:MitigationAction {uid: $uid})
        SET m.status = $status,
            m.desc = $desc,
            m.start_time = $start_time,
            m.end_time = $end_time,
            m.result = $result
        """
        session.run(query,
            uid=data['remediation']['uid'],
            status=data['remediation']['status'],
            desc=data['remediation']['desc'],
            start_time=data['remediation']['start_time'],
            end_time=data['remediation']['end_time'],
            result=data['remediation']['result']
        )
        self.nodes_created['MitigationAction'] = self.nodes_created.get('MitigationAction', 0) + 1
    
    def _create_node_13_engine_merged(self, session, data):
        """13. Engine (merged) — key (uid): pre_execution|On-Write Static AI|On-Write DFI|agent_policy"""
        metadata = data['metadata']['product']
        engine_names = [metadata['feature']['name']] + metadata['name']
        engine_uid = '|'.join(engine_names)
        
        query = """
        MERGE (e:Engine {uid: $uid})
        SET e.name = $name,
            e.version = $version,
            e.names = $names,
            e.detection_type = $detection_type
        """
        session.run(query,
            uid=engine_uid,
            name=metadata['feature']['name'],
            version=metadata['feature']['version'],
            names=engine_names,
            detection_type=data['threat']['detection']['type']
        )
        self.nodes_created['Engine'] = self.nodes_created.get('Engine', 0) + 1
    
    def _create_node_14_site(self, session, data):
        """14. Site — key: device.location.uid"""
        location = data['device']['location']
        query = """
        MERGE (s:Site {uid: $uid})
        SET s.desc = $desc
        """
        session.run(query,
            uid=location['uid'],
            desc=location['desc']
        )
        self.nodes_created['Site'] = self.nodes_created.get('Site', 0) + 1
    
    def _create_node_15_group(self, session, data):
        """15. Group — key: device.groups[0].uid"""
        if data['device']['groups']:
            group = data['device']['groups'][0]
            query = """
            MERGE (g:Group {uid: $uid})
            SET g.name = $name
            """
            session.run(query,
                uid=group['uid'],
                name=group['name']
            )
            self.nodes_created['Group'] = self.nodes_created.get('Group', 0) + 1
    
    def _create_node_16_incident(self, session, data):
        """16. Incident — key: INC-{threat.id} (synthetic)"""
        incident_id = f"INC-{data['threat']['id']}"
        query = """
        MERGE (i:Incident {incident_id: $incident_id})
        SET i.status = $status,
            i.desc = $desc
        """
        session.run(query,
            incident_id=incident_id,
            status=data['incident']['status'],
            desc=data['incident']['desc']
        )
        self.nodes_created['Incident'] = self.nodes_created.get('Incident', 0) + 1
    
    def _create_node_17_os_version(self, session, data):
        """17. OsVersion — key: (device.os.name, device.os.build)"""
        os_info = data['device']['os']
        query = """
        MERGE (o:OsVersion {name: $name, build: $build})
        SET o.type = $type
        """
        session.run(query,
            name=os_info['name'],
            build=os_info['build'],
            type=os_info['type']
        )
        self.nodes_created['OsVersion'] = self.nodes_created.get('OsVersion', 0) + 1
    
    def _create_node_18_whitening_rule(self, session, data):
        """18. WhiteningRule — key: remediation.result"""
        query = """
        MERGE (w:WhiteningRule {rule: $rule})
        """
        session.run(query, rule=data['remediation']['result'])
        self.nodes_created['WhiteningRule'] = self.nodes_created.get('WhiteningRule', 0) + 1
    
    # ==================== RELATIONSHIP CREATION METHODS (20 relationships) ====================
    
    def _create_rel_1_alert_refers_to_file(self, session, data):
        """1. ALERT_REFERS_TO_FILE — Alert → File edge props: created_at = time"""
        query = """
        MATCH (a:Alert {threat_id: $threat_id}), (f:File {uid: $file_uid})
        MERGE (a)-[r:ALERT_REFERS_TO_FILE]->(f)
        SET r.created_at = $created_at
        """
        session.run(query,
            threat_id=data['threat']['id'],
            file_uid=data['file']['uid'],
            created_at=data['time']
        )
        self.relationships_created.append('ALERT_REFERS_TO_FILE')
    
    def _create_rel_2_file_has_hash_sha256(self, session, data):
        """2. FILE_HAS_HASH — File → Hash(sha256)"""
        if data['file']['hashes'].get('sha256'):
            query = """
            MATCH (f:File {uid: $file_uid}), (h:Hash {algorithm: 'sha256', value: $hash_value})
            MERGE (f)-[:FILE_HAS_HASH]->(h)
            """
            session.run(query,
                file_uid=data['file']['uid'],
                hash_value=data['file']['hashes']['sha256']
            )
            self.relationships_created.append('FILE_HAS_HASH(SHA256)')
    
    def _create_rel_3_file_has_hash_sha1(self, session, data):
        """3. FILE_HAS_HASH — File → Hash(sha1)"""
        if data['file']['hashes'].get('sha1'):
            query = """
            MATCH (f:File {uid: $file_uid}), (h:Hash {algorithm: 'sha1', value: $hash_value})
            MERGE (f)-[:FILE_HAS_HASH]->(h)
            """
            session.run(query,
                file_uid=data['file']['uid'],
                hash_value=data['file']['hashes']['sha1']
            )
            self.relationships_created.append('FILE_HAS_HASH(SHA1)')
    
    def _create_rel_4_alert_triggered_by(self, session, data):
        """4. ALERT_TRIGGERED_BY — Alert → Process edge props: detection_type, initiated_by"""
        query = """
        MATCH (a:Alert {threat_id: $threat_id}), (p:Process {threat_id: $threat_id, name: $process_name})
        MERGE (a)-[r:ALERT_TRIGGERED_BY]->(p)
        SET r.detection_type = $detection_type,
            r.initiated_by = 'agent_policy'
        """
        session.run(query,
            threat_id=data['threat']['id'],
            process_name=data['process']['name'],
            detection_type=data['threat']['detection']['type']
        )
        self.relationships_created.append('ALERT_TRIGGERED_BY')
    
    def _create_rel_5_process_executed_by(self, session, data):
        """5. PROCESS_EXECUTED_BY — Process → User"""
        if data['actor']['process']['user']['name']:
            query = """
            MATCH (p:Process {threat_id: $threat_id, name: $process_name}), (u:User {name: $user_name})
            MERGE (p)-[:PROCESS_EXECUTED_BY]->(u)
            """
            session.run(query,
                threat_id=data['threat']['id'],
                process_name=data['process']['name'],
                user_name=data['actor']['process']['user']['name']
            )
            self.relationships_created.append('PROCESS_EXECUTED_BY')
    
    def _create_rel_6_process_on_host(self, session, data):
        """6. PROCESS_ON_HOST — Process → Host"""
        query = """
        MATCH (p:Process {threat_id: $threat_id, name: $process_name}), (h:Host {uuid: $host_uuid})
        MERGE (p)-[:PROCESS_ON_HOST]->(h)
        """
        session.run(query,
            threat_id=data['threat']['id'],
            process_name=data['process']['name'],
            host_uuid=data['device']['uuid']
        )
        self.relationships_created.append('PROCESS_ON_HOST')
    
    def _create_rel_7_file_resides_on(self, session, data):
        """7. FILE_RESIDES_ON — File → Host"""
        query = """
        MATCH (f:File {uid: $file_uid}), (h:Host {uuid: $host_uuid})
        MERGE (f)-[:FILE_RESIDES_ON]->(h)
        """
        session.run(query,
            file_uid=data['file']['uid'],
            host_uuid=data['device']['uuid']
        )
        self.relationships_created.append('FILE_RESIDES_ON')
    
    def _create_rel_8_hash_enriched_by_ti_cp(self, session, data):
        """8. HASH_ENRICHED_BY_TI — Hash(sha256) → TI (Check Point)"""
        if (data['file']['hashes'].get('sha256') and 
            'enrichments' in data and len(data['enrichments']) > 0 and 
            'resource' in data['enrichments'][0]['data']):
            query = """
            MATCH (h:Hash {algorithm: 'sha256', value: $hash_value}), 
                  (t:ThreatIntel {resource: $resource, provider: 'Check Point'})
            MERGE (h)-[:HASH_ENRICHED_BY_TI]->(t)
            """
            session.run(query,
                hash_value=data['file']['hashes']['sha256'],
                resource=data['enrichments'][0]['data']['resource']
            )
            self.relationships_created.append('HASH_ENRICHED_BY_TI(CheckPoint)')
    
    def _create_rel_9_hash_enriched_by_ti_vt(self, session, data):
        """9. HASH_ENRICHED_BY_TI — Hash(sha256) → TI (VirusTotal)"""
        if (data['file']['hashes'].get('sha256') and 
            'enrichments' in data and len(data['enrichments']) > 1):
            vt_data = data['enrichments'][1]['data']
            composite_key = f"VirusTotal_{vt_data.get('total', 0)}_{vt_data.get('positives', 0)}"
            query = """
            MATCH (h:Hash {algorithm: 'sha256', value: $hash_value}), 
                  (t:ThreatIntel {composite_key: $composite_key, provider: 'VirusTotal'})
            MERGE (h)-[:HASH_ENRICHED_BY_TI]->(t)
            """
            session.run(query,
                hash_value=data['file']['hashes']['sha256'],
                composite_key=composite_key
            )
            self.relationships_created.append('HASH_ENRICHED_BY_TI(VirusTotal)')
    
    def _create_rel_10_host_connects_to(self, session, data):
        """10. HOST_CONNECTS_TO — Host → ExternalIP edge props: vantage = "egress" """
        query = """
        MATCH (h:Host {uuid: $host_uuid}), (e:ExternalIP {ip: $external_ip})
        MERGE (h)-[r:HOST_CONNECTS_TO]->(e)
        SET r.vantage = 'egress'
        """
        session.run(query,
            host_uuid=data['device']['uuid'],
            external_ip=data['device']['interface']['ip']
        )
        self.relationships_created.append('HOST_CONNECTS_TO')
    
    def _create_rel_11_alert_mitigated_via(self, session, data):
        """11. ALERT_MITIGATED_VIA — Alert → MitigationAction"""
        query = """
        MATCH (a:Alert {threat_id: $threat_id}), (m:MitigationAction {uid: $mitigation_uid})
        MERGE (a)-[:ALERT_MITIGATED_VIA]->(m)
        """
        session.run(query,
            threat_id=data['threat']['id'],
            mitigation_uid=data['remediation']['uid']
        )
        self.relationships_created.append('ALERT_MITIGATED_VIA')
    
    def _create_rel_12_action_applied_on(self, session, data):
        """12. ACTION_APPLIED_ON — MitigationAction → Host"""
        query = """
        MATCH (m:MitigationAction {uid: $mitigation_uid}), (h:Host {uuid: $host_uuid})
        MERGE (m)-[:ACTION_APPLIED_ON]->(h)
        """
        session.run(query,
            mitigation_uid=data['remediation']['uid'],
            host_uuid=data['device']['uuid']
        )
        self.relationships_created.append('ACTION_APPLIED_ON')
    
    def _create_rel_13_alert_detected_by(self, session, data):
        """13. ALERT_DETECTED_BY — Alert → Engine (merged)"""
        metadata = data['metadata']['product']
        engine_names = [metadata['feature']['name']] + metadata['name']
        engine_uid = '|'.join(engine_names)
        
        query = """
        MATCH (a:Alert {threat_id: $threat_id}), (e:Engine {uid: $engine_uid})
        MERGE (a)-[:ALERT_DETECTED_BY]->(e)
        """
        session.run(query,
            threat_id=data['threat']['id'],
            engine_uid=engine_uid
        )
        self.relationships_created.append('ALERT_DETECTED_BY')
    
    def _create_rel_14_alert_belongs_to_site(self, session, data):
        """14. ALERT_BELONGS_TO_SITE — Alert → Site"""
        query = """
        MATCH (a:Alert {threat_id: $threat_id}), (s:Site {uid: $site_uid})
        MERGE (a)-[:ALERT_BELONGS_TO_SITE]->(s)
        """
        session.run(query,
            threat_id=data['threat']['id'],
            site_uid=data['device']['location']['uid']
        )
        self.relationships_created.append('ALERT_BELONGS_TO_SITE')
    
    def _create_rel_15_host_in_group(self, session, data):
        """15. HOST_IN_GROUP — Host → Group"""
        if data['device']['groups']:
            query = """
            MATCH (h:Host {uuid: $host_uuid}), (g:Group {uid: $group_uid})
            MERGE (h)-[:HOST_IN_GROUP]->(g)
            """
            session.run(query,
                host_uuid=data['device']['uuid'],
                group_uid=data['device']['groups'][0]['uid']
            )
            self.relationships_created.append('HOST_IN_GROUP')
    
    def _create_rel_16_host_has_interface(self, session, data):
        """16. HOST_HAS_INTERFACE — Host → NetworkInterface"""
        query = """
        MATCH (h:Host {uuid: $host_uuid}), 
              (n:NetworkInterface {device_uuid: $host_uuid, mac: $mac})
        MERGE (h)-[:HOST_HAS_INTERFACE]->(n)
        """
        session.run(query,
            host_uuid=data['device']['uuid'],
            mac=data['device']['interface']['mac']
        )
        self.relationships_created.append('HOST_HAS_INTERFACE')
    
    def _create_rel_17_alert_in_incident(self, session, data):
        """17. ALERT_IN_INCIDENT — Alert → Incident"""
        incident_id = f"INC-{data['threat']['id']}"
        query = """
        MATCH (a:Alert {threat_id: $threat_id}), (i:Incident {incident_id: $incident_id})
        MERGE (a)-[:ALERT_IN_INCIDENT]->(i)
        """
        session.run(query,
            threat_id=data['threat']['id'],
            incident_id=incident_id
        )
        self.relationships_created.append('ALERT_IN_INCIDENT')
    
    def _create_rel_18_host_has_os(self, session, data):
        """18. HOST_HAS_OS — Host → OsVersion"""
        query = """
        MATCH (h:Host {uuid: $host_uuid}), 
              (o:OsVersion {name: $os_name, build: $os_build})
        MERGE (h)-[:HOST_HAS_OS]->(o)
        """
        session.run(query,
            host_uuid=data['device']['uuid'],
            os_name=data['device']['os']['name'],
            os_build=data['device']['os']['build']
        )
        self.relationships_created.append('HOST_HAS_OS')
    
    def _create_rel_19_alert_whitelisted_by(self, session, data):
        """19. ALERT_WHITELISTED_BY — Alert → WhiteningRule"""
        query = """
        MATCH (a:Alert {threat_id: $threat_id}), (w:WhiteningRule {rule: $rule})
        MERGE (a)-[:ALERT_WHITELISTED_BY]->(w)
        """
        session.run(query,
            threat_id=data['threat']['id'],
            rule=data['remediation']['result']
        )
        self.relationships_created.append('ALERT_WHITELISTED_BY')
    
    def _create_rel_20_alert_has_score(self, session, data):
        """20. ALERT_HAS_SCORE — Alert → Scores"""
        query = """
        MATCH (a:Alert {threat_id: $threat_id}), (s:Scores {alert_id: $alert_id})
        MERGE (a)-[:ALERT_HAS_SCORE]->(s)
        """
        session.run(query,
            threat_id=data['threat']['id'],
            alert_id=data['alert']['id']
        )
        self.relationships_created.append('ALERT_HAS_SCORE')
    
    def create_constraints_and_indexes(self):
        """Create constraints exactly as per schema specification"""
        constraints_queries = [
            # Node constraints based on exact keys from specification
            "CREATE CONSTRAINT alert_threat_id IF NOT EXISTS FOR (a:Alert) REQUIRE a.threat_id IS UNIQUE",
            "CREATE CONSTRAINT file_uid IF NOT EXISTS FOR (f:File) REQUIRE f.uid IS UNIQUE", 
            "CREATE CONSTRAINT hash_sha256 IF NOT EXISTS FOR (h:Hash) REQUIRE (h.algorithm, h.value) IS UNIQUE",
            "CREATE CONSTRAINT user_name IF NOT EXISTS FOR (u:User) REQUIRE u.name IS UNIQUE",
            "CREATE CONSTRAINT host_uuid IF NOT EXISTS FOR (h:Host) REQUIRE h.uuid IS UNIQUE",
            "CREATE CONSTRAINT process_composite IF NOT EXISTS FOR (p:Process) REQUIRE (p.threat_id, p.name) IS UNIQUE",
            "CREATE CONSTRAINT network_interface IF NOT EXISTS FOR (n:NetworkInterface) REQUIRE (n.device_uuid, n.mac) IS UNIQUE",
            "CREATE CONSTRAINT external_ip IF NOT EXISTS FOR (e:ExternalIP) REQUIRE e.ip IS UNIQUE",
            "CREATE CONSTRAINT threat_intel_cp IF NOT EXISTS FOR (t:ThreatIntel) REQUIRE (t.resource, t.provider) IS UNIQUE",
            "CREATE CONSTRAINT threat_intel_vt IF NOT EXISTS FOR (t:ThreatIntel) REQUIRE (t.composite_key, t.provider) IS UNIQUE",
            "CREATE CONSTRAINT mitigation_uid IF NOT EXISTS FOR (m:MitigationAction) REQUIRE m.uid IS UNIQUE",
            "CREATE CONSTRAINT engine_uid IF NOT EXISTS FOR (e:Engine) REQUIRE e.uid IS UNIQUE",
            "CREATE CONSTRAINT site_uid IF NOT EXISTS FOR (s:Site) REQUIRE s.uid IS UNIQUE",
            "CREATE CONSTRAINT group_uid IF NOT EXISTS FOR (g:Group) REQUIRE g.uid IS UNIQUE",
            "CREATE CONSTRAINT incident_id IF NOT EXISTS FOR (i:Incident) REQUIRE i.incident_id IS UNIQUE",
            "CREATE CONSTRAINT os_version IF NOT EXISTS FOR (o:OsVersion) REQUIRE (o.name, o.build) IS UNIQUE",
            "CREATE CONSTRAINT whitening_rule IF NOT EXISTS FOR (w:WhiteningRule) REQUIRE w.rule IS UNIQUE",
            "CREATE CONSTRAINT scores_alert IF NOT EXISTS FOR (s:Scores) REQUIRE s.alert_id IS UNIQUE"
        ]
        
        with self.driver.session(database=self.database) as session:
            for query in constraints_queries:
                try:
                    session.run(query)
                    print(f"✅ Created constraint: {query.split('FOR')[1].split('REQUIRE')[0].strip()}")
                except Exception as e:
                    print(f"⚠️ Constraint already exists or failed: {e}")
    
    def verify_ingestion(self):
        """Verify the ingestion by counting nodes and relationships"""
        print("🔍 VERIFICATION - Counting nodes and relationships...")

        verification_queries = {
            "Alerts": "MATCH (a:Alert) RETURN COUNT(a) as count",
            "Files": "MATCH (f:File) RETURN COUNT(f) as count",
            "Hashes": "MATCH (h:Hash) RETURN COUNT(h) as count",
            "Processes": "MATCH (p:Process) RETURN COUNT(p) as count",
            "Users": "MATCH (u:User) RETURN COUNT(u) as count",
            "Hosts": "MATCH (h:Host) RETURN COUNT(h) as count",
            "NetworkInterfaces": "MATCH (n:NetworkInterface) RETURN COUNT(n) as count",
            "ExternalIPs": "MATCH (e:ExternalIP) RETURN COUNT(e) as count",
            "ThreatIntel": "MATCH (t:ThreatIntel) RETURN COUNT(t) as count",
            "MitigationActions": "MATCH (m:MitigationAction) RETURN COUNT(m) as count",
            "Engines": "MATCH (e:Engine) RETURN COUNT(e) as count",
            "Sites": "MATCH (s:Site) RETURN COUNT(s) as count",
            "Groups": "MATCH (g:Group) RETURN COUNT(g) as count",
            "Incidents": "MATCH (i:Incident) RETURN COUNT(i) as count",
            "OsVersions": "MATCH (o:OsVersion) RETURN COUNT(o) as count",
            "WhiteningRules": "MATCH (w:WhiteningRule) RETURN COUNT(w) as count",
            "Scores": "MATCH (s:Scores) RETURN COUNT(s) as count",
            "Total Relationships": "MATCH ()-[r]->() RETURN COUNT(r) as count"
        }

        with self.driver.session(database=self.database) as session:
            for entity, query in verification_queries.items():
                try:
                    result = session.run(query)
                    count = result.single()["count"]
                    print(f"   📋 {entity}: {count}")
                except Exception as e:
                    print(f"   ❌ Failed to count {entity}: {e}")


class DynamicThreatAnalyzer:
    """Dynamic analyzer using LangChain Neo4j for question generation and analysis"""

    def __init__(self):
        # Initialize LangChain components
        self.llm = ChatOpenAI(
            temperature=0,
            api_key=OPENAI_API_KEY
        )
        self.graph = Neo4jGraph(
            url=NEO4J_URI,
            username=NEO4J_USERNAME,
            password=NEO4J_PASSWORD
        )
        self.chain = GraphCypherQAChain.from_llm(
            llm=self.llm,
            graph=self.graph,
            allow_dangerous_requests=True
        )
        
        # Analyst-focused question templates
        self.analyst_questions = [
            "What is the complete attack chain visible in this alert?",
            "What are the key threat indicators that suggest malicious activity?",
            "What process execution patterns indicate suspicious behavior?", 
            "How many security vendors flagged this file and what were their detections?",
            "What file reputation and signing information is available?",
            "What network connections or communications were observed?",
            "What system privileges and user context was this executed under?",
            "What behavioral patterns match known attack techniques?",
            "How does this alert relate to known threat intelligence indicators?",
            "What is the timeline and sequence of events in this incident?",
            "What host characteristics make this target valuable to attackers?",
            "What detection engine capabilities identified this threat?"
        ]

    def analyze_alert_from_graph(self, alert_id: str) -> Dict[str, Any]:
        """Dynamically analyze alert using LangChain Neo4j chain"""
        
        print(f"Starting dynamic analysis for alert: {alert_id}")
        
        # First, get basic alert context
        context_query = f"What alert information exists for alert_id '{alert_id}'?"
        
        try:
            context_response = self.chain.run(context_query)
            print(f"Alert context: {context_response}")
        except Exception as e:
            print(f"Error getting context: {e}")
            context_response = "Alert context unavailable"
        
        # Generate dynamic questions and get answers
        qa_analysis = []
        
        for question in self.analyst_questions:
            try:
                # Modify question to be specific to this alert
                specific_question = f"For alert_id '{alert_id}': {question}"
                
                # Get answer from graph
                answer = self.chain.run(specific_question)
                
                # Analyze this Q&A pair for threat assessment
                verdict, confidence, reasoning = self._analyze_qa_for_threat(question, answer)
                
                qa_analysis.append({
                    "question": question,
                    "answer": answer,
                    "individual_verdict": verdict,
                    "individual_confidence": confidence,
                    "reasoning": reasoning
                })
                
                print(f"Q: {question[:60]}...")
                print(f"A: {answer[:100]}...")
                print(f"Verdict: {verdict} ({confidence}%)")
                print("-" * 50)
                
            except Exception as e:
                print(f"Error processing question: {question[:30]}... - {e}")
                continue
        
        # Generate final verdict from all individual assessments
        final_verdict, final_confidence, summary = self._generate_final_verdict(qa_analysis)
        
        result = {
            "success": True,
            "alert_id": alert_id,
            "analysis_method": "Dynamic LangChain Neo4j Analysis",
            "questions_analyzed": len(qa_analysis),
            "qa_analysis": qa_analysis,
            "final_verdict": final_verdict,
            "final_confidence": final_confidence,
            "summary": summary,
            "timestamp": datetime.now().isoformat()
        }
        
        return result

    def _analyze_qa_for_threat(self, question: str, answer: str) -> tuple:
        """Analyze individual Q&A pair for threat indicators"""
        
        threat_analysis_prompt = f"""
You are a cybersecurity analyst. Analyze this specific question and answer for threat indicators:

QUESTION: {question}
ANSWER: {answer}

Based on this information, determine:
1. VERDICT: TRUE_POSITIVE (malicious), FALSE_POSITIVE (benign), or ESCALATE (unclear/mixed)
2. CONFIDENCE: 0-100 confidence in your assessment
3. REASONING: Brief explanation of your assessment

Focus on:
- File reputation and signing status
- Process execution patterns
- Network connections and communications
- Detection by security vendors
- Behavioral indicators
- System context and privileges

Respond with only: VERDICT|CONFIDENCE|REASONING
Example: TRUE_POSITIVE|85|Multiple AV detections with unsigned executable
"""
        
        try:
            response = self.llm.invoke(threat_analysis_prompt)
            analysis = response.content.strip()
            
            # Parse the response
            parts = analysis.split('|')
            if len(parts) >= 3:
                verdict = parts[0].strip()
                confidence = int(parts[1].strip())
                reasoning = '|'.join(parts[2:]).strip()
            else:
                # Fallback parsing
                verdict, confidence, reasoning = self._fallback_threat_analysis(answer)
                
        except Exception as e:
            print(f"Error in threat analysis: {e}")
            verdict, confidence, reasoning = self._fallback_threat_analysis(answer)
        
        return verdict, confidence, reasoning

    def _fallback_threat_analysis(self, answer: str) -> tuple:
        """Fallback threat analysis if LLM analysis fails"""
        answer_lower = answer.lower()
        
        # Count threat indicators
        threat_indicators = [
            "malicious", "suspicious", "trojan", "backdoor", "unsigned", 
            "invalid certificate", "multiple detections", "powershell -enc",
            "base64", "network communication", "drops file", "registry modification"
        ]
        
        benign_indicators = [
            "signed", "valid certificate", "microsoft", "legitimate", 
            "no detections", "clean", "harmless"
        ]
        
        threat_count = sum(1 for indicator in threat_indicators if indicator in answer_lower)
        benign_count = sum(1 for indicator in benign_indicators if indicator in answer_lower)
        
        if threat_count > benign_count and threat_count >= 2:
            return "TRUE_POSITIVE", min(70 + (threat_count * 5), 95), f"Multiple threat indicators detected ({threat_count})"
        elif benign_count > threat_count and benign_count >= 1:
            return "FALSE_POSITIVE", min(60 + (benign_count * 8), 90), f"Benign indicators found ({benign_count})"
        else:
            return "ESCALATE", 50, "Mixed or insufficient indicators for clear determination"

    def _generate_final_verdict(self, qa_analysis: List[Dict]) -> tuple:
        """Generate final verdict from all individual assessments"""
        
        if not qa_analysis:
            return "ESCALATE", 50, "No analysis data available"
        
        # Count verdicts
        tp_count = sum(1 for qa in qa_analysis if qa["individual_verdict"] == "TRUE_POSITIVE")
        fp_count = sum(1 for qa in qa_analysis if qa["individual_verdict"] == "FALSE_POSITIVE")
        escalate_count = sum(1 for qa in qa_analysis if qa["individual_verdict"] == "ESCALATE")
        
        total_questions = len(qa_analysis)
        
        # Calculate weighted confidence
        tp_confidence = sum(qa["individual_confidence"] for qa in qa_analysis if qa["individual_verdict"] == "TRUE_POSITIVE")
        fp_confidence = sum(qa["individual_confidence"] for qa in qa_analysis if qa["individual_verdict"] == "FALSE_POSITIVE")
        
        print(f"Verdict counts - TP: {tp_count}, FP: {fp_count}, ESCALATE: {escalate_count}")
        
        # Determine final verdict
        if tp_count >= 3 and tp_count > fp_count:
            final_verdict = "TRUE_POSITIVE"
            avg_confidence = tp_confidence / tp_count if tp_count > 0 else 70
            final_confidence = min(avg_confidence + (tp_count * 3), 95)
            summary = f"Strong malicious indicators: {tp_count}/{total_questions} questions show threat activity"
            
        elif fp_count >= 3 and fp_count > tp_count:
            final_verdict = "FALSE_POSITIVE"
            avg_confidence = fp_confidence / fp_count if fp_count > 0 else 65
            final_confidence = min(avg_confidence + (fp_count * 2), 90)
            summary = f"Likely benign: {fp_count}/{total_questions} questions indicate legitimate activity"
            
        elif tp_count >= 2 and tp_count >= fp_count:
            final_verdict = "TRUE_POSITIVE"
            final_confidence = 75 + (tp_count * 2)
            summary = f"Probable threat: {tp_count} malicious indicators vs {fp_count} benign"
            
        else:
            final_verdict = "ESCALATE"
            final_confidence = 50 + (total_questions * 2)
            summary = f"Requires human analysis: {tp_count} threat, {fp_count} benign, {escalate_count} unclear indicators"
        
        return final_verdict, final_confidence, summary

# Initialize graph manager
graph_manager = Neo4jGraphManager(neo4j_driver) if neo4j_driver else None

# Initialize threat analyzer only if we have the required components
threat_analyzer = None
if neo4j_driver and OPENAI_API_KEY:
    try:
        threat_analyzer = DynamicThreatAnalyzer()
    except Exception as e:
        print(f"Failed to initialize threat analyzer: {e}")
        threat_analyzer = None

@app.post("/create-graph")
async def create_alert_graph(file: UploadFile = File(...)):
    """
    Create Neo4j knowledge graph from flattened alert JSON file
    """
    try:
        if not file.filename.endswith(".json"):
            raise HTTPException(status_code=400, detail="Only JSON files are supported.")
        
        if not graph_manager:
            raise HTTPException(status_code=500, detail="Neo4j connection not available.")

        # Read and parse JSON
        content = await file.read()
        try:
            alert_data = json.loads(content.decode("utf-8"))
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="Invalid JSON format.")

        # Create graph
        result = graph_manager.create_alert_graph(alert_data)

        return JSONResponse(content=result)

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/analyze-from-graph/{alert_id}")
async def analyze_alert_from_graph(alert_id: str):
    """
    Analyze alert using dynamic LangChain Neo4j querying and generate verdict
    """
    try:
        if not threat_analyzer:
            raise HTTPException(
                status_code=503, 
                detail="Threat analyzer not available. Check Neo4j and OpenAI configuration."
            )
        
        # Run dynamic analysis
        result = threat_analyzer.analyze_alert_from_graph(alert_id)
        
        return JSONResponse(content=result)

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

import os
import json
from datetime import datetime
from typing import Dict, Any, List, Tuple
from langchain_openai import ChatOpenAI
from langchain_neo4j import GraphCypherQAChain, Neo4jGraph
from langchain.tools import Tool
from langchain.agents import initialize_agent, AgentType
from langchain.schema import AgentAction, AgentFinish
from langchain.memory import ConversationBufferMemory
import asyncio
import concurrent.futures
from typing import Dict, Any, List, Tuple, Optional
import time
import random

class AgenticGraphRAG:
    """Dynamic Agentic Graph RAG system with automatic Cypher generation and schema discovery"""
    
    def __init__(self, neo4j_url: str, neo4j_username: str, neo4j_password: str, openai_api_key: str):
        # Initialize core components
        self.llm = ChatOpenAI(
            temperature=0,
            api_key=openai_api_key,
            model="gpt-4o-mini"
        )
        
        self.graph = Neo4jGraph(
            url=neo4j_url,
            username=neo4j_username,
            password=neo4j_password
        )
        
        self.chain = GraphCypherQAChain.from_llm(
            llm=self.llm,
            graph=self.graph,
            allow_dangerous_requests=True,
            verbose=True
        )
        
        # Initialize memory for conversation context
        self.memory = ConversationBufferMemory(
            memory_key="chat_history",
            return_messages=True
        )
        
        # Dynamic schema discovery
        self.graph_schema = None
        self.node_types = []
        self.relationship_types = []
        self.property_patterns = {}
        
        # Define agent tools with dynamic capabilities
        self.tools = self._create_dynamic_agent_tools()
        
        # Initialize the agent
        self.agent = initialize_agent(
            tools=self.tools,
            llm=self.llm,
            agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION,
            memory=self.memory,
            verbose=True,
            max_iterations=20,
            early_stopping_method="generate"
        )
        
        self.investigation_context = {}
        self.qa_history = []
        
        # Retry and parallel execution settings
        self.max_retries = 2
        self.retry_delay = 1  # seconds
        self.max_parallel_requests = 3
        
        # Initialize schema discovery
        self._discover_graph_schema()
        
    def _discover_graph_schema(self):
        """Dynamically discover the current graph schema"""
        try:
            print("Discovering graph schema...")
            
            # Get node labels
            node_query = "CALL db.labels() YIELD label RETURN label"
            node_result = self.graph.query(node_query)
            self.node_types = [row['label'] for row in node_result]
            
            # Get relationship types
            rel_query = "CALL db.relationshipTypes() YIELD relationshipType RETURN relationshipType"
            rel_result = self.graph.query(rel_query)
            self.relationship_types = [row['relationshipType'] for row in rel_result]
            
            # Discover property patterns for each node type
            for node_type in self.node_types:
                prop_query = f"""
                MATCH (n:{node_type})
                WITH keys(n) AS props
                UNWIND props AS prop
                RETURN DISTINCT prop
                LIMIT 20
                """
                try:
                    prop_result = self.graph.query(prop_query)
                    self.property_patterns[node_type] = [row['prop'] for row in prop_result]
                except:
                    self.property_patterns[node_type] = []
            
            # Get schema info from Neo4j
            self.graph_schema = self.graph.get_schema
            
            print(f"Schema discovered: {len(self.node_types)} node types, {len(self.relationship_types)} relationship types")
            
        except Exception as e:
            print(f"Error discovering schema: {e}")
            # Fallback defaults
            self.node_types = ["Alert", "File", "Process", "Host", "User"]
            self.relationship_types = ["INVOLVES_FILE", "DETECTED_ON", "EXECUTED"]
            self.property_patterns = {}
    
    def _create_dynamic_agent_tools(self) -> List[Tool]:
        """Create dynamic tools that adapt to graph schema"""
        
        return [
            Tool(
                name="dynamic_scoring_analysis",
                description="Dynamically analyze scoring data by discovering score-related nodes and properties",
                func=self._dynamic_scoring_analysis_tool
            ),
            Tool(
                name="dynamic_graph_query",
                description="Execute dynamic graph queries with automatic Cypher generation based on current schema",
                func=self._dynamic_graph_query_tool
            ),
            Tool(
                name="schema_discovery",
                description="Discover and analyze the current graph structure and available data",
                func=self._dynamic_schema_discovery_tool
            ),
            Tool(
                name="dynamic_threat_analysis",
                description="Dynamically analyze threat patterns by discovering relevant nodes and relationships",
                func=self._dynamic_threat_analysis_tool
            ),
            Tool(
                name="dynamic_evidence_synthesis",
                description="Synthesize evidence using all discovered data patterns",
                func=self._dynamic_evidence_synthesis_tool
            ),
            Tool(
                name="dynamic_entity_exploration",
                description="Dynamically explore entity relationships based on current graph structure",
                func=self._dynamic_entity_exploration_tool
            ),
            Tool(
                name="dynamic_investigation_summary",
                description="Generate comprehensive summary using all discovered information",
                func=self._dynamic_investigation_summary_tool
            )
        ]
    
    def _generate_dynamic_cypher(self, intent: str, alert_id: str, attempt: int = 0) -> str:
        """Generate Cypher queries dynamically based on intent and discovered schema"""
        
        schema_info = f"""
        Node Types: {self.node_types}
        Relationships: {self.relationship_types}
        """
        
        # Generate intent-specific queries without hardcoded assumptions
        cypher_prompt = f"""
        Generate a Cypher query for: {intent}
        Alert ID: {alert_id}
        
        Current graph schema:
        {schema_info}
        
        Query Generation Rules:
        1. Find node with alert_id property matching '{alert_id}'
        2. Explore relationships discovered in current schema only
        3. Use OPTIONAL MATCH for all relationships
        4. Return properties that exist in current graph
        5. Adapt to whatever schema is actually present
        
        Return only executable Cypher code, no explanations.
        """
        
        try:
            response = self.llm.invoke(cypher_prompt)
            cypher_query = response.content.strip()
            
            # Clean response
            if "```" in cypher_query:
                parts = cypher_query.split("```")
                for part in parts:
                    if "MATCH" in part or "OPTIONAL" in part:
                        cypher_query = part
                        break
            
            # Remove code block markers
            cypher_query = cypher_query.replace("cypher", "").strip()
            
            return cypher_query
            
        except Exception as e:
            # Pure fallback without assumptions
            return f"""
            MATCH (n) WHERE n.alert_id = '{alert_id}'
            OPTIONAL MATCH (n)-[r]-(m)
            RETURN n, r, m
            LIMIT 30
            """
    
    def _execute_dynamic_cypher(self, intent: str, alert_id: str, attempt: int = 0) -> str:
        """Execute dynamically generated Cypher with retry logic"""
        
        try:
            # Generate Cypher query
            cypher_query = self._generate_dynamic_cypher(intent, alert_id, attempt)
            
            print(f"Generated Cypher (attempt {attempt + 1}): {cypher_query}")
            
            # Execute the query
            result = self.graph.query(cypher_query)
            
            if result and not self._is_cypher_result_empty(result):
                return self._format_cypher_result(result, intent)
            else:
                return "No data found with generated query"
                
        except Exception as e:
            error_msg = str(e)
            print(f"Cypher execution error: {error_msg}")
            
            # If it's a syntax error, try to fix it
            if "syntax" in error_msg.lower() or "invalid" in error_msg.lower():
                try:
                    # Try a simpler fallback query
                    fallback_query = f"""
                    MATCH (n) 
                    WHERE n.alert_id = '{alert_id}' OR id(n) = '{alert_id}'
                    OPTIONAL MATCH (n)-[r]-(m)
                    RETURN n, type(r) as rel_type, m
                    LIMIT 20
                    """
                    result = self.graph.query(fallback_query)
                    return self._format_cypher_result(result, intent) if result else f"Cypher error: {error_msg}"
                except:
                    return f"Cypher execution failed: {error_msg}"
            
            return f"Query execution error: {error_msg}"
    
    def _format_cypher_result(self, result, intent: str) -> str:
        """Format Cypher query results in a readable way"""
        
        if not result:
            return "No results returned"
        
        formatted_output = []
        
        try:
            for i, row in enumerate(result[:10]):  # Limit to first 10 results
                row_data = []
                
                for key, value in row.items():
                    if value is not None:
                        if isinstance(value, dict):
                            # Node or relationship properties
                            props = ", ".join([f"{k}: {v}" for k, v in value.items() if v])
                            row_data.append(f"{key}: {{{props}}}")
                        elif isinstance(value, list):
                            # Multiple values
                            row_data.append(f"{key}: {value}")
                        else:
                            row_data.append(f"{key}: {value}")
                
                if row_data:
                    formatted_output.append(f"Result {i+1}: {'; '.join(row_data)}")
            
            return "\n".join(formatted_output) if formatted_output else "Results found but no readable data"
            
        except Exception as e:
            return f"Error formatting results: {str(e)}\nRaw result count: {len(result)}"
    
    def _retry_with_dynamic_enhancement(self, func, *args, **kwargs) -> str:
        """Enhanced retry mechanism with dynamic query improvement"""
        
        for attempt in range(self.max_retries + 1):
            try:
                result = func(*args, **kwargs, attempt=attempt)
                
                # Check if result is empty or indicates no data found
                if self._is_empty_result(result):
                    if attempt < self.max_retries:
                        print(f"Attempt {attempt + 1} returned empty result, retrying with enhanced approach...")
                        time.sleep(self.retry_delay * (attempt + 1))
                        continue
                    else:
                        return "No relevant data found after multiple dynamic attempts."
                
                return result
                
            except Exception as e:
                if attempt < self.max_retries:
                    print(f"Attempt {attempt + 1} failed: {str(e)}, retrying with different approach...")
                    time.sleep(self.retry_delay * (attempt + 1))
                    continue
                else:
                    return f"Error after {self.max_retries + 1} dynamic attempts: {str(e)}"
        
        return "Maximum retries exceeded with dynamic queries."
    
    def _dynamic_scoring_analysis_tool(self, alert_context: str, attempt: int = 0) -> str:
        """Dynamic scoring analysis that discovers score-related nodes"""
        
        alert_id = self.investigation_context.get("alert_id", alert_context)
        
        # Dynamic intent generation based on discovered schema
        scoring_intents = [
            f"Find all scoring, prediction, and confidence data for alert {alert_id}",
            f"Discover any machine learning, GNN, or rule-based analysis results for alert {alert_id}",
            f"Locate any nodes with properties containing 'score', 'confidence', 'verdict', or 'prediction' related to alert {alert_id}"
        ]
        
        intent = scoring_intents[min(attempt, len(scoring_intents) - 1)]
        
        try:
            # Use dynamic Cypher generation
            result = self._execute_dynamic_cypher(intent, alert_id, attempt)
            
            if self._is_empty_result(result):
                # Try natural language fallback
                fallback_query = f"Find any scoring or prediction information for alert with ID '{alert_id}'"
                result = self.chain.run(fallback_query)
            
        except Exception as e:
            result = f"Error in dynamic scoring analysis: {str(e)}"
        
        # Make response concise
        concise_result = self._make_concise_response(
            question="What are the scoring analysis results for this alert?",
            result=result,
            focus="scoring verdicts, confidence levels, and model agreements/disagreements"
        )
        
        return concise_result
    
    def _dynamic_graph_query_tool(self, query: str, attempt: int = 0) -> str:
        """Dynamic graph query with automatic Cypher generation"""
        
        alert_id = self.investigation_context.get("alert_id", "")
        
        # Convert natural language query to intent
        intent = f"Answer this question about alert {alert_id}: {query}"
        
        try:
            # First try dynamic Cypher generation
            result = self._execute_dynamic_cypher(intent, alert_id, attempt)
            
            if self._is_empty_result(result):
                # Fallback to LangChain natural language processing
                enhanced_query = f"For alert with alert_id '{alert_id}': {query}"
                result = self.chain.run(enhanced_query)
            
        except Exception as e:
            # Final fallback
            try:
                result = self.chain.run(query)
            except:
                result = f"Error executing dynamic query: {str(e)}"
        
        # Make response concise
        concise_result = self._make_concise_response(
            question=query,
            result=result,
            focus="key findings and critical details"
        )
        
        return concise_result
    
    def _dynamic_schema_discovery_tool(self, _: str = "") -> str:
        """Dynamic schema discovery and analysis"""
        
        # Refresh schema if needed
        self._discover_graph_schema()
        
        schema_summary = f"""
        Current Graph Schema:
        - Node Types ({len(self.node_types)}): {', '.join(self.node_types)}
        - Relationship Types ({len(self.relationship_types)}): {', '.join(self.relationship_types)}
        - Property Patterns: {len(self.property_patterns)} node types with discovered properties
        
        This schema is discovered dynamically and adapts to the current graph structure.
        """
        
        return schema_summary
    
    def _dynamic_threat_analysis_tool(self, context: str, attempt: int = 0) -> str:
        """Dynamic threat pattern analysis using discovered schema"""
        
        alert_id = self.investigation_context.get("alert_id", "")
        
        # Generate threat analysis intent based on available schema
        threat_intents = [
            f"Analyze threat indicators and malicious patterns for alert {alert_id} using all available node types and relationships",
            f"Discover security-related information and threat indicators connected to alert {alert_id}",
            f"Find any nodes or properties indicating malicious activity, threats, or security concerns for alert {alert_id}"
        ]
        
        intent = threat_intents[min(attempt, len(threat_intents) - 1)]
        
        try:
            # Get current investigation data
            investigation_summary = "\n".join([
                f"Q: {qa['question']}\nA: {qa['answer']}" 
                for qa in self.qa_history[-5:]  # Last 5 Q&As
            ])
            
            # Use dynamic Cypher generation for threat analysis
            cypher_result = self._execute_dynamic_cypher(intent, alert_id, attempt)
            
            # Enhance with LLM analysis
            analysis_prompt = f"""
            Based on investigation data and graph discovery, analyze threat patterns:
            
            Graph Data Found: {cypher_result}
            Recent Investigation Findings: {investigation_summary}
            Available Schema: Node types: {self.node_types}, Relationships: {self.relationship_types}
            
            Identify critical threat indicators and attack patterns from the available data.
            Focus on concrete evidence of malicious activity discovered in the graph.
            Provide information in 5-6 lines . Highlighting important perspectives
            """
            
            analysis = self.llm.invoke(analysis_prompt)
            result = analysis.content.strip()
            
        except Exception as e:
            result = f"Error in dynamic threat analysis: {str(e)}"
        
        # Store in Q&A history
        self.qa_history.append({
            "question": "What threat patterns are present in this alert?",
            "answer": result,
            "timestamp": datetime.now().isoformat()
        })
        
        return result
    
    def _dynamic_evidence_synthesis_tool(self, investigation_summary: str, attempt: int = 0) -> str:
        """Dynamic evidence synthesis using all discovered data"""
        
        try:
            synthesis_prompt = f"""
            Based on the complete dynamic investigation, make a definitive classification.
            
            All Investigation Results: {self.qa_history}
            Graph Schema Used: {self.node_types} nodes, {self.relationship_types} relationships
            
            Classification Criteria (adapt based on available data):
            TRUE_POSITIVE: Clear malicious indicators discovered
            FALSE_POSITIVE: Strong benign indicators found
            ESCALATE: Mixed, insufficient, or unclear evidence
            
            Consider all dynamically discovered data including:
            - Any scoring or prediction nodes found
            - Security-related properties and relationships
            - File, process, network, or other threat indicators
            - Detection results from any security tools
            
            Provide: CLASSIFICATION, CONFIDENCE (0-100), KEY_EVIDENCE, REASONING
            Be decisive based on the evidence discovered through dynamic analysis.
            """
            
            synthesis = self.llm.invoke(synthesis_prompt)
            
            # Extract classification and confidence
            classification_prompt = f"""
            From this dynamic analysis, extract the exact classification and confidence:
            
            {synthesis.content}
            
            Respond with EXACTLY this format:
            CLASSIFICATION: [TRUE_POSITIVE|FALSE_POSITIVE|ESCALATE]
            CONFIDENCE: [0-100]
            """
            
            verdict_result = self.llm.invoke(classification_prompt)
            
            # Store assessment
            self.investigation_context['agent_assessment'] = {
                'full_synthesis': synthesis.content,
                'verdict_extraction': verdict_result.content,
                'timestamp': datetime.now().isoformat(),
                'attempt': attempt,
                'schema_used': {'nodes': self.node_types, 'relationships': self.relationship_types}
            }
            
            return synthesis.content
            
        except Exception as e:
            return f"Error in dynamic evidence synthesis: {str(e)}"
    
    def _dynamic_entity_exploration_tool(self, entity_description: str, attempt: int = 0) -> str:
        """Dynamic entity exploration using discovered relationships"""
        
        alert_id = self.investigation_context.get("alert_id", "")
        
        # Generate exploration intent based on available schema
        exploration_intent = f"Explore and map all entities and relationships connected to '{entity_description}' for alert {alert_id}, using available relationship types: {self.relationship_types}"
        
        try:
            result = self._execute_dynamic_cypher(exploration_intent, alert_id, attempt)
            
            if self._is_empty_result(result):
                # Fallback to natural language
                fallback_query = f"For alert_id '{alert_id}', find entities and relationships related to: {entity_description}"
                result = self.chain.run(fallback_query)
            
        except Exception as e:
            result = f"Error in dynamic entity exploration: {str(e)}"
        
        # Make concise
        concise_result = self._make_concise_response(
            question=f"What entities are related to {entity_description}?",
            result=result,
            focus="relationship mappings and connected entities"
        )
        
        return concise_result
    
    def _dynamic_investigation_summary_tool(self, context: str, attempt: int = 0) -> str:
        """Dynamic investigation summary in strict 5-6 lines"""
        
        try:
            summary_prompt = f"""
            Create investigation summary in EXACTLY 5-6 lines only:
            
            Q&A History: {self.qa_history}
            Alert ID: {self.investigation_context.get('alert_id', 'Unknown')}
            
            STRICT FORMAT:
            - Line 1: Alert ID and basic file/threat info
            - Line 2: ML/GNN/Rule scoring results
            - Line 3: Key threat indicators found
            - Line 4: Detection status and confidence
            - Line 5: Final verdict and reasoning
            - Line 6: Critical action needed (optional)
            
            Maximum 5-6 lines total, no formatting, direct statements only.
            """
            
            summary = self.llm.invoke(summary_prompt)
            response = summary.content.strip()
            
            # Enforce strict line limit
            lines = response.split('\n')
            if len(lines) > 6:
                response = '\n'.join(lines[:6])
            
            return response
            
        except Exception as e:
            # Fallback summary from Q&A
            key_points = []
            for qa in self.qa_history[-3:]:  # Last 3 Q&As only
                if qa['answer'] and len(qa['answer']) > 20:
                    key_points.append(qa['answer'].split('.')[0] + '.')
            
            fallback = f"Alert {self.investigation_context.get('alert_id', 'Unknown')} investigation completed. "
            fallback += ' '.join(key_points[:2])  # Only first 2 key points
            return fallback[:400]  # Limit length
    
    def _make_concise_response(self, question: str, result: str, focus: str) -> str:
        """Make responses concise while preserving key information"""
        
        concise_prompt = f"""
        Summarize this in EXACTLY 5-6 lines only, no more:
        
        Question: {question}
        Result: {result}
        Focus on: {focus}
        
        STRICT REQUIREMENTS:
        - Maximum 5-6 lines total
        - Extract only the most critical information
        - No bullet points, headers, or formatting
        - Direct, factual statements only
        """
        
        try:
            concise_result = self.llm.invoke(concise_prompt)
            response = concise_result.content.strip()
            
            # Enforce line limit by truncating if needed
            lines = response.split('\n')
            if len(lines) > 6:
                response = '\n'.join(lines[:6])
            
            # Store in Q&A history
            self.qa_history.append({
                "question": question,
                "answer": response,
                "timestamp": datetime.now().isoformat()
            })
            
            return response
            
        except Exception as e:
            # Fallback: truncate original result to 5-6 lines
            lines = result.split('\n')[:6]
            fallback_response = '\n'.join(lines) if lines else result[:200] + "..."
            
            self.qa_history.append({
                "question": question,
                "answer": fallback_response,
                "timestamp": datetime.now().isoformat()
            })
            
            return fallback_response
    
    def _is_empty_result(self, result: str) -> bool:
        """Check if result indicates no data found"""
        empty_indicators = [
            "no data", "not found", "no results", "no information",
            "empty", "none found", "no records", "[]", "{}"
        ]
        
        result_lower = result.lower().strip()
        return any(indicator in result_lower for indicator in empty_indicators) or len(result_lower) < 10
    
    def _is_cypher_result_empty(self, result) -> bool:
        """Check if Cypher query result is empty or meaningless"""
        if not result:
            return True
        
        if isinstance(result, list):
            if len(result) == 0:
                return True
            
            # Check if all values are None or empty
            for row in result:
                if isinstance(row, dict):
                    non_null_values = [v for v in row.values() if v is not None and v != ""]
                    if non_null_values:
                        return False
            return True
        
        return False
    
    def investigate_alert(self, alert_id: str) -> Dict[str, Any]:
        """Dynamic investigation with schema-adaptive approach"""
        
        print(f"Starting dynamic investigation for alert: {alert_id}")
        
        # Reset investigation context
        self.qa_history = []
        self.investigation_context = {"alert_id": alert_id}
        
        # Refresh schema discovery for this investigation
        self._discover_graph_schema()
        
        investigation_prompt = f"""
        You are investigating alert ID: {alert_id} using dynamic graph analysis.
        
        Mission: Determine TRUE_POSITIVE, FALSE_POSITIVE, or ESCALATE using adaptive schema discovery.
        
        Current Graph Schema:
        - Node Types: {self.node_types}
        - Relationships: {self.relationship_types}
        
        IMPORTANT: Keep all responses to 5-6 lines maximum.
        
        Dynamic Investigation Process:
        1. Use dynamic_scoring_analysis to discover any scoring-related data
        2. Use dynamic_graph_query to ask specific questions that adapt to current schema:
           - "What file and security characteristics are available for this alert?"
           - "What detection and analysis information exists for this alert?"
           - "What host, network, and system context is available?"
           - "What process and user activity data exists for this alert?"
        3. Use dynamic_entity_exploration to map relationship networks
        4. Apply dynamic_threat_analysis using discovered patterns
        5. Use dynamic_evidence_synthesis for final verdict
        6. Generate dynamic_investigation_summary
        
        The system will automatically generate appropriate Cypher queries based on current schema.
        Start your adaptive investigation now.
        """
        
        try:
            # Run dynamic investigation
            investigation_result = self.agent.run(investigation_prompt)
            
            # Extract agent verdict and confidence
            agent_verdict = "ESCALATE"
            agent_confidence = 50
            
            if 'agent_assessment' in self.investigation_context:
                verdict_text = self.investigation_context['agent_assessment'].get('verdict_extraction', '')
                
                if 'CLASSIFICATION:' in verdict_text:
                    classification_line = [line for line in verdict_text.split('\n') if 'CLASSIFICATION:' in line]
                    if classification_line:
                        extracted_verdict = classification_line[0].split('CLASSIFICATION:')[1].strip()
                        if extracted_verdict in ['TRUE_POSITIVE', 'FALSE_POSITIVE', 'ESCALATE']:
                            agent_verdict = extracted_verdict
                
                if 'CONFIDENCE:' in verdict_text:
                    confidence_line = [line for line in verdict_text.split('\n') if 'CONFIDENCE:' in line]
                    if confidence_line:
                        try:
                            confidence_str = confidence_line[0].split('CONFIDENCE:')[1].strip()
                            agent_confidence = int(''.join(filter(str.isdigit, confidence_str)))
                            agent_confidence = min(max(agent_confidence, 0), 100)
                        except:
                            agent_confidence = 50
            
            # Generate final summary
            summary = self._dynamic_investigation_summary_tool("")
            
            # Return results with schema information
            return {
                "alert_id": alert_id,
                "qa_history": self.qa_history,
                "summary": summary,
                "agent_verdict": agent_verdict,
                "agent_confidence": agent_confidence,
                "schema_discovered": {
                    "node_types": self.node_types,
                    "relationship_types": self.relationship_types,
                    "property_patterns_count": len(self.property_patterns)
                },
                "investigation_method": "Dynamic Schema-Adaptive Analysis"
            }
            
        except Exception as e:
            return {
                "alert_id": alert_id,
                "qa_history": self.qa_history,
                "summary": f"Dynamic investigation error: {str(e)}",
                "agent_verdict": "ESCALATE",
                "agent_confidence": 0,
                "schema_discovered": {
                    "node_types": self.node_types,
                    "relationship_types": self.relationship_types,
                    "property_patterns_count": len(self.property_patterns)
                },
                "investigation_method": "Dynamic Schema-Adaptive Analysis (Error Recovery)"
            }     
            
def create_agentic_investigator():
    """Create and configure the agentic investigator"""
    
    investigator = AgenticGraphRAG(
        neo4j_url="bolt://localhost:7687",
        neo4j_username="neo4j", 
        neo4j_password="password",
        openai_api_key="sk-..."  # Your API key
    )
    
    return investigator

from fastapi import HTTPException

@app.post("/investigate-agentic/{alert_id}")
async def investigate_alert_agentic(alert_id: str):
    """
    Conduct autonomous agentic investigation with scoring analysis and simplified output
    """
    try:
        if not OPENAI_API_KEY:
            raise HTTPException(
                status_code=503,
                detail="OpenAI API key not configured"
            )
        
        # Create simplified investigator instance
        investigator = AgenticGraphRAG(
            neo4j_url=NEO4J_URI,
            neo4j_username=NEO4J_USERNAME,
            neo4j_password=NEO4J_PASSWORD,
            openai_api_key=OPENAI_API_KEY
        )
        
        # Run autonomous investigation
        result = investigator.investigate_alert(alert_id)
        
        return JSONResponse(content=result)
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/investigate-interactive/{alert_id}")
async def investigate_alert_interactive(alert_id: str, question: str):
    """
    Interactive investigation - ask specific questions about an alert
    """
    try:
        investigator = AgenticGraphRAG(
            neo4j_url=NEO4J_URI,
            neo4j_username=NEO4J_USERNAME,
            neo4j_password=NEO4J_PASSWORD,
            openai_api_key=OPENAI_API_KEY
        )
        
        response = investigator.interactive_investigation(alert_id, question)
        
        return JSONResponse(content={
            "alert_id": alert_id,
            "question": question,
            "response": response,
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))




LABELS = ["False Positive", "Escalate", "True Positive"]
_GNN_CACHE: Dict[str, Tuple[nn.Module, dict, list]] = {}

def stable_hash(s: str, mod: int = 512) -> int:
    import hashlib as _h
    return int(_h.sha256(s.encode("utf-8")).hexdigest(), 16) % mod

class GenericFeatureEncoder:
    def __init__(self, dim: int = 512): 
        self.dim = dim
    def encode(self, labels, props):
        v = np.zeros(self.dim, dtype=np.float32)
        lab = labels[0] if labels else "Node"
        for k, val in (props or {}).items():
            if val is None: 
                continue
            if isinstance(val, (int, float, bool)):
                v[stable_hash(f"{lab}.{k}={val}", self.dim)] += 1.0
            elif isinstance(val, (list, tuple)):
                for i, item in enumerate(val[:5]):
                    v[stable_hash(f"{lab}.{k}[{i}]={item}", self.dim)] += 1.0
            else:
                v[stable_hash(f"{lab}.{k}={str(val)[:200]}", self.dim)] += 1.0
        return v.tolist()

ENC = GenericFeatureEncoder(dim=512)

@dataclass
class Subgraph:
    N: int
    F: int
    features: torch.Tensor
    edges_by_rel: Dict[str, Tuple[torch.Tensor, torch.Tensor]]
    target_idx: int

def fetch_khop_alert_subgraph(alert_id: str, max_hops: int = 5, dim: int = 512) -> Optional[Subgraph]:
    """
    Build ego graph up to `max_hops` around (Alert {alert_id: ...}) using your existing neo4j_driver.
    Falls back gracefully (returns None) if driver not available or node not found.
    """
    if not neo4j_driver:
        return None
    try:
        with neo4j_driver.session(database=NEO4J_DATABASE or "neo4j") as s:
            rec = s.run(
                """
                MATCH (a:Alert {alert_id:$id})
                OPTIONAL MATCH p=(a)-[*..$K]-(n)
                WITH a, collect(p) AS paths
                WITH a,
                     reduce(ns=[], p IN paths | ns + nodes(p)) AS ns,
                     reduce(rs=[], p IN paths | rs + relationships(p)) AS rs
                UNWIND ns AS n
                WITH collect(DISTINCT {id: elementId(n), labels: labels(n), props: properties(n)}) AS nodes, rs
                UNWIND rs AS r
                WITH nodes, collect(DISTINCT {
                  type: type(r), start: elementId(startNode(r)), end: elementId(endNode(r))
                }) AS rels
                RETURN nodes, rels
                """,
                id=alert_id, K=max_hops
            ).single()
    except Exception:
        return None

    if not rec:
        return None
    nodes = rec.get("nodes") or []
    rels  = rec.get("rels") or []
    if not nodes:
        return None

    id2idx = {n["id"]: i for i, n in enumerate(nodes)}
    target_idx = None
    for i, n in enumerate(nodes):
        if "Alert" in n.get("labels", []) and str(n.get("props", {}).get("alert_id")) == str(alert_id):
            target_idx = i
            break
    if target_idx is None:
        # fallback to any Alert node
        for i, n in enumerate(nodes):
            if "Alert" in n.get("labels", []):
                target_idx = i
                break
    if target_idx is None:
        return None

    X = torch.tensor([ENC.encode(n.get("labels", []), n.get("props", {})) for n in nodes], dtype=torch.float32)

    rel_names = sorted(set(r["type"] for r in rels))
    edges_by_rel: Dict[str, Tuple[list, list]] = {}
    for t in rel_names:
        edges_by_rel[t] = ([], [])
        edges_by_rel[t + "_rev"] = ([], [])
    for r in rels:
        t = r["type"]; s_id = r["start"]; d_id = r["end"]
        if s_id not in id2idx or d_id not in id2idx:
            continue
        u = id2idx[s_id]; v = id2idx[d_id]
        edges_by_rel[t][0].append(u); edges_by_rel[t][1].append(v)
        edges_by_rel[t + "_rev"][0].append(v); edges_by_rel[t + "_rev"][1].append(u)

    out: Dict[str, Tuple[torch.Tensor, torch.Tensor]] = {}
    for k, (ss, dd) in edges_by_rel.items():
        if len(ss) == 0:
            out[k] = (torch.empty(0, dtype=torch.long), torch.empty(0, dtype=torch.long))
        else:
            out[k] = (torch.tensor(ss, dtype=torch.long), torch.tensor(dd, dtype=torch.long))
    return Subgraph(N=len(nodes), F=X.size(1), features=X, edges_by_rel=out, target_idx=target_idx)

class RelGraphLayer(nn.Module):
    def __init__(self, in_dim, out_dim, rel_names, dropout=0.1):
        super().__init__()
        self.rel_names = rel_names
        self.rel_weights = nn.ModuleDict({r: nn.Linear(in_dim, out_dim, bias=False) for r in rel_names})
        self.self_loop = nn.Linear(in_dim, out_dim, bias=True)
        self.dropout = nn.Dropout(dropout)
        self.act = nn.ReLU()
    def forward(self, h, edges_by_rel):
        N, _ = h.shape
        out = self.self_loop(h)
        for r in self.rel_names:
            src_idx, dst_idx = edges_by_rel.get(r, (torch.empty(0, dtype=torch.long), torch.empty(0, dtype=torch.long)))
            if src_idx.numel() == 0:
                continue
            Wh = self.rel_weights[r](h)
            msgs = Wh[src_idx]
            agg = torch.zeros_like(out)
            agg.index_add_(0, dst_idx, msgs)
            deg = torch.zeros(N, device=h.device)
            deg.index_add_(0, dst_idx, torch.ones_like(dst_idx, dtype=torch.float32))
            deg = deg.clamp_min(1.0).unsqueeze(1)
            out = out + agg / deg
        out = self.act(out)
        return self.dropout(out)

class RGCN_NoDGL(nn.Module):
    def __init__(self, in_dim, hid, out_dim, rel_names, dropout=0.1):
        super().__init__()
        self.rel_names = rel_names
        self.l1 = RelGraphLayer(in_dim, hid, rel_names, dropout)
        self.l2 = RelGraphLayer(hid, hid, rel_names, dropout)
        self.head = nn.Sequential(nn.Dropout(dropout), nn.Linear(hid, out_dim))
    def forward(self, X, edges_by_rel):
        h = self.l1(X, edges_by_rel)
        h = self.l2(h, edges_by_rel)
        return self.head(h)

def _load_gnn_model(ckpt_path: str):
    """
    Load and cache the R-GCN model checkpoint.
    Expects a torch checkpoint with keys: 'config' (dict) and 'state_dict'.
    config must contain: in_dim, hidden, out_dim, rel_names, (optional) dropout/hops.
    """
    if ckpt_path in _GNN_CACHE:
        return _GNN_CACHE[ckpt_path]
    ckpt = torch.load(ckpt_path, map_location="cpu")
    cfg = ckpt["config"]
    rel_names = cfg["rel_names"]
    model = RGCN_NoDGL(cfg["in_dim"], cfg["hidden"], cfg["out_dim"], rel_names, cfg.get("dropout", 0.1))
    model.load_state_dict(ckpt["state_dict"])
    model.eval()
    _GNN_CACHE[ckpt_path] = (model, cfg, rel_names)
    return model, cfg, rel_names
# ==== /GNN core ===============================================================

def _flatten_json(obj, parent_key=""):
    flat = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            nk = f"{parent_key}.{k}" if parent_key else k
            flat.update(_flatten_json(v, nk))
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:50]):
            nk = f"{parent_key}[{i}]"
            flat.update(_flatten_json(v, nk))
    else:
        flat[parent_key] = obj
    return flat

def _extract_uid_from_json(payload: dict) -> str:
    candidates = ["uid", "alert_id", "alertId", "threatId", "threat_id", "id"]
    for k in candidates:
        if k in payload and payload[k]:
            return str(payload[k])
    flat = _flatten_json(payload)
    for k, v in flat.items():
        last = k.split(".")[-1]
        if last in candidates and v not in (None, ""):
            return str(v)
    return ""

@app.post("/gnn/predict_json")
async def gnn_predict_json(
    file: UploadFile = File(None),
    payload: dict = Body(None)
):
    """
    Accepts JSON file or raw JSON body.
    1) Extract alert_id
    2) Try Neo4j ego graph (hops=5); if no relations → selfie on provided JSON
    """
    import json, torch, numpy as np
    # 1) Parse JSON
    if payload is None and file is not None:
        raw = await file.read()
        payload = json.loads(raw.decode("utf-8"))
    if payload is None:
        raise HTTPException(status_code=400, detail="Provide a JSON file or JSON body.")

    alert_id = _extract_uid_from_json(payload)
    if not alert_id:
        raise HTTPException(status_code=400, detail="Could not find alert id in JSON.")

    # 2) Load model (defaults)
    try:
        model, cfg, rel_names = _load_gnn_model(DEFAULT_GNN_CKPT)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Checkpoint not found: {DEFAULT_GNN_CKPT}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load checkpoint: {e}")

    # 3) Try ego; fallback to selfie if no edges
    try:
        sg = fetch_khop_alert_subgraph(alert_id, max_hops=cfg.get('hops', DEFAULT_GNN_HOPS), dim=cfg['in_dim'])
    except Exception:
        sg = None

    def empty_edges(names):
        return {r: (torch.empty(0, dtype=torch.long), torch.empty(0, dtype=torch.long)) for r in names}

    mode = "ego"
    if sg is None:
        # selfie mode
        mode = "selfie"
        enc = GenericFeatureEncoder(dim=cfg['in_dim'])
        x = torch.tensor([enc.encode(["Alert"], _flatten_json(payload))], dtype=torch.float32)
        with torch.no_grad():
            logits = model(x, empty_edges(rel_names))[0].detach().cpu().numpy()
    else:
        # check for any relations in ego graph
        has_edge = any(
            sg.edges_by_rel.get(r, (torch.empty(0, dtype=torch.long), torch.empty(0, dtype=torch.long)))[0].numel() > 0
            for r in rel_names
        )
        if not has_edge:
            # selfie fallback
            mode = "selfie"
            enc = GenericFeatureEncoder(dim=cfg['in_dim'])
            x = torch.tensor([enc.encode(["Alert"], _flatten_json(payload))], dtype=torch.float32)
            with torch.no_grad():
                logits = model(x, empty_edges(rel_names))[0].detach().cpu().numpy()
        else:
            # ego graph inference
            edges_aligned = {
                r: sg.edges_by_rel.get(r, (torch.empty(0, dtype=torch.long), torch.empty(0, dtype=torch.long)))
                for r in rel_names
            }
            with torch.no_grad():
                logits = model(sg.features, edges_aligned)[sg.target_idx].detach().cpu().numpy()

    prob = np.exp(logits - logits.max()); prob = prob / prob.sum()
    labels = ["False Positive", "Escalate", "True Positive"]
    top = int(prob.argmax())
    return {
        "alert_id": alert_id,
        "verdict": labels[top],
        "score": round(float(prob[top] * 100.0), 2),
        "probabilities": {labels[i]: float(prob[i]) for i in range(len(labels))},
        "mode": mode
    }

# Add this to your existing FastAPI app

import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, List, Optional
import json
import requests
from datetime import datetime

class SupervisorAgent:
    """Orchestrates parallel sub-agents with dynamic weighting"""
    
    def __init__(self):
        self.executor = ThreadPoolExecutor(max_workers=4)
        
        # Source to agent mapping
        self.source_mapping = {
            "edr": "EDR",
            "endpoint": "EDR", 
            "sentinelone": "EDR",
            "crowdstrike": "EDR",
            "firewall": "Firewall",
            "palo_alto": "Firewall",
            "fortinet": "Firewall",
            "email": "Email",
            "proofpoint": "Email",
            "mimecast": "Email",
            "gnn": "GNN",
            "graph": "GNN"
        }
    
    async def run_edr_agent(self, edr_data: Dict[str, Any]) -> Dict[str, Any]:
        """Run EDR agent using the classifier directly (no HTTP request)"""
        try:
            # Use the classifier directly instead of HTTP request
            result = classifier.predict(edr_data)
            
            # Extract confidence score and convert to 0-100 scale
            confidence = result.get('prediction', {}).get('confidence', 0) * 100
            verdict = result.get('prediction', {}).get('predicted_verdict', 'Unknown')
            
            # Normalize verdict format
            verdict_mapping = {
                'true_positive': 'True Positive',
                'false_positive': 'False Positive', 
                'undefined': 'Escalate',
                'escalate': 'Escalate'
            }
            normalized_verdict = verdict_mapping.get(verdict.lower(), verdict)
            
            # Map verdict to risk score
            risk_score = 0
            if normalized_verdict == "True Positive":
                risk_score = max(80, confidence)
            elif normalized_verdict == "Escalate":
                risk_score = max(50, min(confidence, 79))
            else:  # False Positive
                risk_score = min(confidence, 30)
            
            return {
                "agent": "EDR",
                "score": int(risk_score),
                "verdict": normalized_verdict,
                "confidence": round(confidence, 2),
                "message": f"EDR Analysis: {normalized_verdict} with {confidence:.1f}% confidence",
                "details": result.get('metadata', {}),
                "success": True
            }
                
        except Exception as e:
            return self._error_response("EDR", f"EDR agent error: {str(e)}")
    
    async def run_gnn_agent(self, gnn_data: Dict[str, Any]) -> Dict[str, Any]:
        """Run GNN agent using the GNN functions directly (no HTTP request)"""
        try:
            # Extract alert_id for GNN processing
            alert_id = _extract_uid_from_json(gnn_data)
            if not alert_id:
                return self._error_response("GNN", "Could not find alert_id in GNN data")
            
            # Load GNN model (use existing cached version if available)
            try:
                model, cfg, rel_names = _load_gnn_model(DEFAULT_GNN_CKPT)
            except FileNotFoundError:
                return self._error_response("GNN", f"GNN model not found: {DEFAULT_GNN_CKPT}")
            except Exception as e:
                return self._error_response("GNN", f"Failed to load GNN model: {str(e)}")
            
            # Try ego graph first, fallback to selfie if needed
            try:
                sg = fetch_khop_alert_subgraph(alert_id, max_hops=cfg.get('hops', DEFAULT_GNN_HOPS), dim=cfg['in_dim'])
            except Exception:
                sg = None

            def empty_edges(names):
                return {r: (torch.empty(0, dtype=torch.long), torch.empty(0, dtype=torch.long)) for r in names}

            mode = "ego"
            if sg is None:
                # selfie mode
                mode = "selfie"
                enc = GenericFeatureEncoder(dim=cfg['in_dim'])
                x = torch.tensor([enc.encode(["Alert"], _flatten_json(gnn_data))], dtype=torch.float32)
                with torch.no_grad():
                    logits = model(x, empty_edges(rel_names))[0].detach().cpu().numpy()
            else:
                # check for any relations in ego graph
                has_edge = any(
                    sg.edges_by_rel.get(r, (torch.empty(0, dtype=torch.long), torch.empty(0, dtype=torch.long)))[0].numel() > 0
                    for r in rel_names
                )
                if not has_edge:
                    # selfie fallback
                    mode = "selfie"
                    enc = GenericFeatureEncoder(dim=cfg['in_dim'])
                    x = torch.tensor([enc.encode(["Alert"], _flatten_json(gnn_data))], dtype=torch.float32)
                    with torch.no_grad():
                        logits = model(x, empty_edges(rel_names))[0].detach().cpu().numpy()
                else:
                    # ego graph inference
                    edges_aligned = {
                        r: sg.edges_by_rel.get(r, (torch.empty(0, dtype=torch.long), torch.empty(0, dtype=torch.long)))
                        for r in rel_names
                    }
                    with torch.no_grad():
                        logits = model(sg.features, edges_aligned)[sg.target_idx].detach().cpu().numpy()

            import numpy as np
            prob = np.exp(logits - logits.max())
            prob = prob / prob.sum()
            labels = ["False Positive", "Escalate", "True Positive"]
            top = int(prob.argmax())
            score = float(prob[top] * 100.0)
            verdict = labels[top]
            
            # Convert verdict to risk score if needed
            risk_score = score
            if verdict == "True Positive":
                risk_score = max(80, score)
            elif verdict == "Escalate": 
                risk_score = max(40, min(score, 79))
            elif verdict == "False Positive":
                risk_score = min(score, 30)
            
            return {
                "agent": "GNN",
                "score": int(risk_score),
                "verdict": verdict,
                "confidence": round(score, 2),
                "probabilities": {labels[i]: round(float(prob[i]), 4) for i in range(len(labels))},
                "mode": mode,
                "message": f"GNN Analysis ({mode}): {verdict} with {score:.1f}% confidence",
                "details": {"alert_id": alert_id, "mode": mode},
                "success": True
            }
                
        except Exception as e:
            return self._error_response("GNN", f"GNN agent error: {str(e)}")
    
    async def run_firewall_agent(self, context_data: Dict[str, Any]) -> Dict[str, Any]:
        """Run Firewall agent (pluggable - currently returns 0)"""
        try:
            # Placeholder for firewall analysis
            # This would integrate with firewall logs, network monitoring, etc.
            # Could use either edr_data or gnn_data based on implementation needs
            
            return {
                "agent": "Firewall",
                "score": 0,
                "verdict": "No Analysis",
                "message": "Firewall agent not implemented - pluggable for future network analysis",
                "details": {"status": "placeholder"},
                "success": True
            }
            
        except Exception as e:
            return self._error_response("Firewall", f"Firewall agent error: {str(e)}")
    
    async def run_email_agent(self, context_data: Dict[str, Any]) -> Dict[str, Any]:
        """Run Email agent (pluggable - currently returns 0)"""
        try:
            # Placeholder for email security analysis
            # This would integrate with email security tools, phishing detection, etc.
            # Could use either edr_data or gnn_data based on implementation needs
            
            return {
                "agent": "Email",
                "score": 0,
                "verdict": "No Analysis", 
                "message": "Email agent not implemented - pluggable for future email security analysis",
                "details": {"status": "placeholder"},
                "success": True
            }
            
        except Exception as e:
            return self._error_response("Email", f"Email agent error: {str(e)}")
    
    def _error_response(self, agent_name: str, error_msg: str) -> Dict[str, Any]:
        """Generate standardized error response"""
        return {
            "agent": agent_name,
            "score": 0,
            "verdict": "Error",
            "message": error_msg,
            "details": {},
            "success": False
        }
    
    async def run_all_agents_with_separate_data(self, source: str, edr_data: Dict[str, Any], gnn_data: Dict[str, Any]) -> Dict[str, Any]:
        """Run all agents in parallel with separate data sources and apply dynamic weighting"""
        
        print(f"Supervisor Agent: Running parallel analysis for source '{source}'")
        print(f"EDR data keys: {list(edr_data.keys()) if isinstance(edr_data, dict) else 'Invalid EDR data'}")
        print(f"GNN data keys: {list(gnn_data.keys()) if isinstance(gnn_data, dict) else 'Invalid GNN data'}")
        
        # Run all agents in parallel with appropriate data
        tasks = [
            self.run_edr_agent(edr_data),
            self.run_gnn_agent(gnn_data),
            self.run_firewall_agent({"edr": edr_data, "gnn": gnn_data}),  # Pass both for context
            self.run_email_agent({"edr": edr_data, "gnn": gnn_data})      # Pass both for context
        ]
        
        # Execute all tasks concurrently
        agent_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results and handle any exceptions
        processed_results = []
        for result in agent_results:
            if isinstance(result, Exception):
                processed_results.append({
                    "agent": "Unknown",
                    "score": 0,
                    "verdict": "Error",
                    "message": f"Agent execution failed: {str(result)}",
                    "success": False
                })
            else:
                processed_results.append(result)
        
        # Extract scores and apply weighting logic
        agent_scores = {result["agent"]: result["score"] for result in processed_results}
        
        # GNN gets fixed 60% weight
        gnn_score = agent_scores.get("GNN", 0)
        gnn_weighted = gnn_score * 0.6
        
        # Apply dynamic weighting for remaining 40%
        non_gnn_agents = ["EDR", "Firewall", "Email"]
        non_gnn_scores = {agent: agent_scores.get(agent, 0) for agent in non_gnn_agents}
        
        # Determine how to distribute the 40%
        source_agent = self.source_mapping.get(source.lower())
        remaining_weighted = 0
        weighting_strategy = ""
        
        if source_agent and source_agent in non_gnn_scores and non_gnn_scores[source_agent] > 0:
            # Source maps to specific agent with non-zero score - give it full 40%
            remaining_weighted = non_gnn_scores[source_agent] * 0.4
            weighting_strategy = f"Source-specific: {source_agent} gets 40%"
        else:
            # Distribute 40% proportionally among non-zero scoring agents
            non_zero_agents = {k: v for k, v in non_gnn_scores.items() if v > 0}
            
            if non_zero_agents:
                total_non_zero = sum(non_zero_agents.values())
                for agent, score in non_zero_agents.items():
                    weight = (score / total_non_zero) * 0.4
                    remaining_weighted += score * weight
                weighting_strategy = f"Proportional among {list(non_zero_agents.keys())}"
            else:
                # Fallback to EDR for predictable weighting
                remaining_weighted = non_gnn_scores["EDR"] * 0.4
                weighting_strategy = "Fallback: EDR gets 40% (all agents scored 0)"
        
        # Calculate final consolidated score
        consolidated_score = gnn_weighted + remaining_weighted
        
        # Determine final decision
        if consolidated_score >= 80:
            final_decision = "True Positive"
        elif consolidated_score >= 50:
            final_decision = "Escalate"
        else:
            final_decision = "False Positive"
        
        # Build comprehensive response in the requested format
        return {
            "prediction": {
                "predicted_verdict": final_decision,
                "confidence": round(consolidated_score / 100.0, 4),
                "consolidated_score": round(consolidated_score, 2),
                "probabilities": {
                    "false_positive": round((100 - consolidated_score) / 100.0, 4) if final_decision != "False Positive" else round(consolidated_score / 100.0, 4),
                    "escalate": 0.5 if final_decision == "Escalate" else round(abs(consolidated_score - 50) / 100.0, 4),
                    "true_positive": round(consolidated_score / 100.0, 4) if final_decision == "True Positive" else round((100 - consolidated_score) / 100.0, 4)
                }
            },
            "metadata": {
                "supervisor_analysis": {
                    "source": source,
                    "final_decision": final_decision,
                    "consolidated_score": round(consolidated_score, 2),
                    "weighting_applied": {
                        "gnn_weight": "60% (fixed)",
                        "remaining_weight": "40% (dynamic)",
                        "strategy": weighting_strategy
                    }
                },
                "agent_results": processed_results,
                "score_breakdown": {
                    "gnn_raw": gnn_score,
                    "gnn_weighted": round(gnn_weighted, 2),
                    "non_gnn_raw": non_gnn_scores,
                    "non_gnn_weighted": round(remaining_weighted, 2),
                    "final_consolidated": round(consolidated_score, 2)
                },
                "actionable_messages": [
                    result["message"] for result in processed_results if result.get("success", False)
                ],
                "data_sources": {
                    "edr_data_keys": list(edr_data.keys()) if isinstance(edr_data, dict) else "Invalid",
                    "gnn_data_keys": list(gnn_data.keys()) if isinstance(gnn_data, dict) else "Invalid"
                },
                "agent_agreement_analysis": self._analyze_agent_agreement(processed_results),
                "timestamp": datetime.utcnow().isoformat(),
                "execution_summary": {
                    "total_agents": len(processed_results),
                    "successful_agents": sum(1 for r in processed_results if r.get("success", False)),
                    "failed_agents": sum(1 for r in processed_results if not r.get("success", True))
                }
            }
        }
    
    def _analyze_agent_agreement(self, agent_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze agreement/disagreement between agents"""
        
        successful_agents = [r for r in agent_results if r.get("success", False) and r["agent"] in ["EDR", "GNN"]]
        
        if len(successful_agents) < 2:
            return {
                "agreement_status": "insufficient_data",
                "description": f"Only {len(successful_agents)} agents provided successful results",
                "consensus": "none"
            }
        
        # Extract verdicts from successful agents
        verdicts = [agent["verdict"] for agent in successful_agents]
        unique_verdicts = set(verdicts)
        
        if len(unique_verdicts) == 1:
            consensus_verdict = verdicts[0]
            return {
                "agreement_status": "full_agreement",
                "description": f"All {len(successful_agents)} agents agree on {consensus_verdict}",
                "consensus": consensus_verdict,
                "agreeing_agents": [agent["agent"] for agent in successful_agents]
            }
        elif len(unique_verdicts) == 2:
            agent_verdicts = {agent["agent"]: agent["verdict"] for agent in successful_agents}
            return {
                "agreement_status": "partial_disagreement", 
                "description": f"Agents disagree: {agent_verdicts}",
                "consensus": "mixed",
                "disagreement_details": agent_verdicts
            }
        else:
            agent_verdicts = {agent["agent"]: agent["verdict"] for agent in successful_agents}
            return {
                "agreement_status": "full_disagreement",
                "description": f"All agents disagree: {agent_verdicts}",
                "consensus": "none",
                "disagreement_details": agent_verdicts
            }

# Initialize supervisor agent
supervisor_agent = SupervisorAgent()

@app.post("/supervisor-agent")
async def run_supervisor_agent(
    source: str,
    alert_data: UploadFile = File(...),
    gnn_data: UploadFile = File(...)
):
    """
    Supervisor Agent: Orchestrates parallel sub-agents with dynamic weighting
    
    - source: Query parameter indicating the alert source (edr, firewall, email, etc.)
    - alert_data: JSON file for EDR agent analysis
    - gnn_data: JSON file for GNN agent analysis
    
    Behavior:
    - Runs EDR, Firewall, Email, and GNN agents in parallel
    - GNN gets fixed 60% weight
    - Remaining 40% distributed based on source and agent scores
    - Returns consolidated analysis with actionable messages
    """
    try:
        if not source:
            raise HTTPException(status_code=400, detail="Source query parameter is required")
        
        if not alert_data.filename.endswith(".json"):
            raise HTTPException(status_code=400, detail="alert_data must be a JSON file")
        
        if not gnn_data.filename.endswith(".json"):
            raise HTTPException(status_code=400, detail="gnn_data must be a JSON file")
        
        # Parse the uploaded JSON files
        alert_content = await alert_data.read()
        gnn_content = await gnn_data.read()
        
        try:
            edr_json = json.loads(alert_content.decode("utf-8"))
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="Invalid JSON format in alert_data file")
        
        try:
            gnn_json = json.loads(gnn_content.decode("utf-8"))
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="Invalid JSON format in gnn_data file")
        
        print(f"Supervisor Agent: Processing alert from source '{source}'")
        print(f"EDR data from file: {alert_data.filename}")
        print(f"GNN data from file: {gnn_data.filename}")
        print(f"EDR data keys: {list(edr_json.keys()) if isinstance(edr_json, dict) else 'Not a dict'}")
        print(f"GNN data keys: {list(gnn_json.keys()) if isinstance(gnn_json, dict) else 'Not a dict'}")
        
        # Run supervisor analysis with separate data for each agent
        result = await supervisor_agent.run_all_agents_with_separate_data(source, edr_json, gnn_json)
        
        return JSONResponse(content=result)
        
    except Exception as e:
        print(f"Supervisor Agent Error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Supervisor agent failed: {str(e)}")
    
@app.on_event("shutdown")
def shutdown_event():
    """Cleanup on shutdown"""
    if neo4j_driver:
        neo4j_driver.close()

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    neo4j_status = False
    if neo4j_driver:
        try:
            neo4j_driver.verify_connectivity()
            neo4j_status = True
        except Exception:
            neo4j_status = False
    
    return {
        "status": "healthy",
        "neo4j_connected": neo4j_status,
        "openai_configured": OPENAI_API_KEY is not None,
        "graph_manager_ready": graph_manager is not None,
        "threat_analyzer_ready": threat_analyzer is not None,
        "timestamp": datetime.now().isoformat()
    }


if __name__ == "__main__":
    uvicorn.run("app_final:app", host="0.0.0.0", port=2000, reload=True)