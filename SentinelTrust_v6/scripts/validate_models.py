"""
Reproducible validation for the IsolationForest + LSTM Autoencoder pipeline.

Trains on sample_data/camera_baseline_large.csv (300 rows, synthetic but
grounded in the real 10-row baseline's mean/std), then scores two labeled
held-out sets:
  - sample_data/camera_test_normal_large.csv   (60 rows, all normal)
  - sample_data/camera_test_attack_large.csv   (60 rows: 20 normal + 40
    rows of a sustained Mirai-style ramp attack — packet_rate, unique
    dest IPs, new external connections, and TCP flag anomalies all spike
    and stay elevated)

Prints reliability of both trained models plus precision / recall / F1
against the attack test set's ground-truth labels, and the false-positive
count on the pure-normal test set. This is exactly what TrustEngine does
in production — same code path, not a mock.

Run from the backend/ directory:
    cd backend
    python3 ../scripts/validate_models.py

Note: IsolationForest uses a fixed random_state, so its results are
deterministic. LSTM training has some run-to-run variance from Keras/
TensorFlow weight initialization even with data held fixed — expect small
fluctuations in exact scores, not in the overall precision/recall story.
"""
import sys
import os
import csv
import shutil
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

import services.trust_engine as te

TEST_DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "backend", "user_data_validation")
SAMPLE_DIR = os.path.join(os.path.dirname(__file__), "..", "sample_data")


def read_csv(path):
    with open(path) as f:
        return [{k: float(v) for k, v in row.items()} for row in csv.DictReader(f)]


def main():
    shutil.rmtree(TEST_DATA_DIR, ignore_errors=True)
    te.DATA_DIR = TEST_DATA_DIR
    from services.trust_engine import TrustEngine

    baseline = read_csv(os.path.join(SAMPLE_DIR, "camera_baseline_large.csv"))
    test_normal = read_csv(os.path.join(SAMPLE_DIR, "camera_test_normal_large.csv"))
    test_attack = read_csv(os.path.join(SAMPLE_DIR, "camera_test_attack_large.csv"))

    engine = TrustEngine()
    user = "validation@example.com"

    engine.register_device(user, "cam_normal", "Validation Camera A", "ip_camera", "10.0.0.5")
    t0 = time.time()
    res = engine.train_baseline(user, "cam_normal", baseline)
    print(f"Trained on {len(baseline)} baseline rows in {time.time()-t0:.1f}s")
    print(f"  Isolation Forest: trained={res['isolation_forest']['trained']} "
          f"reliability={res['isolation_forest'].get('reliability')}")
    print(f"  LSTM Autoencoder: trained={res['lstm_autoencoder']['trained']} "
          f"reliability={res['lstm_autoencoder'].get('reliability')} "
          f"seq_len={res['lstm_autoencoder'].get('seq_len')}")

    fp = 0
    for row in test_normal:
        r = engine.score_test_data(user, "cam_normal", dict(row))
        if r["anomaly_detected"]:
            fp += 1
    print(f"\nPure-normal test set ({len(test_normal)} rows): "
          f"{fp} false positives ({fp/len(test_normal)*100:.1f}%)")

    engine.register_device(user, "cam_attack", "Validation Camera B", "ip_camera", "10.0.0.6")
    engine.train_baseline(user, "cam_attack", baseline)

    ground_truth = [False] * 20 + [True] * 40  # matches how camera_test_attack_large.csv was built
    preds = []
    for row in test_attack:
        r = engine.score_test_data(user, "cam_attack", dict(row))
        preds.append(r["anomaly_detected"])

    tp = sum(1 for gt, p in zip(ground_truth, preds) if gt and p)
    fp2 = sum(1 for gt, p in zip(ground_truth, preds) if not gt and p)
    fn = sum(1 for gt, p in zip(ground_truth, preds) if gt and not p)
    tn = sum(1 for gt, p in zip(ground_truth, preds) if not gt and not p)
    precision = tp / (tp + fp2) if (tp + fp2) else float("nan")
    recall = tp / (tp + fn) if (tp + fn) else float("nan")
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else float("nan")

    print(f"\nLabeled attack test set ({len(test_attack)} rows: 20 normal + 40 sustained attack):")
    print(f"  TP={tp} FP={fp2} FN={fn} TN={tn}")
    print(f"  precision={precision:.3f}  recall={recall:.3f}  f1={f1:.3f}")

    shutil.rmtree(TEST_DATA_DIR, ignore_errors=True)


if __name__ == "__main__":
    main()
