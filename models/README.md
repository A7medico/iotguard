# IoTGuard Models

Artifacts
- `lightgbm.joblib`: current trained model (binary or multiclass).
- `classes.json` (optional): present when the model is multiclass.
  - `classes`: array of class names (lowercase strings)
  - `benign_index`: index of the class considered benign

How it’s used
- Decision loop computes attack score as:
  - Binary: `P(attack)` from `predict_proba[:,1]`
  - Multiclass: `1 - P(benign)` using `benign_index`

Updating the model
1. Prepare `data/iotguard_training.csv` with columns: features + `label`.
2. Run `scripts/train_supervised.py`.
3. Restart the decision loop to load the new model.





