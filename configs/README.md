# IoTGuard Configs

- model.yaml
  - features: ordered feature names used by training/inference
  - lgbm: parameters for LightGBM training
  - decision:
    - threshold: score threshold for classifying ATTACK
    - grace: number of recent windows to require before BLOCK (burst policy)
    - window: sliding window size used by decision loop counters
    - cooldown_sec: min seconds between BLOCK actions
    - instant_block: score to trigger immediate BLOCK regardless of grace
    - dry_run: if true, do not change firewall rules
    - hook, windows_hook, linux_hook: OS hook selection

Hot-reload
- The decision loop watches model.yaml and applies changed values without restart.



