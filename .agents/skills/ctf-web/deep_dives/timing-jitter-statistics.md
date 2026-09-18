# Deep Dive: Timing Attack Jitter Mitigation & Statistical Filtering

## 1. Why Simple Timing Comparisons Fail
In remote CTFs, network jitter ($\sigma_{\text{network}} \approx 5\text{ms} - 30\text{ms}$) completely dominates server execution differences ($\Delta t_{\text{valid}} \approx 1\text{ms} - 5\text{ms}$).
Comparing raw numbers $T_1 > T_2$ produces **100% false positives**.

---

## 2. Statistical Solution: Interquartile Range (IQR) & Trimmed Median

```text
Raw Measurements: [15ms, 16ms, 14ms, 15ms, 95ms (Jitter spike), 15ms, 16ms]
                                               └── OMITTED by IQR / Trimmed Median
Filtered Measurement: 15.00ms
```

### Production Timing Scaffolding
```python
import time
import statistics
import requests

def measure_char_samples(target_func, candidate_payload: str, samples: int = 9) -> float:
    timings = []
    for _ in range(samples):
        t0 = time.perf_counter()
        target_func(candidate_payload)
        t1 = time.perf_counter()
        timings.append((t1 - t0) * 1000) # milliseconds

    # 1. Sort samples
    timings.sort()

    # 2. Interquartile Range (IQR) outlier rejection
    q1 = statistics.median(timings[:len(timings)//2])
    q3 = statistics.median(timings[(len(timings)+1)//2:])
    iqr = q3 - q1
    lower_bound = q1 - 1.5 * iqr
    upper_bound = q3 + 1.5 * iqr

    clean_samples = [t for t in timings if lower_bound <= t <= upper_bound]
    if not clean_samples:
        clean_samples = timings[1:-1] if len(timings) > 2 else timings

    # 3. Return robust median of clean samples
    return statistics.median(clean_samples)
```
