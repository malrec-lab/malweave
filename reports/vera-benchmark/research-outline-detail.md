# **Research Outline**

Phiên bản cập nhật theo cấu hình đã chốt — Research Questions, Experimental Design và Execution Order

## **A Reliability-Aware Benchmark for Static Ransomware Detection Using VERA**

**Tên tiếng Việt:** Xây dựng benchmark có kiểm soát độ tin cậy cho phát hiện mã độc tống tiền bằng phân tích tĩnh sử dụng VERA.

## **1. Research Objective**

Xây dựng một benchmark có thể tái lập cho bài toán phân loại **Ransomware vs Benign** trên Windows PE, sử dụng raw bytes của toàn bộ tệp làm đầu vào cho MalConv và MalConv2.

Nghiên cứu tập trung vào ba câu hỏi:

| RQ | Research Question | Mục tiêu |
| --- | --- | --- |
| **RQ1** | Whole-File & Executable-Code Duplication and Leakage | Đánh giá ảnh hưởng của các mức kiểm soát trùng lặp đến kết quả benchmark |
| **RQ2** | Evaluation-Set Sufficiency & Statistical Reliability | Đánh giá độ ổn định thống kê của kết quả theo quy mô tập test |
| **RQ3** | Frequency-Based Active/Latent Loss Reweighting | Kiểm tra tác động của việc điều chỉnh loss theo tỷ lệ Active/Latent thực tế |

**Đóng góp chính:** Xây dựng benchmark có manifest, giao thức chia dữ liệu kiểm soát leakage, baseline MalConv/MalConv2, phương pháp đánh giá thống kê và kết quả có thể tái lập.

## **2. Dataset & Experimental Configuration**

### **2.1. Dataset**

| Dataset | Vai trò | Số nhóm đầu vào unique đã thống kê |
| --- | --- | --- |
| VERA-Active | Ransomware | 6.205 |
| VERA-Latent | Ransomware | 4.295 |
| Assemblage | Benign | 30.524 |
| **Tổng** | | **41.024** |

Các số liệu trên là số nhóm unique bạn đã thống kê, chưa mặc định bằng số file thực tế còn lại trong master manifest.

### **2.2. Dataset Configurations**

| Cấu hình | Active : Latent | Ransomware : Benign | Sử dụng |
| --- | --- | --- | --- |
| **D1 — Balanced Dataset** | 1:1 | 1:1 | RQ1, RQ2 |
| **D2 — Natural-Imbalance Dataset** | Tỷ lệ thực tế sau lọc | 1:1 | RQ3 |

- **D1:** Lấy số lượng Active và Latent bằng nhau, bổ sung benign bằng tổng ransomware.
- **D2:** Giữ toàn bộ Active và Latent đủ điều kiện trong development, bổ sung benign để cân bằng hai class chính.
- Held-out test giữ phân bố Active:Latent:Benign = **1:1:2**, sử dụng cho RQ2 và đánh giá cuối RQ3.

### **2.3. Preprocessing & Duplication Handling**

| Bước | Phương pháp | Cách xử lý |
| --- | --- | --- |
| PE validation | Kiểm tra định dạng Windows PE | Loại file không hợp lệ |
| Packed detection | Detect It Easy (DiE) | Lọc các file được xác định là packed |
| **Exact whole-file dedup** | SHA-256 trên toàn bộ PE | **Xóa duplicates, mỗi hash giữ một file** |
| Executable exact analysis | SHA-256 trên executable sections | Chỉ tạo nhóm, không xóa |
| Whole-file near-duplicate | TLSH trên toàn PE | Chỉ tạo nhóm tương đồng, không xóa |
| Executable near-duplicate | TLSH trên executable sections | Chỉ tạo nhóm tương đồng, không xóa |
| Model input | Whole-file raw PE bytes | MalConv/MalConv2 |

**Quy tắc đã chốt:**

- Chỉ thực sự dedup bằng **whole-file SHA-256**.
- Executable SHA-256 dùng để tạo exact-code groups.
- Whole-file TLSH và executable TLSH dùng để phát hiện và xác minh near-duplicate groups.
- Không xóa thêm mẫu ở P2/P3; chỉ thay đổi cách phân chia fold.

Cần lưu cả thống kê trước và sau whole-file dedup để phục vụ RQ1.

### **2.4. Data Partition**

**Whole-File SHA-256 Deduplicated Dataset**

Master manifest, executable hashes và similarity groups

# **80%**

**Development Pool**

RQ1 10-fold; baseline training; RQ3 training

# **20%**

**Held-Out Test Pool**

RQ2 statistical evaluation; RQ3 final evaluation

Chia development/held-out theo similarity groups mức P3, để ngăn cross-partition leakage.

**Quan trọng:**

- RQ1 chỉ chạy trên 80% development.
- RQ2 sử dụng 20% held-out test.
- RQ3 training trên 80% development và đánh giá trên held-out test.
- Không tạo thêm test set độc lập cho từng RQ.

### **2.5. Model & Training Configuration**

| Thành phần | Cấu hình |
| --- | --- |
| Models | MalConv, MalConv2 (MalConvGCT) |
| Input | Whole-file raw PE bytes |
| Training | From scratch |
| Cross-validation | 10-fold |
| Max epochs | 100 |
| Early stopping monitor | Unweighted validation BCE loss |
| Patience | 3 |
| Min delta | 0.001 |
| Epoch selection | Mean Best Epoch từ 10 validation folds |
| Full training | Train lại từ đầu trên development theo Mean Epoch |
| Primary metrics | F1, Recall, FPR, AUROC |
| Additional metrics | Precision, Recall Active/Latent, 95% confidence intervals |

Với RQ1, các test folds dùng để đánh giá protocol không được đồng thời làm validation chọn epoch. Việc chọn epoch phải diễn ra trên training portion của từng lượt đánh giá.

Đối với final training của RQ2/RQ3, dùng 10-fold trên development để xác định Mean Best Epoch trước khi huấn luyện toàn bộ development.

# **3. Research Questions & Experimental Design**

## **RQ1 — Whole-File & Executable-Code Duplication and Leakage**

**Research Question**

*To what extent do executable-code duplication and near-duplication, beyond whole-file exact duplication, affect leakage and evaluation reliability in raw-byte ransomware detection?*

**Câu hỏi nghiên cứu:** Sau khi loại trùng hoàn toàn ở cấp PE, việc kiểm soát thêm executable-code duplicates và near-duplicates ảnh hưởng như thế nào đến data leakage và độ tin cậy của kết quả đánh giá?

**Mục tiêu:** Xác định các quan hệ trùng lặp mà whole-file hashing bỏ sót; đo mức leakage còn tồn tại giữa các folds; đánh giá ảnh hưởng của các mức kiểm soát leakage đến MalConv và MalConv2.

**Dataset:** D1 — Active:Latent = 1:1, Ransomware:Benign = 1:1.

**Input:** Whole-file raw PE bytes.

**Evaluation:** 10-fold trên development 80%, không sử dụng held-out test.

### **Experiments**

| ID | Experiment | Phương pháp thực hiện |
| --- | --- | --- |
| **E1.1** | **Exact Duplication Audit** | Thống kê whole-file SHA-256 duplicates đã loại; tính executable SHA-256 trên các file còn lại để xác định những trường hợp file khác nhau nhưng executable giống nhau. |
| **E1.2** | **Near-Duplicate Analysis** | Tính TLSH trên whole-file và executable bytes, hiệu chuẩn ngưỡng similarity, kiểm tra các cặp tương đồng và xác định similarity groups. |
| **E1.3** | **Cross-Fold Leakage Measurement** | Tạo P1/P2/P3 trên cùng D1 development; đo tỷ lệ executable-exact và near-duplicate overlap giữa train/test của từng fold. |
| **E1.4** | **Leakage-Control Protocol Comparison** | Train MalConv/MalConv2 trên whole-file raw bytes; đánh giá F1, Recall, FPR, AUROC giữa P1/P2/P3. |
| **E1.5** | **Controlled Leakage Impact** | Trên development, sử dụng cùng evaluation samples và các training sets đối chứng có quy mô tương đương để kiểm tra tác động của việc xuất hiện executable tương đồng trong training. |

### **E1.4 — Three Leakage-Control Protocols**

| Protocol | Quy tắc chia 10-fold | Kiểm soát leakage |
| --- | --- | --- |
| **P1 — Whole-File Exact Baseline** | Stratified 10-Fold trên dữ liệu đã whole-file dedup | Đã loại whole-file exact duplicates; chưa kiểm soát executable overlap |
| **P2 — Executable Exact Disjoint** | Stratified Group 10-Fold theo executable SHA-256 | Ngăn executable exact duplicates đi qua các folds |
| **P3 — Near-Duplicate Disjoint** | Stratified Group 10-Fold theo executable SHA-256 và similarity groups xác minh từ whole-file/executable TLSH | Kiểm soát thêm near-duplicates |

**Cả ba protocol sử dụng cùng bộ file D1**. Không xóa thêm file trong P2 hoặc P3.

### **E1.5 — Controlled Leakage Impact**

**Mục tiêu:** Kiểm tra tác động của leakage trực tiếp, hạn chế nhiễu do sự khác nhau của test folds trong E1.4.

Quy trình:

1. Xác định các evaluation samples có counterpart executable-exact hoặc near-duplicate trong development.
2. Giữ cố định evaluation samples giữa hai điều kiện.
3. **Clean condition:** Training không chứa counterpart tương đồng.
4. **Leaky condition:** Training chứa counterpart tương đồng với evaluation samples.
5. Giữ số lượng training samples và tỷ lệ nhãn tương đương bằng cách thay thế mẫu phù hợp.
6. Train MalConv/MalConv2 và so sánh kết quả.

Không sử dụng held-out test 20%. Chỉ dùng các cặp tương đồng thực sự tồn tại trong dữ liệu.

### **Expected Outcomes**

- Whole-file exact duplicate statistics.
- Số trường hợp executable exact duplicate mà whole-file dedup bỏ sót.
- Whole-file/executable near-duplicate statistics.
- Cross-fold leakage rate dưới P1/P2/P3.
- Chênh lệch hiệu suất MalConv/MalConv2 giữa các protocol.
- Controlled leakage impact trên cùng evaluation samples.
- Giao thức chia dữ liệu chống leakage cho benchmark.

## **RQ2 — Evaluation-Set Sufficiency & Statistical Reliability**

**Research Question**

*How does evaluation-set size affect the statistical reliability and reproducibility of performance estimates in a VERA-based ransomware detection benchmark?*

**Câu hỏi nghiên cứu:** Quy mô tập test ảnh hưởng như thế nào đến độ ổn định và độ chính xác thống kê của kết quả benchmark?

**Mục tiêu:** Kiểm tra độ tin cậy của held-out test 20% và xây dựng giao thức đánh giá thống kê có thể tái lập.

**Dataset:** D1 — Active:Latent:Benign = 1:1:2.

**Evaluation:** Held-out test 20%, tách biệt với RQ1.

### **Experimental Setup**

1. Huấn luyện MalConv/MalConv2 với Standard BCE trên D1 development.
2. Dùng 10-fold trên development để xác định Mean Best Epoch.
3. Full train trên D1 development.
4. Chạy inference trên held-out D1 test.
5. Lưu prediction scores và labels.
6. Tái sử dụng prediction records để phân tích statistical reliability theo test size.

### **Experiments**

| ID | Experiment | Phương pháp thực hiện |
| --- | --- | --- |
| **E2.1** | **Test-Set Size Sensitivity** | Lấy mẫu từ held-out test ở các mức 25%, 50%, 75%, 100%, giữ tỷ lệ Active/Latent/Benign và lặp lại 200 lần ở các mức có nhiều tập con khác nhau. |
| **E2.2** | **Metric Variability** | Tính độ phân tán F1, Recall, FPR, AUROC theo từng test size. |
| **E2.3** | **Model Ranking Stability** | Dùng paired predictions để đánh giá độ ổn định của thứ hạng MalConv/MalConv2 khi thay đổi số mẫu test. |
| **E2.4** | **Statistical Precision & Benchmark Specification** | Tính confidence intervals 95%, báo cáo độ chính xác đạt được và cố định evaluation protocol. |

### **Evaluation Size**

| Level | Held-out test proportion |
| --- | --- |
| S1 | 25% |
| S2 | 50% |
| S3 | 75% |
| S4 | 100% |

Các tập con phải giữ đúng sample identity giữa hai mô hình để thực hiện paired comparison.

Tại mức 100%, chỉ có một full test set. Việc lấy mẫu lặp lại ở các mức nhỏ hơn không tạo ra những test sets độc lập mới.

### **Expected Outcomes**

- Metric variability theo quy mô test.
- Confidence interval widths.
- MalConv/MalConv2 ranking stability.
- Độ tin cậy thống kê thực tế của held-out benchmark.
- Fixed test manifest và evaluation protocol.

## **RQ3 — Frequency-Based Active/Latent Loss Reweighting**

**Research Question**

*Does inverse-frequency loss weighting improve ransomware detection compared with standard BCE when VERA-Active and VERA-Latent have unequal sample counts?*

**Câu hỏi nghiên cứu:** Điều chỉnh loss theo tỷ lệ mất cân bằng thực tế giữa VERA-Active và VERA-Latent có cải thiện khả năng phát hiện ransomware so với Standard BCE không?

**Mục tiêu:** Kiểm tra ảnh hưởng của inverse-frequency weighting trong điều kiện training giữ phân bố Active/Latent tự nhiên.

**Dataset:** D2 — Active/Latent giữ tỷ lệ thực tế; tổng Ransomware:Benign = 1:1.

**Evaluation:** Held-out D1 test 20%, giữ Active:Latent:Benign = 1:1:2.

### **Loss Configurations**

| Configuration | Active | Latent | Benign |
| --- | --- | --- | --- |
| **W0 — Standard BCE** | 1 | 1 | 1 |
| **W1 — Frequency-Weighted BCE** | \(w_A\) | \(w_L\) | 1 |

Trong đó:

\[ w_A=\frac{N_A+N_L}{2N_A} \]

\[ w_L=\frac{N_A+N_L}{2N_L} \]

\(N_A,N_L\) được tính từ training partition, không sử dụng nhãn validation/test để tính trọng số.

### **Experiments**

| ID | Experiment | Phương pháp thực hiện |
| --- | --- | --- |
| **E3.1** | **Standard BCE Baseline** | Train MalConv/MalConv2 trên D2 với BCE không trọng số. |
| **E3.2** | **Frequency-Weighted BCE** | Train trên cùng D2, chỉ thay đổi loss weights theo phân bố Active/Latent. |
| **E3.3** | **Performance & Trade-off Analysis** | So sánh W0/W1 trên cùng held-out D1 test; báo cáo F1, Recall, FPR, AUROC, Recall Active/Latent và Recall Gap. |

### **Training Protocol**

- Giữ giống nhau model input, optimizer, data partitions và hyperparameters giữa W0/W1.
- Sử dụng 10-fold trên D2 development để chọn Mean Best Epoch.
- Max 100 epochs, early stopping theo unweighted validation BCE, patience = 3, min_delta = 0.001.
- Full train trên D2 development theo Mean Best Epoch riêng của từng cấu hình.
- Đánh giá trên cùng held-out test 20%.

### **Expected Outcomes**

- Thay đổi Recall Active và Recall Latent.
- Thay đổi F1, FPR và AUROC.
- Mức đánh đổi giữa hiệu suất nhóm ít mẫu và toàn bộ ransomware.
- Kết luận về lợi ích hoặc giới hạn của frequency-weighted BCE.

# **4. Experimental Execution Order**

Đây là **thứ tự chạy thực tế** nhằm tránh duplicate effort.

1. **Phase 1 — Dataset Collection & Preprocessing**

   Kiểm tra PE, lọc packed bằng DiE, tạo raw PE dataset; tính whole-file SHA-256, dedup và lưu manifest trước/sau lọc.

   Output: Whole-file deduplicated dataset và master manifest.
2. **Phase 2 — Executable & Near-Duplicate Analysis**

   Trích xuất executable bytes phục vụ tính hash, TLSH trên whole-file/executable; kiểm tra ngưỡng và xác định similarity groups.

   Output: E1.1/E1.2 statistics, exact-code groups, near-duplicate groups.
3. **Phase 3 — Benchmark Partition & Dataset Sampling**

   Tạo 80/20 group-disjoint theo P3 từ dữ liệu hợp lệ; tạo D1 và D2 theo đúng tỷ lệ từng RQ. Lưu toàn bộ sample IDs.

   Output: Development/held-out manifest, D1/D2 configurations.
4. **Phase 4 — RQ1 Leakage Experiments**

   Trên D1 development, tạo P1/P2/P3 folds; đo leakage và chạy E1.3–E1.5.

   Output: Cross-fold leakage rates, protocol comparison và controlled leakage impact.
5. **Phase 5 — RQ2 Baseline Training**

   Huấn luyện MalConv/MalConv2 Standard BCE trên D1 development, chọn Mean Best Epoch qua 10-fold; full train và lưu prediction scores trên held-out test.

   Output: Official baseline checkpoints và held-out prediction records.
6. **Phase 6 — RQ2 Statistical Evaluation**

   Từ predictions đã lưu, chạy E2.1–E2.4 và xây dựng benchmark statistical reporting protocol.

   Output: Test-size sensitivity, 95% CI, ranking stability.
7. **Phase 7 — RQ3 Weighted-Loss Experiments**

   Train W0/W1 trên D2 development; dùng held-out D1 test để đánh giá, báo cáo group recall và performance trade-offs.

   Output: Standard vs weighted BCE comparison.
8. **Phase 8 — Benchmark Packaging**

   Tổng hợp data manifests, fold IDs, preprocessing, evaluation scripts, training configs, baselines và statistical results.

   Output: Reproducible benchmark package.

## **5. Result Reuse — Tránh Duplicate Effort**

| Thành phần | Sử dụng lại |
| --- | --- |
| Whole-file dedup manifest | RQ1/RQ2/RQ3 |
| Executable SHA-256 | RQ1, split construction |
| Whole-file/executable TLSH | RQ1, split construction |
| P3 similarity groups | 80/20 partition, RQ1 P3, benchmark validation |
| D1 development | RQ1, RQ2 training |
| D1 held-out test | RQ2 và RQ3 evaluation |
| RQ2 Standard BCE predictions | RQ2 analyses; không tự động dùng làm RQ3 baseline vì training D1/D2 khác nhau |
| Metrics code | RQ1, RQ2, RQ3 |

# **6. Proposed Paper Structure**

| Section | Nội dung |
| --- | --- |
| **1. Introduction** | Motivation, research gaps, objectives, contributions, RQs |
| **2. Related Work** | Ransomware detection, raw-byte malware classification, duplication/leakage, benchmark reliability |
| **3. Benchmark Construction** | VERA/Assemblage, preprocessing, dedup, D1/D2, group-disjoint partition |
| **4. Experimental Methodology** | MalConv/MalConv2, 10-fold CV, checkpoint selection, loss weighting, metrics |
| **5.1. RQ1 — Duplication & Leakage** | Exact/near-duplicate audit, P1/P2/P3 comparison, controlled leakage |
| **5.2. RQ2 — Statistical Reliability** | Test-size sensitivity, statistical precision, ranking stability |
| **5.3. RQ3 — Loss Reweighting** | Standard vs frequency-weighted BCE, detection trade-offs |
| **6. Discussion & Limitations** | Leakage, representativeness, source-label confounding, input-length limitations |
| **7. Conclusion** | Benchmark contributions và kết luận |

## **7. Tables & Figures dự kiến**

| Figure/Table | Nội dung | Experiment |
| --- | --- | --- |
| Figure 1 | Dataset & benchmark construction pipeline | Phase 1–3 |
| Table 1 | Dataset composition before/after filtering; D1/D2 | Phase 1–3 |
| Table 2 | Whole-file/executable exact and near-duplicate statistics | E1.1/E1.2 |
| Figure 2 | Cross-fold overlap/leakage dưới P1/P2/P3 | E1.3 |
| Table 3 | MalConv/MalConv2 performance theo protocol | E1.4 |
| Figure 3 | Clean vs Leaky controlled comparison | E1.5 |
| Figure 4 | Test-size vs metric variability | E2.1/E2.2 |
| Figure 5 | Confidence interval width & ranking stability | E2.3/E2.4 |
| Table 4 | Standard BCE vs Frequency-Weighted BCE | E3.1–E3.3 |
| Figure 6 | Recall Active/Latent và FPR trade-offs | E3.3 |

## **8. Những quy tắc đã chốt**

- **2 class:** Ransomware và Benign.
- **3 nhóm dữ liệu:** VERA-Active, VERA-Latent, Assemblage Benign.
- **Model input:** Whole-file raw PE bytes.
- **Dedup:** Chỉ whole-file SHA-256.
- **Disjoint:** Executable SHA-256 (P2), thêm whole-file/executable TLSH (P3).
- **RQ1/RQ2:** Active:Latent = 1:1; Ransomware:Benign = 1:1.
- **RQ3:** Active/Latent theo tỷ lệ thực tế trong training; Ransomware:Benign = 1:1.
- **80/20:** Held-out test được phân chia theo P3 để bảo đảm group-disjoint.
- **RQ1:** Chỉ dùng 80% development với 10-fold.
- **RQ2:** Dùng held-out 20% để phân tích độ tin cậy thống kê.
- **RQ3:** Train trên development, đánh giá trên cùng held-out 20%.
- **Training:** MalConv/MalConv2 from scratch; maximum 100 epochs; early stopping patience 3, min_delta 0.001; final training theo Mean Best Epoch.

### **Điểm cần xác minh trước khi chạy**

Số file thực tế trước/sau whole-file SHA-256 dedup, số nhóm độc lập sau P3, mức cân bằng các folds, số cặp near-duplicate được xác minh và giới hạn xử lý raw PE dài của MalConv/MalConv2.

**Thứ tự tổng thể:** Preprocessing → Whole-file dedup → Executable/TLSH audit → 80/20 split → RQ1 → RQ2 → RQ3 → Benchmark package.

Đây là bản sườn theo cấu hình mới, trong đó **deduplication và disjoint splitting đã được tách rõ**, ba RQ có dataset riêng phù hợp mục tiêu nhưng không phải giữ thêm các test sets độc lập không cần thiết.
