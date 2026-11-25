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
| **RQ2** | PE Region Attribution & Benchmark Interpretability | Kiểm toán vùng thông tin ảnh hưởng đến dự đoán và ý nghĩa đối với độ tin cậy benchmark |
| **RQ3** | Frequency-Based Active/Latent Loss Reweighting | Kiểm tra tác động của việc điều chỉnh loss theo tỷ lệ Active/Latent thực tế |

**Đóng góp chính:** Xây dựng benchmark có manifest, chia dữ liệu kiểm soát leakage, baseline MalConv/MalConv2, giao thức PE-region attribution và kết quả tái lập kèm độ bất định thống kê. Ba trục là **Data Reliability (RQ1), Model Interpretability (RQ2), Learning Strategy (RQ3)**; không đề xuất kiến trúc hay phương pháp IG mới.

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

RQ2 performance/attribution audit; RQ3 final evaluation

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

## **RQ2 — PE Region Attribution & Benchmark Interpretability**

**Research Question**

*Do MalConv and MalConv2 rely on different PE regions when detecting ransomware, and what do these differences reveal about the reliability of benchmark results?*

**Câu hỏi nghiên cứu:** Các mô hình phát hiện ransomware dựa trên những vùng thông tin nào của PE, và sự phụ thuộc đó ảnh hưởng như thế nào đến cách diễn giải tính đáng tin cậy của kết quả benchmark?

**Mục tiêu:** Kiểm toán vùng PE ảnh hưởng đến dự đoán và xem bảng F1 có che khuất khác biệt attribution giữa hai mô hình hay không. Tầng explainability mô tả attribution; tầng benchmark reliability đối chiếu attribution với hiệu suất, agreement và lỗi. **E2.3/E2.4 là trọng tâm**, không chỉ vẽ heatmaps vài file.

**Dataset:** D1 — Active:Latent:Benign = 1:1:2.

**Evaluation:** Held-out test 20%, tách biệt với RQ1.

### **Experimental Setup**

1. Huấn luyện MalConv/MalConv2 với Standard BCE trên D1 development.
2. Dùng 10-fold trên development để xác định Mean Best Epoch.
3. Full train trên D1 development.
4. Chạy inference trên held-out D1 test.
5. Lưu scores, labels, sample IDs, correctness và byte-coverage map của từng model.
6. Tính **Integrated Gradients (IG) trong không gian embedding**, ánh xạ về bytes/vùng PE; không nội suy integer token IDs.
7. Phân tích toàn bộ held-out nếu khả thi. Nếu cần subset vì chi phí, chốt trước sampling đại diện theo Active/Latent/benign, similarity groups và kích thước; dùng cùng sample IDs giữa hai model, báo coverage/failures, không chỉ chọn ví dụ đẹp.
8. Giữ checkpoint/threshold cố định. Không tune model/loss/protocol RQ3 bằng attribution held-out rồi gọi lại cùng held-out là đánh giá độc lập.

### **Experiments**

| ID | Experiment | Phương pháp thực hiện |
| --- | --- | --- |
| **E2.1** | **Region Attribution Mapping** | Tính IG, ánh xạ vào Header, Executable, Non-executable, Overlay theo contract chung. |
| **E2.2** | **Attribution Concentration** | So tỷ trọng attribution với tỷ trọng bytes thực sự được xử lý; kiểm tra vùng nhỏ có attribution tập trung cao không. |
| **E2.3** | **Cross-Model Attribution Agreement** | So region profiles trên cùng PE files; báo paired differences/agreement theo metric chốt trước, đối chiếu với performance. |
| **E2.4** | **Attribution vs Prediction Errors** | So attribution giữa đúng/sai, riêng Active/Latent và benign, TP/FN/FP/TN; xét similarity groups và kích thước file. |

### **Region Mapping & Normalization**

| Region | Phạm vi cần xác định bằng PE parser |
| --- | --- |
| Header | DOS/PE/optional/section-table headers và header padding theo contract |
| Executable | Raw section ranges có executable/code flags theo contract |
| Non-executable | Raw section ranges còn lại |
| Overlay | Bytes sau phần ảnh PE lưu trên đĩa, theo định nghĩa overlay đã chốt |

Mapping phải chốt precedence cho overlap, clipping, section gaps, certificate table và malformed ranges. Bốn vùng không mặc định phủ hết file: giữ **unmapped** riêng, không đếm byte hai lần. Lưu parser identity, ranges và input digest; không sửa PE để tính attribution.

Mẫu số byte chỉ gồm bytes **thực sự được model xử lý**, không dùng toàn PE nếu truncation/tail/chunk làm thiếu coverage. Padding tách riêng. Báo coverage từng model; agreement cần cùng vùng được bao phủ hoặc công bố rõ khác biệt coverage.

Phân biệt **signed attribution** (hướng đóng góp vào target score) và **absolute attribution mass** (độ lớn). Concentration có thể là tỷ trọng absolute attribution chia tỷ trọng bytes được xử lý; công thức cuối cần chốt trước. Vùng rỗng hoặc tổng attribution bằng 0 ghi undefined, không thay bằng 0. Báo phân bố theo mẫu/nhóm, không chỉ tổng corpus thiên về file dài.

### **Attribution Validity & Stability**

- Chốt target score dùng chung, baseline embedding/reference và cách gộp embedding dimensions về bytes. PAD/zero embedding cần kiểm tra; không mặc định là PE trung tính/hợp lệ.
- Kiểm tra sensitivity theo baseline và số bước tích phân; lưu convergence/completeness residual, failures, runtime/memory. Chốt tolerances bằng development/synthetic fixtures trước held-out.
- Với low-memory MalConv2, kiểm tra `no_grad`, chunk selection/max pooling và recomputation: gradient đủ để train không tự bảo đảm IG đúng. Đối chiếu reference khả vi trên input tổng hợp nhỏ, xác minh logits tương đương; chưa qua gate này thì chưa công bố IG như kết quả hợp lệ.
- Báo paired uncertainty/95% CI có xét similarity groups; định nghĩa agreement/resampling trước khi xem kết quả held-out.
- F1 tương đương nhưng attribution khác nhau là thông tin bổ sung, **không tự chứng minh shortcut, nhân quả hoặc học đúng ngữ nghĩa ransomware**. Error associations không phải causal effects.
- RQ2 này **thay thế** test-size sensitivity cũ; bỏ thiết kế 25/50/75/100% ×200 subsamples. 95% CI và giới hạn ước lượng FPR hiếm vẫn thuộc đánh giá metrics chung.

### **Expected Outcomes**

- Giao thức PE-region attribution tái lập, fixed manifest và byte-coverage maps.
- Region profiles và concentration so với byte proportions.
- Cross-model agreement/differences, kể cả khi performance tương đương.
- Attribution patterns liên quan đến lỗi và Active/Latent/benign.
- Stability, convergence, coverage và failure accounting.
- Diễn giải bổ sung cho benchmark, không tuyên bố phát minh IG hoặc chứng minh shortcut.

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
6. **Phase 6 — RQ2 PE-Region Attribution Audit**

   Với checkpoints/predictions cố định, chạy IG mapping, concentration, cross-model agreement và error analysis; kiểm tra baseline/step stability và gradient validity, không train lại cho từng attribution analysis.

   Output: Region profiles/concentration, paired agreement, error analysis, stability và 95% CI có xét groups.
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
| RQ2 Standard BCE checkpoints/predictions | IG và error analyses; không tự động dùng làm RQ3 baseline vì training D1/D2 khác nhau |
| Metrics code | RQ1, RQ2, RQ3 |

# **6. Proposed Paper Structure**

| Section | Nội dung |
| --- | --- |
| **1. Introduction** | Motivation, research gaps, objectives, contributions, RQs |
| **2. Related Work** | Ransomware detection, raw-byte malware classification, duplication/leakage, benchmark reliability |
| **3. Benchmark Construction** | VERA/Assemblage, preprocessing, dedup, D1/D2, group-disjoint partition |
| **4. Experimental Methodology** | MalConv/MalConv2, 10-fold CV, checkpoint selection, loss weighting, metrics |
| **5.1. RQ1 — Duplication & Leakage** | Exact/near-duplicate audit, P1/P2/P3 comparison, controlled leakage |
| **5.2. RQ2 — Benchmark Interpretability** | PE-region attribution, concentration, cross-model agreement, error analysis và stability |
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
| Figure 4 | Region attribution và concentration so với byte proportions | E2.1/E2.2 |
| Figure 5 | Cross-model agreement và attribution theo đúng/sai, Active/Latent/benign; kèm stability/CI | E2.3/E2.4 |
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
- **RQ2:** Dùng held-out 20% để kiểm toán PE-region attribution và benchmark interpretability; IG settings/coverage/gradient validity phải được xác minh trước.
- **RQ3:** Train trên development, đánh giá trên cùng held-out 20%.
- **Training:** MalConv/MalConv2 from scratch; maximum 100 epochs; early stopping patience 3, min_delta 0.001; final training theo Mean Best Epoch.

### **Điểm cần xác minh trước khi chạy**

Số file trước/sau whole-file dedup, số nhóm độc lập P3, cân bằng folds, near-duplicate verification, giới hạn/tail coverage của model; region mapping, IG baseline/target/steps/convergence, gradient validity của low-memory implementation và chi phí attribution. Đây là các gate triển khai cần xác minh, không phải khẳng định tool đã sẵn sàng.

**Thứ tự tổng thể:** Preprocessing → Whole-file dedup → Executable/TLSH audit → 80/20 split → RQ1 → RQ2 → RQ3 → Benchmark package.

Đây là bản sườn theo cấu hình mới, trong đó **deduplication và disjoint splitting đã được tách rõ**, ba RQ có dataset riêng phù hợp mục tiêu nhưng không phải giữ thêm các test sets độc lập không cần thiết.
