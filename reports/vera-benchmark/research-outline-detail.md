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
- **D2:** Trong mỗi outer lượt, giữ toàn bộ Active/Latent đủ điều kiện ngoài outer-test groups, bổ sung benign để cân bằng hai class chính; sau đó tách inner validation. Không ép Active/Latent 1:1.
- **Common evaluation:** RQ2/RQ3 dùng cùng D1 P3 outer-test IDs. D1 toàn tập có Active:Latent:Benign = **1:1:2**; từng fold có thể xấp xỉ vì giữ nguyên groups. D2 là training-pool configuration, không tạo test pool riêng.

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

### **2.4. Outer Cross-Validation & Inner Validation**

**Không dành riêng test pool cố định.** Benchmark dùng outer 10-fold CV trên dữ liệu đủ điều kiện sau whole-file dedup và sampling theo từng RQ.

1. Xác định P3 groups trên master pool; gán mỗi group vào đúng một outer fold trước sampling D1/D2, cân đối Active/Latent/benign khi khả thi. Chốt similarity rule bằng static evidence/synthetic references, không tối ưu theo outer-test performance.
2. Chọn D1 cân bằng, kế thừa P3 fold IDs. RQ1 tạo thêm P1/P2 trên **cùng D1 files**, nên test membership giữa protocols có thể khác; E1.5 kiểm soát khác biệt này bằng evaluation samples cố định.
3. Mỗi lượt giữ một outer fold để đánh giá; phần còn lại là outer-training pool. Tách **inner validation** trong pool này để chọn checkpoint. P2 inner split giữ executable groups; P3 giữ similarity groups; P1 giữ source disjoint, không cố ngăn quan hệ executable/near-duplicate vốn là điều kiện baseline.
4. RQ2 dùng P3 D1 checkpoints và predictions từ RQ1: mỗi file được giải thích chỉ bởi checkpoint của outer lượt mà group của nó không tham gia training/inner validation.
5. RQ3 tạo D2 từ master groups ngoài outer test, dùng cùng D1 P3 test IDs cho W0/W1 và RQ2. Mọi mẫu bổ sung thuộc outer-test groups đều bị chặn khỏi train/validation dù không được chọn vào D1 test subset.

Lưu master group/fold IDs, D1 membership và D2 train/validation/test manifests từng lượt. Báo lệch tỷ lệ, group sizes, effective group counts và khả năng tạo 10 folds; không chia nhỏ group chỉ để ép tỷ lệ đẹp. Inner-validation fraction/seed và sampling rules phải chốt trước chạy, không mặc định một tỷ lệ mới trong tài liệu này.

Kết quả là **cross-validated benchmark**, không phải đánh giá final model trên một test độc lập chưa từng được xem. Freeze protocol trước khi xem outer-test predictions/attribution; sửa thiết kế sau đó phải ghi là exploratory, không tự coi đánh giá lại cùng folds là xác nhận độc lập.

### **2.5. Model & Training Configuration**

| Thành phần | Cấu hình |
| --- | --- |
| Models | MalConv, MalConv2 (MalConvGCT) |
| Input | Whole-file raw PE bytes |
| Training | From scratch |
| Cross-validation | Outer 10-fold; inner validation trong outer-training pool |
| Max epochs | 100 |
| Early stopping monitor | Unweighted validation BCE loss |
| Patience | 3 |
| Min delta | 0.001 |
| Checkpoint selection | Best unweighted inner-validation BCE của từng outer lượt |
| Evaluation checkpoint | Checkpoint đã chọn của lượt đó; không full-data refit để tạo OOF |
| Primary metrics | F1, Recall, FPR, AUROC |
| Additional metrics | Precision, Recall Active/Latent, 95% confidence intervals |

Trong cả ba RQ, outer-test folds không được dùng chọn epoch, threshold hoặc hyperparameters. Inner validation tuân theo group policy của protocol tương ứng. W0/W1 dùng cùng actual training/validation IDs và quy tắc early stopping, chọn checkpoint riêng; loss weights chỉ tính từ actual training sau inner split.

Không có bước Mean Best Epoch/full-data final training trong thiết kế đánh giá này. Lưu OOF predictions với sample/fold/checkpoint identity; báo per-fold và pooled OOF metrics. Paired CI/resampling xét similarity groups và giới hạn do các training folds chồng lấp; không coi 10 folds là 10 phép đo độc lập.

# **3. Research Questions & Experimental Design**

## **RQ1 — Whole-File & Executable-Code Duplication and Leakage**

**Research Question**

*To what extent do executable-code duplication and near-duplication, beyond whole-file exact duplication, affect leakage and evaluation reliability in raw-byte ransomware detection?*

**Câu hỏi nghiên cứu:** Sau khi loại trùng hoàn toàn ở cấp PE, việc kiểm soát thêm executable-code duplicates và near-duplicates ảnh hưởng như thế nào đến data leakage và độ tin cậy của kết quả đánh giá?

**Mục tiêu:** Xác định các quan hệ trùng lặp mà whole-file hashing bỏ sót; đo mức leakage còn tồn tại giữa các folds; đánh giá ảnh hưởng của các mức kiểm soát leakage đến MalConv và MalConv2.

**Dataset:** D1 — Active:Latent = 1:1, Ransomware:Benign = 1:1.

**Input:** Whole-file raw PE bytes.

**Evaluation:** Outer 10-fold trên D1; inner validation riêng trong mỗi outer-training pool.

### **Experiments**

| ID | Experiment | Phương pháp thực hiện |
| --- | --- | --- |
| **E1.1** | **Exact Duplication Audit** | Thống kê whole-file SHA-256 duplicates đã loại; tính executable SHA-256 trên các file còn lại để xác định những trường hợp file khác nhau nhưng executable giống nhau. |
| **E1.2** | **Near-Duplicate Analysis** | Tính TLSH trên whole-file và executable bytes, hiệu chuẩn ngưỡng similarity, kiểm tra các cặp tương đồng và xác định similarity groups. |
| **E1.3** | **Cross-Fold Leakage Measurement** | Tạo P1/P2/P3 trên cùng D1; đo executable-exact/near-duplicate overlap giữa outer train/test và audit inner validation. |
| **E1.4** | **Leakage-Control Protocol Comparison** | Train MalConv/MalConv2 trên whole-file raw bytes; đánh giá F1, Recall, FPR, AUROC giữa P1/P2/P3. |
| **E1.5** | **Controlled Leakage Impact** | Dùng cùng evaluation samples và training sets đối chứng có quy mô tương đương để kiểm tra tác động counterpart executable tương đồng trong training; validation chọn checkpoint tách biệt evaluation. |

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

1. Xác định evaluation samples có counterpart executable-exact hoặc near-duplicate trong pool đủ điều kiện; freeze membership trước chạy.
2. Giữ cố định evaluation samples giữa hai điều kiện.
3. **Clean condition:** Training không chứa counterpart tương đồng.
4. **Leaky condition:** Training chứa counterpart tương đồng với evaluation samples.
5. Giữ số lượng training samples và tỷ lệ nhãn tương đương bằng cách thay thế mẫu phù hợp.
6. Train MalConv/MalConv2 và so sánh kết quả.

Chỉ dùng cặp tương đồng thực sự tồn tại. Đây là thí nghiệm can thiệp leakage riêng, không thay thế P3 group-disjoint baseline; không tái sử dụng checkpoint leaky cho RQ2. Không dùng evaluation samples chọn checkpoint/hyperparameters.

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

- **Tầng 1 — Explainability:** Mô hình sử dụng thông tin từ vùng PE nào?
- **Tầng 2 — Benchmark Reliability:** Hai mô hình có F1 tương đương nhưng dựa vào những vùng PE khác nhau không? Liệu benchmark chỉ báo cáo F1 có bỏ sót khác biệt quan trọng này?

**Dataset:** D1 — Active:Latent:Benign = 1:1:2.

**Evaluation:** D1 P3 outer-test folds; tái sử dụng OOF checkpoints/predictions từ RQ1 khi training protocol khớp.

### **Experimental Setup**

1. Lấy Standard BCE P3 checkpoints của MalConv/MalConv2 từ RQ1, cùng fold manifests và checkpoint-selection evidence; không cần vòng baseline training mới.
2. Xác minh mỗi checkpoint không train hoặc chọn epoch trên outer-test group tương ứng.
3. Tái sử dụng OOF predictions; nếu thiếu inference thì chạy đúng checkpoint trên outer-test files tương ứng, không dùng một full-data model cho toàn D1.
4. Ghép records theo sample IDs giữa hai model và giữ fold identity để phân tích paired attribution.
5. Lưu scores, labels, sample IDs, correctness và byte-coverage map của từng model.
6. Tính **Integrated Gradients (IG) trong không gian embedding**, ánh xạ về bytes/vùng PE; không nội suy integer token IDs.
7. Phân tích toàn bộ OOF files nếu khả thi. Nếu cần subset vì chi phí, chốt trước sampling đại diện theo Active/Latent/benign, groups, folds và kích thước; dùng cùng IDs giữa hai model, báo coverage/failures, không chỉ chọn ví dụ đẹp.
8. Giữ checkpoint/threshold cố định. Không tune model/loss/protocol RQ3 bằng OOF attribution rồi gọi đánh giá lại cùng folds là xác nhận độc lập.

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
- Kiểm tra sensitivity theo baseline và số bước tích phân; lưu convergence/completeness residual, failures, runtime/memory. Chốt settings/tolerances bằng synthetic fixtures hoặc inner-training data, không dựa outer-test attribution.
- Với low-memory MalConv2, kiểm tra `no_grad`, chunk selection/max pooling và recomputation: gradient đủ để train không tự bảo đảm IG đúng. Đối chiếu reference khả vi trên input tổng hợp nhỏ, xác minh logits tương đương; chưa qua gate này thì chưa công bố IG như kết quả hợp lệ.
- Báo paired uncertainty/95% CI có xét similarity groups và fold identity; định nghĩa agreement/resampling trước khi xem OOF kết quả, nêu giới hạn do training folds chồng lấp.
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

**Evaluation:** Cùng D1 P3 outer-test IDs như RQ2 trong mỗi lượt. D1 toàn tập có Active:Latent:Benign = 1:1:2; báo tỷ lệ thực tế mỗi fold. Không tạo test set riêng cho D2.

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
| **E3.3** | **Performance & Trade-off Analysis** | So W0/W1 trên cùng D1 P3 outer-test IDs, tổng hợp OOF; báo F1, Recall, FPR, AUROC, Recall Active/Latent và Recall Gap. |

### **Training Protocol**

- Giữ giống nhau model input, optimizer, data partitions và hyperparameters giữa W0/W1.
- Dùng master P3 outer assignments; tạo D2 chỉ từ groups ngoài outer test, tách inner validation, chặn cả các mẫu bổ sung cùng test groups. Freeze actual training/validation IDs giống nhau giữa W0/W1.
- Max 100 epochs, early stopping theo unweighted validation BCE, patience = 3, min_delta = 0.001.
- Chọn best checkpoint riêng W0/W1 bằng inner-validation BCE; weights tính lại từ actual training partition của lượt đó. Không lấy trung bình best epochs để train model dùng cho OOF.
- Đánh giá cùng D1 outer-test IDs, lưu OOF predictions và paired comparisons. Không dùng D1/RQ2 checkpoint làm D2/W0 baseline trừ khi actual training/validation/protocol trùng hoàn toàn.

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

   Gán P3 groups vào outer folds trên master pool trước sampling; chọn D1 giữ fold IDs, tạo P1/P2 trên cùng D1. Chuẩn bị D2 và inner validation từng outer lượt, không cho bổ sung mẫu từ test groups.

   Output: Master group/fold map, D1 membership, D2/inner manifests từng lượt và coverage/balance audits.
4. **Phase 4 — RQ1 Leakage Experiments**

   Trên D1, chạy P1/P2/P3 outer CV với inner validation; đo leakage và chạy E1.3–E1.5. Giữ P3 Standard BCE checkpoints cho RQ2.

   Output: Cross-fold leakage rates, protocol comparison và controlled leakage impact.
5. **Phase 5 — RQ2 Baseline Reuse & OOF Verification**

   Xác minh và tái sử dụng P3 checkpoints/OOF predictions của RQ1; chỉ inference bổ sung nếu thiếu records, không train baseline riêng khi protocol khớp.

   Output: Verified fold-specific baseline checkpoints và OOF prediction records.
6. **Phase 6 — RQ2 PE-Region Attribution Audit**

   Với checkpoints/predictions cố định, chạy IG mapping, concentration, cross-model agreement và error analysis; kiểm tra baseline/step stability và gradient validity, không train lại cho từng attribution analysis.

   Output: Region profiles/concentration, paired agreement, error analysis, stability và 95% CI có xét groups.
7. **Phase 7 — RQ3 Weighted-Loss Experiments**

   Train W0/W1 trên D2 outer-training/inner-validation partitions; đánh giá cùng D1 P3 outer-test IDs, tổng hợp OOF và group recall/trade-offs.

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
| P3 similarity groups/master outer assignments | RQ1 P3, RQ2/RQ3 folds và chống group leakage khi bổ sung D2 |
| D1 file membership | RQ1 comparison; P3 outer-test IDs chung cho RQ2/RQ3 |
| RQ1 P3 Standard BCE checkpoints/OOF predictions | RQ2 IG/error analyses, không thêm vòng baseline training |
| D2 W0/W1 checkpoints | RQ3; không tự dùng D1 checkpoints vì training/validation subsets khác nhau |
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
- **Partition:** Outer 10-fold CV, không test pool cố định; inner validation nằm trong outer-training pool.
- **RQ1:** P1/P2/P3 trên cùng D1 files; mỗi protocol có inner validation phù hợp.
- **RQ2:** Tái sử dụng P3 checkpoints/OOF predictions của RQ1; giải thích file bằng checkpoint chưa thấy group của file đó. Xác minh IG settings/coverage/gradient validity trước.
- **RQ3:** D2 chỉ lấy từ master groups ngoài outer test; W0/W1 dùng cùng training/validation và D1 P3 test IDs.
- **Training:** From scratch từng outer lượt, maximum 100 epochs; early stopping theo unweighted inner-validation BCE, patience 3, min_delta 0.001; không Mean Best Epoch/full-data final training cho đánh giá OOF.

### **Điểm cần xác minh trước khi chạy**

Số file trước/sau whole-file dedup, số nhóm độc lập P3, cân bằng folds, near-duplicate verification, giới hạn/tail coverage của model; region mapping, IG baseline/target/steps/convergence, gradient validity của low-memory implementation và chi phí attribution. Đây là các gate triển khai cần xác minh, không phải khẳng định tool đã sẵn sàng.

**Thứ tự tổng thể:** Preprocessing → Whole-file dedup → Executable/TLSH audit → Master P3 folds/D1/D2 manifests → RQ1 outer CV → RQ2 OOF attribution → RQ3 outer CV → Benchmark package.

Đây là bản sườn theo cấu hình mới, trong đó **deduplication và disjoint splitting đã được tách rõ**, ba RQ có dataset riêng phù hợp mục tiêu nhưng không phải giữ thêm các test sets độc lập không cần thiết.
