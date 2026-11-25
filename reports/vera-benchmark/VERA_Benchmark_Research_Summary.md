Chi tiết nằm ở [research-outline-detail.md](research-outline-detail.md).

# Research Summary — VERA Ransomware Benchmark

**Đề tài:** *A Reliability-Aware Benchmark for Static Ransomware Detection Using VERA*
**Mục tiêu:** Xây dựng benchmark có thể tái lập để phân loại **Ransomware vs Benign** trên Windows PE bằng raw bytes toàn file; kiểm tra độ tin cậy của kết quả thay vì chỉ tối đa hóa điểm số mô hình.

## 1. Dữ liệu và mô hình

- **Nguồn:** VERA-Active (ransomware), VERA-Latent (ransomware), Assemblage (benign). Đây là bài toán **2 lớp**; vẫn lưu nhãn nhóm Active/Latent để phân tích riêng.
- **Quy mô unique đã thống kê:** Active **6.205**, Latent **4.295**, benign **30.524** (tổng **41.024 nhóm đầu vào unique**; cần xác nhận đơn vị unique và số file sau các bước lọc cuối).
- **Input mô hình:** raw bytes của **toàn bộ file PE**; huấn luyện **MalConv và MalConv2** từ đầu.
- **Tiền xử lý:** kiểm tra PE, lọc packed bằng Detect It Easy (DiE), **xóa bản sao có cùng SHA-256 toàn file PE** (mỗi hash giữ một file). Giữ thống kê trước/sau lọc.
- **Không xóa thêm** theo executable SHA-256 hoặc TLSH: hai loại này được dùng để **gom nhóm, ngăn trùng/gần trùng đi qua train–test**.
- **Phân chia chính:** **Outer 10-fold cross-validation**, không dành riêng một test pool cố định. RQ1 so P1/P2/P3; RQ2/RQ3 dùng P3 group-disjoint. Mỗi lượt giữ một outer fold để đánh giá, chọn checkpoint bằng inner validation trong phần còn lại; không dùng outer test để early stopping.

## 2. Câu hỏi nghiên cứu và thí nghiệm

### RQ1 — Duplication & Leakage
**Câu hỏi:** Sau khi xóa file PE trùng hoàn toàn, kiểm soát thêm executable-code duplicates và near-duplicates ảnh hưởng như thế nào đến leakage và kết quả đánh giá?

**Thiết kế:** Dùng D1 cân bằng **Active:Latent = 1:1** và **Ransomware:Benign = 1:1**; chạy **outer 10-fold**, so sánh ba giao thức trên **cùng tập file**:

| Protocol | Cách chia fold | Khác biệt chính |
|---|---|---|
| **P1 — Whole-file exact baseline** | Stratified 10-Fold sau khi đã xóa whole-file SHA-256 duplicates | Chưa ngăn executable/near-duplicate đi qua folds |
| **P2 — Executable exact disjoint** | Stratified Group 10-Fold theo executable SHA-256 | Ngăn executable giống hệt nằm ở train và test |
| **P3 — Near-duplicate disjoint** | Stratified Group 10-Fold theo executable SHA-256 và quan hệ TLSH đã xác minh (whole PE + executable) | Ngăn thêm near-duplicates giữa folds |

**Thực nghiệm:** (E1.1) thống kê exact duplicates toàn PE và executable; (E1.2) thống kê/kiểm chứng near-duplicates bằng TLSH; (E1.3) đo leakage giữa các folds; (E1.4) so sánh F1/Recall/FPR/AUROC của MalConv, MalConv2 theo P1–P3; (E1.5) đối chứng clean/leaky trên **cùng mẫu đánh giá**, quy mô train tương đương, để phân biệt tác động leakage với khác biệt độ khó test. E1.5 là thí nghiệm riêng, không dùng checkpoint leaky cho RQ2.

**Đầu ra:** thống kê redundancy, leakage rate, mức thay đổi kết quả khi kiểm soát leakage và giao thức phân chia được công bố cho benchmark.

### RQ2 — PE Region Attribution & Benchmark Interpretability
**Câu hỏi:** MalConv và MalConv2 dựa vào những vùng thông tin nào của PE khi phát hiện ransomware, và những khác biệt đó cho biết gì về tính đáng tin cậy của kết quả benchmark?

**Thiết kế:** Tái sử dụng **Standard BCE P3 checkpoints và out-of-fold (OOF) predictions từ RQ1** trên D1 (**Active:Latent:Benign = 1:1:2** toàn tập; tỷ lệ từng fold có thể xấp xỉ do groups). Mỗi file được giải thích bằng checkpoint của outer fold mà file/similarity group đó không tham gia training hoặc inner validation. Tính **Integrated Gradients (IG) trong không gian embedding**, ánh xạ về **Header, Executable, Non-executable, Overlay** trên cùng PE files. Không cần thêm vòng training riêng cho RQ2 khi protocol khớp.

**Thí nghiệm:** (E2.1) Region Attribution Mapping; (E2.2) Attribution Concentration — so tỷ trọng attribution với tỷ trọng bytes của vùng; (E2.3) Cross-Model Attribution Agreement trên cùng sample IDs; (E2.4) Attribution vs Prediction Errors, phân tích riêng Active/Latent và benign. **E2.3/E2.4 là trọng tâm.** Báo cáo phân bố, độ bất định có xét similarity groups và độ ổn định theo baseline/số bước IG; không chỉ dùng trung bình hoặc heatmaps.

**Đầu ra:** giao thức PE-region attribution tái lập, region profiles, agreement giữa hai model và liên hệ với lỗi dự đoán. Chuẩn hóa chỉ theo bytes **thực sự được mô hình xử lý**, ghi rõ vùng không được bao phủ; phân biệt signed attribution và absolute attribution mass. Chốt baseline, target score, mapping vùng và IG convergence bằng synthetic fixtures/inner training trước khi phân tích outer-test attribution. Với MalConv2, cần kiểm tra gradient qua chunk selection/max pooling và so với đường tính tham chiếu khả vi trên input tổng hợp nhỏ; gradient tối ưu cho training không tự bảo đảm IG hợp lệ.

**Giới hạn:** F1 tương đương nhưng attribution khác nhau **không tự chứng minh shortcut, nhân quả hay học đúng ngữ nghĩa ransomware**. 95% CI của metrics chung vẫn giữ. Đây là cross-validated benchmark, không có final test độc lập; không tune model/threshold/loss bằng OOF results rồi gọi lại các kết quả đó là xác nhận độc lập.

### RQ3 — Frequency-Based Active/Latent Loss Reweighting
**Câu hỏi:** Khi giữ mức mất cân bằng Active/Latent thực tế, việc tính trọng số loss theo tần suất nhóm có cải thiện phát hiện ransomware không?

**Thiết kế:** Gán P3 outer fold cho toàn bộ master pool trước sampling; D1 và D2 kế thừa cùng fold IDs theo group. Trong mỗi lượt, tạo D2 từ các groups ngoài outer test: giữ toàn bộ Active/Latent hợp lệ trong pool này, không ép 1:1, chọn benign để **Ransomware:Benign ≈ 1:1**, rồi tách inner validation. So sánh **chỉ hai cấu hình** trên cùng actual training/validation IDs và cùng **D1 outer-test IDs như RQ2**. Các mẫu D2 bổ sung thuộc outer-test groups không được train/validate, kể cả khi không nằm trong D1 test subset.

- **W0:** Standard BCE, trọng số bằng 1.
- **W1:** Frequency-weighted BCE:
  \(w_A=(N_A+N_L)/(2N_A),\quad w_L=(N_A+N_L)/(2N_L),\quad w_B=1\).
  Tính \(N_A,N_L\) **chỉ từ training partition** tương ứng.

**Đo lường:** F1, AUROC, FPR, Recall chung, **Recall Active/Latent** và đánh đổi giữa các chỉ số. Không tự đặt các trọng số ×2, ×4.

**Lưu ý tái sử dụng:** baseline RQ2 train trên D1 cân bằng Active/Latent, còn baseline RQ3 train trên D2 mất cân bằng nên **không được dùng cùng checkpoint**, trừ khi thực tế hai training subsets trùng nhau.

## 3. Giao thức huấn luyện chung

- **MalConv, MalConv2:** from scratch trong từng outer fold; tối đa **100 epochs**, Early Stopping theo **unweighted inner-validation BCE**, `patience = 3`, `min_delta = 0.001`. Dùng checkpoint tốt nhất của lượt đó để đánh giá outer test.
- **Inner validation:** chỉ lấy từ outer-training pool; P1 source-disjoint, P2 executable-group-disjoint, P3 similarity-group-disjoint; tỷ lệ/seed phải chốt trước chạy. Không dùng outer test để chọn epoch/threshold/hyperparameters. Không có bước Mean Best Epoch hay full-data final training trong đánh giá này.
- **Tổng hợp:** lưu một OOF prediction/file/model/condition; báo metrics từng fold và pooled OOF, paired comparisons/95% CI có xét similarity groups và giới hạn phụ thuộc do training folds chồng lấp. Không coi 10 folds là 10 thí nghiệm độc lập.
- **Giới hạn phải kiểm tra:** kích thước file so với giới hạn input thực tế của từng triển khai MalConv/MalConv2; near-duplicate false merges và nhóm TLSH quá lớn; rủi ro **source–label confounding** do ransomware đến từ VERA còn benign từ Assemblage.

## 4. Thứ tự chạy, tránh làm lại

1. **Preprocess & master manifest:** xác thực PE → DiE → whole-file SHA-256 dedup → executable SHA-256 + TLSH toàn PE/executable; lưu thống kê và similarity groups.
2. **Tạo folds:** P3 outer group assignments trên master pool → chọn D1 (**RQ1/RQ2/common evaluation**), giữ fold IDs; tạo P1/P2 trên cùng D1. D2 training pools cho **RQ3** chỉ lấy từ groups ngoài outer test; lưu cả inner-validation IDs.
3. **RQ1:** audit duplicates → đo leakage P1/P2/P3 → chạy các baseline 10-fold → controlled comparison E1.5.
4. **RQ2:** tái sử dụng P3 checkpoints/OOF predictions của RQ1 → IG trên outer-test files tương ứng → concentration, cross-model agreement và error analysis; không train lại.
5. **RQ3:** train W0/W1 trên D2 của từng outer lượt, đánh giá trên cùng D1 outer-test IDs; tổng hợp OOF và group recall/trade-offs.
6. **Benchmark package:** công bố manifest và fold IDs (trong phạm vi được phép), preprocessing/splitting/evaluation scripts, model configs và kết quả thống kê.

## 5. Paper sẽ trình bày gì?

**Introduction & Related Work → Dataset/Benchmark Construction → Experimental Methodology → RQ1 (data reliability: duplicate/leakage) → RQ2 (model interpretability: PE-region attribution) → RQ3 (learning strategy: loss weighting) → Discussion/Limitations → Conclusion.**

Các kết quả chính để review: **(i)** bảng lượng dữ liệu/duplicates theo từng cấp; **(ii)** bảng leakage và F1/FPR dưới P1–P3; **(iii)** region-attribution profiles, concentration, cross-model agreement và error analysis; **(iv)** bảng Standard BCE vs weighted BCE và Recall Active/Latent.

**Giá trị nghiên cứu:** Không đề xuất kiến trúc hay phương pháp IG mới; đóng góp là **giao thức benchmark có kiểm soát leakage, kiểm toán PE-region attribution có thể tái lập và các baseline/loss comparisons được đánh giá có độ bất định thống kê**. Mọi kết luận phải giới hạn trong dữ liệu và nguồn hiện được sử dụng.
