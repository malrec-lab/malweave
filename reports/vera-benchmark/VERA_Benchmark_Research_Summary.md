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
- **Phân chia chính:** **80% development / 20% held-out test**, tách theo similarity groups nghiêm ngặt nhất (P3). RQ1 chỉ dùng development; RQ2 và đánh giá cuối RQ3 dùng held-out.

## 2. Câu hỏi nghiên cứu và thí nghiệm

### RQ1 — Duplication & Leakage
**Câu hỏi:** Sau khi xóa file PE trùng hoàn toàn, kiểm soát thêm executable-code duplicates và near-duplicates ảnh hưởng như thế nào đến leakage và kết quả đánh giá?

**Thiết kế:** Dùng tập cân bằng **Active:Latent = 1:1** và **Ransomware:Benign = 1:1**; chạy **10-fold trong 80% development**, so sánh ba giao thức trên **cùng tập file**:

| Protocol | Cách chia fold | Khác biệt chính |
|---|---|---|
| **P1 — Whole-file exact baseline** | Stratified 10-Fold sau khi đã xóa whole-file SHA-256 duplicates | Chưa ngăn executable/near-duplicate đi qua folds |
| **P2 — Executable exact disjoint** | Stratified Group 10-Fold theo executable SHA-256 | Ngăn executable giống hệt nằm ở train và test |
| **P3 — Near-duplicate disjoint** | Stratified Group 10-Fold theo executable SHA-256 và quan hệ TLSH đã xác minh (whole PE + executable) | Ngăn thêm near-duplicates giữa folds |

**Thực nghiệm:** (E1.1) thống kê exact duplicates toàn PE và executable; (E1.2) thống kê/kiểm chứng near-duplicates bằng TLSH; (E1.3) đo leakage giữa các folds; (E1.4) so sánh F1/Recall/FPR/AUROC của MalConv, MalConv2 theo P1–P3; (E1.5) đối chứng clean/leaky trên **cùng mẫu đánh giá**, quy mô train tương đương, để phân biệt tác động leakage với khác biệt độ khó test. **Không sử dụng held-out 20% ở RQ1.**

**Đầu ra:** thống kê redundancy, leakage rate, mức thay đổi kết quả khi kiểm soát leakage và giao thức phân chia được công bố cho benchmark.

### RQ2 — PE Region Attribution & Benchmark Interpretability
**Câu hỏi:** MalConv và MalConv2 dựa vào những vùng thông tin nào của PE khi phát hiện ransomware, và những khác biệt đó cho biết gì về tính đáng tin cậy của kết quả benchmark?

**Thiết kế:** Train hai baseline Standard BCE trên D1 development, đánh giá trên held-out **20%**, cân bằng **Active:Latent:Benign = 1:1:2**. Lưu predictions và tính **Integrated Gradients (IG) trong không gian embedding**, ánh xạ về **Header, Executable, Non-executable, Overlay** trên cùng PE files. Mục tiêu là kiểm toán vùng thông tin ảnh hưởng đến dự đoán, không chỉ minh họa một vài heatmaps.

**Thí nghiệm:** (E2.1) Region Attribution Mapping; (E2.2) Attribution Concentration — so tỷ trọng attribution với tỷ trọng bytes của vùng; (E2.3) Cross-Model Attribution Agreement trên cùng sample IDs; (E2.4) Attribution vs Prediction Errors, phân tích riêng Active/Latent và benign. **E2.3/E2.4 là trọng tâm.** Báo cáo phân bố, độ bất định có xét similarity groups và độ ổn định theo baseline/số bước IG; không chỉ dùng trung bình hoặc heatmaps.

**Đầu ra:** giao thức PE-region attribution tái lập, region profiles, agreement giữa hai model và liên hệ với lỗi dự đoán. Chuẩn hóa chỉ theo bytes **thực sự được mô hình xử lý**, ghi rõ vùng không được bao phủ; phân biệt signed attribution và absolute attribution mass. Chốt baseline, target score, mapping vùng và IG convergence trước khi phân tích held-out. Với MalConv2, cần kiểm tra gradient qua chunk selection/max pooling và so với đường tính tham chiếu khả vi trên input tổng hợp nhỏ; gradient tối ưu cho training không tự bảo đảm IG hợp lệ.

**Giới hạn:** F1 tương đương nhưng attribution khác nhau là thông tin bổ sung, **không tự chứng minh shortcut, quan hệ nhân quả hay mô hình học đúng ngữ nghĩa ransomware**. RQ2 mới thay thế thí nghiệm test-size cũ; 95% CI của các metrics chung vẫn giữ. Không tune model/threshold/loss dựa vào attribution held-out rồi dùng lại tập đó như đánh giá độc lập.

### RQ3 — Frequency-Based Active/Latent Loss Reweighting
**Câu hỏi:** Khi giữ mức mất cân bằng Active/Latent thực tế, việc tính trọng số loss theo tần suất nhóm có cải thiện phát hiện ransomware không?

**Thiết kế:** Training giữ **toàn bộ Active/Latent hợp lệ** trong development, không ép hai nhóm 1:1; tổng **Ransomware:Benign ≈ 1:1**. So sánh **chỉ hai cấu hình**, trên cùng training subset và cùng held-out test cân bằng như RQ2:

- **W0:** Standard BCE, trọng số bằng 1.
- **W1:** Frequency-weighted BCE:
  \(w_A=(N_A+N_L)/(2N_A),\quad w_L=(N_A+N_L)/(2N_L),\quad w_B=1\).
  Tính \(N_A,N_L\) **chỉ từ training partition** tương ứng.

**Đo lường:** F1, AUROC, FPR, Recall chung, **Recall Active/Latent** và đánh đổi giữa các chỉ số. Không tự đặt các trọng số ×2, ×4.

**Lưu ý tái sử dụng:** baseline RQ2 train trên D1 cân bằng Active/Latent, còn baseline RQ3 train trên D2 mất cân bằng nên **không được dùng cùng checkpoint**, trừ khi thực tế hai training subsets trùng nhau.

## 3. Giao thức huấn luyện chung

- **MalConv, MalConv2:** from scratch; 10-fold trên development để chọn epoch; tối đa **100 epochs**, Early Stopping theo **unweighted validation BCE**, `patience = 3`, `min_delta = 0.001`.
- **Final training:** lấy **Mean Best Epoch** từ 10 validation folds, huấn luyện lại từ đầu trên toàn bộ development subset, rồi mới đánh giá held-out.
- **Đối với RQ1:** fold dùng làm test để so sánh protocol **không** được dùng chọn epoch; cần validation bên trong training portion của từng lượt để tránh evaluation leakage.
- **Giới hạn phải kiểm tra:** kích thước file so với giới hạn input thực tế của từng triển khai MalConv/MalConv2; near-duplicate false merges và nhóm TLSH quá lớn; rủi ro **source–label confounding** do ransomware đến từ VERA còn benign từ Assemblage.

## 4. Thứ tự chạy, tránh làm lại

1. **Preprocess & master manifest:** xác thực PE → DiE → whole-file SHA-256 dedup → executable SHA-256 + TLSH toàn PE/executable; lưu thống kê và similarity groups.
2. **Tạo partition:** 80/20 theo P3; từ development tạo D1 (**RQ1/RQ2**) và D2 (**RQ3**). Giữ một held-out test cân bằng dùng cho RQ2/RQ3.
3. **RQ1:** audit duplicates → đo leakage P1/P2/P3 → chạy các baseline 10-fold → controlled comparison E1.5.
4. **RQ2:** CV chọn epoch trên D1 → full train Standard BCE → lưu predictions held-out → IG region mapping, concentration, cross-model agreement và error analysis; kiểm tra độ ổn định/convergence, **không train lại cho từng phân tích attribution**.
5. **RQ3:** train W0/W1 trên D2, đánh giá trên held-out đã cố định, so sánh group recall và trade-offs.
6. **Benchmark package:** công bố manifest và fold IDs (trong phạm vi được phép), preprocessing/splitting/evaluation scripts, model configs và kết quả thống kê.

## 5. Paper sẽ trình bày gì?

**Introduction & Related Work → Dataset/Benchmark Construction → Experimental Methodology → RQ1 (data reliability: duplicate/leakage) → RQ2 (model interpretability: PE-region attribution) → RQ3 (learning strategy: loss weighting) → Discussion/Limitations → Conclusion.**

Các kết quả chính để review: **(i)** bảng lượng dữ liệu/duplicates theo từng cấp; **(ii)** bảng leakage và F1/FPR dưới P1–P3; **(iii)** region-attribution profiles, concentration, cross-model agreement và error analysis; **(iv)** bảng Standard BCE vs weighted BCE và Recall Active/Latent.

**Giá trị nghiên cứu:** Không đề xuất kiến trúc hay phương pháp IG mới; đóng góp là **giao thức benchmark có kiểm soát leakage, kiểm toán PE-region attribution có thể tái lập và các baseline/loss comparisons được đánh giá có độ bất định thống kê**. Mọi kết luận phải giới hạn trong dữ liệu và nguồn hiện được sử dụng.
