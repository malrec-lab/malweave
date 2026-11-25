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

### RQ2 — Evaluation-Set Sufficiency & Statistical Reliability
**Câu hỏi:** Kích thước tập test ảnh hưởng ra sao tới độ ổn định và độ chính xác thống kê của kết quả benchmark?

**Thiết kế:** Held-out test **20%**, cân bằng **Active:Latent:Benign = 1:1:2**. Train hai baseline Standard BCE trên development, dự đoán toàn bộ held-out **một lần**, lưu prediction scores. Phân tích các tập con **25%, 50%, 75%, 100%** của held-out; tại các mức nhỏ hơn lặp lấy mẫu phân tầng **200 lần**, dùng đúng cùng sample IDs cho hai mô hình.

**Đo lường:** biến thiên F1/Recall/FPR/AUROC, khoảng tin cậy **95%**, độ ổn định thứ hạng/chênh lệch MalConv–MalConv2. Resampling cần xét similarity groups; lặp lấy mẫu từ một pool **không** tương đương có thêm dữ liệu test độc lập. Mức 100% chỉ là một full test set.

**Đầu ra:** báo cáo độ bất định theo kích thước test, fixed test manifest và quy tắc đánh giá có thể tái lập. Không mặc định held-out hiện có đủ để ước lượng FPR cực thấp thật chính xác.

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
4. **RQ2:** CV chọn epoch trên D1 → full train Standard BCE → lưu predictions held-out → chạy toàn bộ phân tích statistical reliability **không train lại cho từng test size**.
5. **RQ3:** train W0/W1 trên D2, đánh giá trên held-out đã cố định, so sánh group recall và trade-offs.
6. **Benchmark package:** công bố manifest và fold IDs (trong phạm vi được phép), preprocessing/splitting/evaluation scripts, model configs và kết quả thống kê.

## 5. Paper sẽ trình bày gì?

**Introduction & Related Work → Dataset/Benchmark Construction → Experimental Methodology → RQ1 (duplicate/leakage) → RQ2 (test-size reliability) → RQ3 (loss weighting) → Discussion/Limitations → Conclusion.**

Các kết quả chính để review: **(i)** bảng lượng dữ liệu/duplicates theo từng cấp; **(ii)** bảng leakage và F1/FPR dưới P1–P3; **(iii)** đồ thị độ bất định theo test size; **(iv)** bảng Standard BCE vs weighted BCE và Recall Active/Latent.

**Giá trị nghiên cứu:** Không đề xuất một kiến trúc phát hiện ransomware mới; đóng góp là **giao thức benchmark có kiểm soát leakage, đánh giá độ tin cậy thống kê và các baseline có thể tái lập**. Mọi kết luận phải giới hạn trong dữ liệu và nguồn hiện được sử dụng.
