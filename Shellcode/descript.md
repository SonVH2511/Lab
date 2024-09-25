### shellcode

- Ý tưởng để xây dựng shellcode khá đơn giản. Mình thực hiện viết một đoạn chương trình rồi quăng vào `IDA`. Chép opcode ra rồi sửa lại một chút là được.

- Tất nhiên, một số vấn đề xảy ra trong quá trình xây dựng shell mà mình gặp phải.

  - Các giá trị được lấy ra từ hàm ban đầu nếu bao gồm dải data(string) sẽ không được truyền tải chính xác khi thực thi shell.
  - Các `winAPI` được gọi ra ở hàm ban đầu sẽ bị dịch lỗi trong shell.

- Nào rảnh mình viết nốt :v.
