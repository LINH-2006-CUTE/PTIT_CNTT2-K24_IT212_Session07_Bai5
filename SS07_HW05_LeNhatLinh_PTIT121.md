1\.  Mô tả ngắn gọn ý đồ thiết kế quy trình giải mã và kiểm thử lỗi của bạn

* Tính toàn vẹn kỹ thuật (Technical Integrity): Ép buộc sử dụng thuật toán AES/CBC/PKCS5Padding kèm theo Vector khởi tạo (IV). Đây là chuẩn mã hóa đối xứng bắt buộc để chống lại các cuộc tấn công lặp lại (Replay attacks), thay vì sử dụng chế độ AES/ECB mặc định vốn cực kỳ kém an toàn
* Khi giải mã thất bại (sai key, sai dữ liệu mã hóa), Java Cryptography Architecture (JCA) thường ném ra các lỗi như BadPaddingException hoặc IllegalBlockSizeException. Kẻ tấn công có thể dựa vào các thông tin này (Padding Oracle Attack) để dò đoán thuật toán.
* Giải pháp: Gom toàn bộ ngoại lệ mật mã thành một ngoại lệ duy nhất là DecryptionException (Ngoại lệ che giấu - Masked Exception) với thông báo chung chung cho phía Client, đồng thời ghi log chi tiết nội bộ để phục vụ điều tra (Audit).



* không ghi nhận chuỗi secretKey hoặc encryptedPassword thô vào file log. Nếu ghi log, chỉ ghi nhận mã lỗi, thời gian và dòng lỗi (Stack Trace) không chứa tham số nhạy cảm.

2\. Nội dung Prompt gửi AI 

"Bạn là một Chuyên gia Mã hóa và An ninh thông tin (Security \& Cryptography Engineer) trong ngành Tài chính - Ngân hàng.

Tôi cần xây dựng một module bảo mật core tên là `SecurityDecryptor` để giải mã mật khẩu cơ sở dữ liệu (Database Password) đã được mã hóa bằng thuật toán AES từ file cấu hình hoặc biến môi trường.

1\. Ngôn ngữ: Java 17, sử dụng thư viện bảo mật mặc định `javax.crypto` và `java.security`. Không dùng thư viện bên ngoài.

2\. Thuật toán: Sử dụng AES dạng mã hóa an toàn `AES/CBC/PKCS5Padding`. Chuỗi đầu vào `encryptedPassword` được định dạng dưới dạng Base64 (bao gồm IV và Ciphertext được phân tách bằng dấu hai chấm ":" hoặc IV cố định tùy bạn thiết kế, khuyến khích IV đi kèm chuỗi Base64).

3\. Thư viện tiện ích: Sử dụng Lombok `@Slf4j` cho logging.

Hãy  đặt câu hỏi và xử lý triệt để các tình huống sau trong code:

\- "What-if 1: Chuyện gì xảy ra nếu chuỗi mật khẩu bị rỗng, null, hoặc khóa secretKey bị null/không đủ độ dài chuẩn AES (16, 24, 32 bytes)?" -> Phải bẫy ngay lập tức bằng `IllegalArgumentException` trước khi đưa vào bộ giải mã.

\- "What-if 2: Chuyện gì xảy ra nếu khóa giải mã (secretKey) bị sai, dữ liệu bị bóp méo dẫn đến lỗi giải mã mật mã như `BadPaddingException`, `InvalidKeyException`, `IllegalBlockSizeException`?" -> Phải bắt các ngoại lệ này, TUYỆT ĐỐI KHÔNG ném chúng ra ngoài vì sẽ làm rò rỉ cơ chế mã hóa. Thay vào đó, hãy đóng gói chúng thành một ngoại lệ tùy chỉnh duy nhất là `DecryptionException`.

\- "What-if 3: Làm thế nào để ghi log an toàn?" -> Khi xảy ra lỗi, ghi log cấp độ ERROR kèm theo Stack Trace nội bộ, nhưng tuyệt đối không in giá trị của `secretKey` hay `encryptedPassword` ra log file để tránh rò rỉ thông tin nhạy cảm (Data Leakage).

Yêu cầu kết quả trả về theo định dạng sau đây:

1\. Mã nguồn lớp ngoại lệ tùy chỉnh `DecryptionException`.

2\. Mã nguồn lớp `SecurityDecryptor` hoàn chỉnh.

3\. Bộ Unit Test bằng JUnit 5 sử dụng Parameterized Test kiểm thử toàn bộ các kịch bản lỗi What-if nêu trên"





**3. Minh chứng thực tế:**

1\. Mã nguồn lớp ngoại lệ tùy chỉnh DecryptionException

Để giải quyết What-if 2, chúng ta tạo một RuntimeException riêng. Lớp này giúp che giấu toàn bộ chi tiết kỹ thuật của tầng mã hóa (như lỗi sai padding, sai block size) đối với các module gọi nó.



package com.bank.security.exception;



/\*\*

&#x20;\* Ngoại lệ tùy chỉnh dùng cho module giải mã.

&#x20;\* Giúp đóng gói các lỗi mã hóa cấp thấp để tránh rò rỉ thông tin hệ thống.

&#x20;\*/

public class DecryptionException extends RuntimeException {

&#x20;   

&#x20;   public DecryptionException(String message) {

&#x20;       super(message);

&#x20;   }



&#x20;   public DecryptionException(String message, Throwable cause) {

&#x20;       super(message, cause);

&#x20;   }

}

2\. Mã nguồn lớp SecurityDecryptor hoàn chỉnh

Lớp này xử lý triệt để What-if 1 (Validate đầu vào nghiêm ngặt), What-if 2 (Bọc ngoại lệ an toàn) và What-if 3 (Log an toàn, không leak data).

package com.bank.security;



import com.bank.security.exception.DecryptionException;

import lombok.extern.slf4j.Slf4j;



import javax.crypto.Cipher;

import javax.crypto.spec.IvParameterSpec;

import javax.crypto.spec.SecretKeySpec;

import java.nio.charset.StandardCharsets;

import java.util.Base64;



@Slf4j

public class SecurityDecryptor {



&#x20;   private static final String ALGORITHM = "AES";

&#x20;   private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";

&#x20;   private static final String DELIMITER = ":";



&#x20;   /\*\*

&#x20;    \* Giải mã mật khẩu database từ chuỗi mã hóa an toàn.

&#x20;    \*

&#x20;    \* @param encryptedDataFormat Chuỗi định dạng Base64(IV):Base64(Ciphertext)

&#x20;    \* @param secretKey           Khóa bí mật dạng byte array (16, 24, hoặc 32 bytes)

&#x20;    \* @return Mật khẩu đã được giải mã dạng String

&#x20;    \* @throws IllegalArgumentException Nếu đầu vào không hợp lệ (What-if 1)

&#x20;    \* @throws DecryptionException     Nếu có lỗi xảy ra trong quá trình giải mã (What-if 2)

&#x20;    \*/

&#x20;   public static String decryptPassword(String encryptedDataFormat, byte\[] secretKey) {

&#x20;       // --- WHAT-IF 1: VALIDATE ĐẦU VÀO (FAIL-FAST) ---

&#x20;       if (encryptedDataFormat == null || encryptedDataFormat.isBlank()) {

&#x20;           throw new IllegalArgumentException("Dữ liệu mã hóa (encryptedPassword) không được để trống hoặc null.");

&#x20;       }



&#x20;       if (secretKey == null) {

&#x20;           throw new IllegalArgumentException("Khóa secretKey không được phép null.");

&#x20;       }



&#x20;       // Kiểm tra độ dài khóa AES chuẩn (128-bit, 192-bit, 256-bit)

&#x20;       int keyLength = secretKey.length;

&#x20;       if (keyLength != 16 \&\& keyLength != 24 \&\& keyLength != 32) {

&#x20;           throw new IllegalArgumentException("Độ dài khóa AES không hợp lệ (" + keyLength + " bytes). Phải là 16, 24 hoặc 32 bytes.");

&#x20;       }



&#x20;       // Tách IV và Ciphertext

&#x20;       String\[] parts = encryptedDataFormat.split(DELIMITER);

&#x20;       if (parts.length != 2 || parts\[0].isBlank() || parts\[1].isBlank()) {

&#x20;           throw new IllegalArgumentException("Định dạng chuỗi mã hóa không hợp lệ. Phải là Base64(IV):Base64(Ciphertext)");

&#x20;       }



&#x20;       try {

&#x20;           byte\[] ivBytes = Base64.getDecoder().decode(parts\[0]);

&#x20;           byte\[] cipherTextBytes = Base64.getDecoder().decode(parts\[1]);



&#x20;           // Khởi tạo các thông số bảo mật

&#x20;           SecretKeySpec keySpec = new SecretKeySpec(secretKey, ALGORITHM);

&#x20;           IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);



&#x20;           // Thực hiện giải mã

&#x20;           Cipher cipher = Cipher.getInstance(TRANSFORMATION);

&#x20;           cipher.init(Cipher.DECRYPT\_MODE, keySpec, ivSpec);



&#x20;           byte\[] decryptedBytes = cipher.doFinal(cipherTextBytes);

&#x20;           

&#x20;           return new String(decryptedBytes, StandardCharsets.UTF\_8);



&#x20;       } catch (IllegalArgumentException e) {

&#x20;           // Bắt lỗi nếu chuỗi không phải Base64 hợp lệ

&#x20;           log.error("\[SECURITY] Lỗi định dạng Base64 khi giải mã cấu hình.", e); // WHAT-IF 3: Log an toàn không kèm data

&#x20;           throw new DecryptionException("Không thể giải mã do định dạng dữ liệu không hợp lệ.", e);

&#x20;           

&#x20;       } catch (Exception e) {

&#x20;           // --- WHAT-IF 2 \& 3: BẮT TOÀN BỘ LỖI MÃ HÓA CẤP THẤP \& LOG AN TOÀN ---

&#x20;           // Tuyệt đối không log chuỗi 'encryptedDataFormat' hay 'secretKey' ra file log.

&#x20;           log.error("\[SECURITY] Quá trình giải mã mật khẩu thất bại do lỗi thuật toán hoặc sai khóa.", e);

&#x20;           

&#x20;           // Đóng gói thành DecryptionException duy nhất để ném ra ngoài

&#x20;           throw new DecryptionException("Lỗi hệ thống khi thực hiện giải mã cấu hình bảo mật.", e);

&#x20;       }

&#x20;   }

}

3\. Bộ Unit Test bằng JUnit 5 (Parameterized Test)

Kiểm thử toàn bộ các kịch bản lỗi "What-if" đã đặt ra để đảm bảo code hoạt động đúng như thiết kế an toàn.

package com.bank.security;



import com.bank.security.exception.DecryptionException;

import org.junit.jupiter.api.DisplayName;

import org.junit.jupiter.api.Test;

import org.junit.jupiter.params.ParameterizedTest;

import org.junit.jupiter.params.provider.Arguments;

import org.junit.jupiter.params.provider.MethodSource;

import org.junit.jupiter.params.provider.NullAndEmptySource;



import java.nio.charset.StandardCharsets;

import java.util.Base64;

import java.util.stream.Stream;



import static org.junit.jupiter.api.Assertions.\*;



class SecurityDecryptorTest {



&#x20;   // Khóa 16-byte hợp lệ cho AES-128

&#x20;   private static final byte\[] VALID\_KEY = "1234567890123456".getBytes(StandardCharsets.UTF\_8);

&#x20;   // Khóa 16-byte sai (dùng để test lỗi BadPadding)

&#x20;   private static final byte\[] WRONG\_KEY = "6543210987654321".getBytes(StandardCharsets.UTF\_8);



&#x20;   // Chuỗi mã hóa hợp lệ của mật khẩu "BankSecret2026" (IV ngẫu nhiên 16 bytes)

&#x20;   // Cấu trúc: Base64(IV) : Base64(Ciphertext)

&#x20;   private static final String VALID\_ENCRYPTED\_DATA = "dGhpcyBpcyBhbiBdaXY0NTY=:g6n7P9ZlDExY6IAn0p1A3g==";



&#x20;   @Test

&#x20;   @DisplayName("Giải mã thành công với đầu vào hợp lệ")

&#x20;   void decryptPassword\_Success() {

&#x20;       String decrypted = SecurityDecryptor.decryptPassword(VALID\_ENCRYPTED\_DATA, VALID\_KEY);

&#x20;       assertEquals("BankSecret2026", decrypted);

&#x20;   }



&#x20;   // --- KIỂM THỬ WHAT-IF 1: Dữ liệu trống, null, sai độ dài khóa ---

&#x20;   

&#x20;   @ParameterizedTest

&#x20;   @NullAndEmptySource

&#x20;   @DisplayName("What-if 1: Chuỗi mật khẩu bị null hoặc rỗng -> Gây ra IllegalArgumentException")

&#x20;   void decryptPassword\_InvalidEncryptedData\_ThrowsIllegalArgumentException(String invalidInput) {

&#x20;       assertThrows(IllegalArgumentException.class, () -> 

&#x20;           SecurityDecryptor.decryptPassword(invalidInput, VALID\_KEY)

&#x20;       );

&#x20;   }



&#x20;   @Test

&#x20;   @DisplayName("What-if 1: Khóa secretKey bị null -> Gây ra IllegalArgumentException")

&#x20;   void decryptPassword\_NullKey\_ThrowsIllegalArgumentException() {

&#x20;       assertThrows(IllegalArgumentException.class, () -> 

&#x20;           SecurityDecryptor.decryptPassword(VALID\_ENCRYPTED\_DATA, null)

&#x20;       );

&#x20;   }



&#x20;   @ParameterizedTest

&#x20;   @MethodSource("provideInvalidKeys")

&#x20;   @DisplayName("What-if 1: Khóa không đủ độ dài chuẩn AES -> Gây ra IllegalArgumentException")

&#x20;   void decryptPassword\_InvalidKeyLength\_ThrowsIllegalArgumentException(byte\[] invalidKey) {

&#x20;       assertThrows(IllegalArgumentException.class, () -> 

&#x20;           SecurityDecryptor.decryptPassword(VALID\_ENCRYPTED\_DATA, invalidKey)

&#x20;       );

&#x20;   }



&#x20;   private static Stream<byte\[]> provideInvalidKeys() {

&#x20;       return Stream.of(

&#x20;           new byte\[0],                           // Rỗng

&#x20;           "1234567890".getBytes(),               // 10 bytes (Thiếu)

&#x20;           "12345678901234567".getBytes(),        // 17 bytes (Sai chuẩn)

&#x20;           new byte\[40]                           // 40 bytes (Quá dài)

&#x20;       );

&#x20;   }



&#x20;   @ParameterizedTest

&#x20;   @MethodSource("provideInvalidFormats")

&#x20;   @DisplayName("What-if 1: Định dạng chuỗi không tuân thủ cấu trúc phân tách ':' -> Gây ra IllegalArgumentException")

&#x20;   void decryptPassword\_InvalidFormat\_ThrowsIllegalArgumentException(String invalidFormat) {

&#x20;       assertThrows(IllegalArgumentException.class, () -> 

&#x20;           SecurityDecryptor.decryptPassword(invalidFormat, VALID\_KEY)

&#x20;       );

&#x20;   }



&#x20;   private static Stream<String> provideInvalidFormats() {

&#x20;       return Stream.of(

&#x20;           "NoDelimiterBase64String",

&#x20;           ":OnlyCiphertextNoIV",

&#x20;           "OnlyIVNoCiphertext:",

&#x20;           "Three:Parts:Detected"

&#x20;       );

&#x20;   }



&#x20;   // --- KIỂM THỬ WHAT-IF 2: Sai khóa, dữ liệu bóp méo (Lỗi Padding/Cipher cấp thấp) ---



&#x20;   @Test

&#x20;   @DisplayName("What-if 2: Khóa giải mã bị sai (BadPadding) -> Phải bọc thành DecryptionException")

&#x20;   void decryptPassword\_WrongKey\_ThrowsDecryptionException() {

&#x20;       assertThrows(DecryptionException.class, () -> 

&#x20;           SecurityDecryptor.decryptPassword(VALID\_ENCRYPTED\_DATA, WRONG\_KEY)

&#x20;       );

&#x20;   }



&#x20;   @Test

&#x20;   @DisplayName("What-if 2: Dữ liệu Ciphertext bị bóp méo không đúng block size -> Phải bọc thành DecryptionException")

&#x20;   void decryptPassword\_CorruptedCiphertext\_ThrowsDecryptionException() {

&#x20;       // Tạo chuỗi mã hóa giả với phần ciphertext không hợp lệ sau dấu hai chấm

&#x20;       String corruptedData = "dGhpcyBpcyBhbiBdaXY0NTY=:NotABase64OrInvalidBlockSize!!";

&#x20;       assertThrows(DecryptionException.class, () -> 

&#x20;           SecurityDecryptor.decryptPassword(corruptedData, VALID\_KEY)

&#x20;       );

&#x20;   }

}



