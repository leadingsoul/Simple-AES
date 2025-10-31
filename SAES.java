package S_AES;

public class SAES {
    // -------------------------- 1.
    // 基础配置（S盒、逆S盒，严格遵循文档表D.1）--------------------------
    private static final int[] S_BOX = {
            0x9, 0x4, 0xA, 0xB, // 行0（00）：0→9, 1→4, 2→A, 3→B
            0xD, 0x1, 0x8, 0x5, // 行1（01）：4→D, 5→1, 6→8, 7→5
            0x6, 0x2, 0x0, 0x3, // 行2（10）：8→6, 9→2, 10→0, 11→3
            0xC, 0xE, 0xF, 0x7 // 行3（11）：12→C, 13→E, 14→F, 15→7
    };

    private static final int[] INV_S_BOX = {
            0xA, 0x5, 0x9, 0xB, // 行0（00）：0→A, 1→5, 2→9, 3→B
            0x1, 0x7, 0x8, 0xF, // 行1（01）：4→1, 5→7, 6→8, 7→F
            0x6, 0x0, 0x2, 0x3, // 行2（10）：8→6, 9→0, 10→2, 11→3
            0xC, 0x4, 0xD, 0xE // 行3（11）：12→C, 13→4, 14→D, 15→E
    };

    // -------------------------- 2.
    // GF(2⁴)乘法（文档附件D.1，模x⁴+x+1=0x13）--------------------------
    private static int gf24Multiply(int a, int b) {
        int result = 0;
        a &= 0xF; // 确保输入为4位
        b &= 0xF;

        for (int i = 0; i < 4; i++) {
            if ((b & 1) != 0) {
                result ^= a;
            }
            boolean carry = (a & 0x8) != 0; // 第4位（bit3）是否为1
            a <<= 1;
            if (carry) {
                a ^= 0x13; // 模x⁴+x+1
            }
            b >>= 1;
        }
        return result & 0xF; // 结果截断为4位
    }

    // -------------------------- 3. 核心变换（均添加16位截断，避免溢出）--------------------------
    /**
     * 半字节代替（文档D.2.2）：S盒替换4个半字节
     */
    private static int subNibbles(int state) {
        // 按列拆分状态：s00(12-15位)、s10(8-11位)、s01(4-7位)、s11(0-3位)（文档1-14）
        int s00 = (state >> 12) & 0xF;
        int s10 = (state >> 8) & 0xF;
        int s01 = (state >> 4) & 0xF;
        int s11 = state & 0xF;

        // S盒替换
        s00 = S_BOX[s00];
        s10 = S_BOX[s10];
        s01 = S_BOX[s01];
        s11 = S_BOX[s11];

        // 重组并截断为16位
        return ((s00 << 12) | (s10 << 8) | (s01 << 4) | s11) & 0xFFFF;
    }

    /**
     * 逆半字节代替（文档D.2.2）：逆S盒替换
     */
    private static int invSubNibbles(int state) {
        int s00 = (state >> 12) & 0xF;
        int s10 = (state >> 8) & 0xF;
        int s01 = (state >> 4) & 0xF;
        int s11 = state & 0xF;

        s00 = INV_S_BOX[s00];
        s10 = INV_S_BOX[s10];
        s01 = INV_S_BOX[s01];
        s11 = INV_S_BOX[s11];

        return ((s00 << 12) | (s10 << 8) | (s01 << 4) | s11) & 0xFFFF;
    }

    /**
     * 行移位（文档D.2.3）：第二行半字节交换（s10↔s11），第一行不变
     */
    private static int shiftRows(int state) {
        int s00 = (state >> 12) & 0xF;
        int s10 = (state >> 8) & 0xF;
        int s01 = (state >> 4) & 0xF;
        int s11 = state & 0xF;

        // 交换第二行半字节，重组后截断16位
        return ((s00 << 12) | (s11 << 8) | (s01 << 4) | s10) & 0xFFFF;
    }

    /**
     * 列混淆（文档D.2.4）：矩阵[[1,4],[4,1]]乘法（GF(2⁴)）
     */
    private static int mixColumns(int state) {
        int s00 = (state >> 12) & 0xF;
        int s10 = (state >> 8) & 0xF;
        int s01 = (state >> 4) & 0xF;
        int s11 = state & 0xF;

        // 文档公式：s00'=1*s00⊕4*s10；s10'=4*s00⊕1*s10；s01'、s11'同理
        int s00New = gf24Multiply(1, s00) ^ gf24Multiply(4, s10);
        int s10New = gf24Multiply(4, s00) ^ gf24Multiply(1, s10);
        int s01New = gf24Multiply(1, s01) ^ gf24Multiply(4, s11);
        int s11New = gf24Multiply(4, s01) ^ gf24Multiply(1, s11);

        return ((s00New << 12) | (s10New << 8) | (s01New << 4) | s11New) & 0xFFFF;
    }

    /**
     * 逆列混淆（文档D.2.4）：矩阵[[9,2],[2,9]]乘法（GF(2⁴)）
     */
    private static int invMixColumns(int state) {
        int s00 = (state >> 12) & 0xF;
        int s10 = (state >> 8) & 0xF;
        int s01 = (state >> 4) & 0xF;
        int s11 = state & 0xF;

        int s00New = gf24Multiply(9, s00) ^ gf24Multiply(2, s10);
        int s10New = gf24Multiply(2, s00) ^ gf24Multiply(9, s10);
        int s01New = gf24Multiply(9, s01) ^ gf24Multiply(2, s11);
        int s11New = gf24Multiply(2, s01) ^ gf24Multiply(9, s11);

        return ((s00New << 12) | (s10New << 8) | (s01New << 4) | s11New) & 0xFFFF;
    }

    // 密钥拓展
    private static byte g(byte w, int round) {
        // 1. RotNib：交换8位字的高低4位
        byte rotNib = (byte) (((w & 0x0F) << 4) | ((w & 0xF0) >> 4));

        // 2. SubNib：对RotNib结果的两个半字节分别S盒替换
        int nibHigh = (rotNib >> 4) & 0xF;
        int nibLow = rotNib & 0xF;
        byte subNib = (byte) ((S_BOX[nibHigh] << 4) | S_BOX[nibLow]);

        // 3. XOR RCON（文档1-61：RCON1=0x80，RCON2=0x30）
        byte rcon = (round == 1) ? (byte) 0x80 : (byte) 0x30;
        return (byte) (subNib ^ rcon);
    }

    // 3个16位轮密钥
    private static int[] keyExpansion(int key) {
        // 拆分16位密钥为两个8位字
        byte w0 = (byte) ((key >> 8) & 0xFF);
        byte w1 = (byte) (key & 0xFF);

        byte w2 = (byte) (w0 ^ g(w1, 1));
        byte w3 = (byte) (w2 ^ w1);
        byte w4 = (byte) (w2 ^ g(w3, 2));
        byte w5 = (byte) (w4 ^ w3);

        int K0 = ((w0 << 8) | (w1 & 0xFF)) & 0xFFFF;
        int K1 = ((w2 << 8) | (w3 & 0xFF)) & 0xFFFF;
        int K2 = ((w4 << 8) | (w5 & 0xFF)) & 0xFFFF;

        return new int[] { K0, K1, K2 };
    }

    // 十六进制字符串转整数
    public static int hexStringToInt(String hexString) {
        return Integer.parseInt(hexString, 16);
    }

    // 整数转十六进制字符串（固定长度）
    public static String intToHexString(int value, int length) {
        String hex = Integer.toHexString(value).toUpperCase();
        while (hex.length() < length) {
            hex = "0" + hex;
        }
        return hex;
    }

    // ASCII字符串转十六进制字符串（每2个字符对应一个16位数据）
    public static String asciiToHexString(String asciiText) {
        StringBuilder hexBuilder = new StringBuilder();
        for (int i = 0; i < asciiText.length(); i++) {
            char c = asciiText.charAt(i);
            String hex = Integer.toHexString((int) c).toUpperCase();
            if (hex.length() == 1) {
                hex = "0" + hex;
            }
            hexBuilder.append(hex);
        }
        return hexBuilder.toString();
    }

    // 十六进制字符串转ASCII字符串
    public static String hexStringToAscii(String hexString) {
        StringBuilder asciiBuilder = new StringBuilder();
        for (int i = 0; i < hexString.length(); i += 2) {
            String hexByte = hexString.substring(i, Math.min(i + 2, hexString.length()));
            int charValue = Integer.parseInt(hexByte, 16);
            asciiBuilder.append((char) charValue);
        }
        return asciiBuilder.toString();
    }

    // 加密ASCII文本（支持多字符）
    public static String encryptAscii(String asciiText, String keyHex) {
        StringBuilder result = new StringBuilder();
        String textHex = asciiToHexString(asciiText);
        int key = hexStringToInt(keyHex);

        // 每4个十六进制字符（16位）进行一次加密
        for (int i = 0; i < textHex.length(); i += 4) {
            String blockHex = textHex.substring(i, Math.min(i + 4, textHex.length()));
            // 如果不足4位，补0
            while (blockHex.length() < 4) {
                blockHex += "0";
            }
            int plaintext = hexStringToInt(blockHex);
            int ciphertext = encrypt(plaintext, key);
            result.append(intToHexString(ciphertext, 4));
        }
        return result.toString();
    }

    // 解密ASCII文本（支持多字符）
    public static String decryptAscii(String cipherHex, String keyHex) {
        StringBuilder result = new StringBuilder();
        int key = hexStringToInt(keyHex);

        // 每4个十六进制字符（16位）进行一次解密
        for (int i = 0; i < cipherHex.length(); i += 4) {
            String blockHex = cipherHex.substring(i, Math.min(i + 4, cipherHex.length()));
            int ciphertext = hexStringToInt(blockHex);
            int plaintext = decrypt(ciphertext, key);
            String plainHex = intToHexString(plaintext, 4);
            result.append(plainHex);
        }

        // 转换为ASCII
        return hexStringToAscii(result.toString());
    }

    // 加密A_K2 ∘ SR ∘ NS ∘ A_K1 ∘ MC ∘ SR ∘ NS ∘ A_K0
    public static int encrypt(int plaintext, int key) {
        int[] roundKeys = keyExpansion(key);
        int state = plaintext;

        // 第0轮：仅轮密钥加（A_K2）
        state ^= roundKeys[2];

        // 第1轮：SR → NS → 轮密钥加（A_K1）
        state = shiftRows(state);
        state = subNibbles(state);
        state ^= roundKeys[1];

        // 第2轮：MC→ SR → NS → 轮密钥加（A_K0）
        state = mixColumns(state);
        state = shiftRows(state);
        state = subNibbles(state);
        state ^= roundKeys[0];

        return state;
    }

    // 解密A_K0 ∘ INS ∘ ISR ∘ IMC ∘ A_K1 ∘ INS ∘ ISR ∘ A_K2
    public static int decrypt(int ciphertext, int key) {
        int[] roundKeys = keyExpansion(key);
        int state = ciphertext;

        // 第0逆轮：轮密钥加（A_K0）
        state ^= roundKeys[0];

        // 第1逆轮：逆半字节代替（INS）→ 逆行移位（ISR）→ 逆列混淆（IMC）→ 轮密钥加（A_K1）
        state = invSubNibbles(state);
        state = shiftRows(state);
        state = invMixColumns(state);
        state ^= roundKeys[1];

        // 第2逆轮：逆半字节代替（INS）→ 逆行移位（ISR）→ 轮密钥加（A_K2）
        state = invSubNibbles(state);
        state = shiftRows(state);
        state ^= roundKeys[2];

        return state;
    }

    public static int doubleEncrypt(int plaintext, String keyHex) {
        if (keyHex.length() != 8) {
            throw new IllegalArgumentException("双重加密需要8位十六进制密钥（32位）");
        }

        // 拆分32位密钥为两个16位密钥
        String key1Hex = keyHex.substring(0, 4);
        String key2Hex = keyHex.substring(4, 8);

        int key1 = hexStringToInt(key1Hex);
        int key2 = hexStringToInt(key2Hex);

        // 双重加密：先用key1加密，再用key2加密
        int intermediate = encrypt(plaintext, key1);
        return encrypt(intermediate, key2);
    }

    // 双重解密：使用32位密钥（K1+K2）
    public static int doubleDecrypt(int ciphertext, String keyHex) {
        if (keyHex.length() != 8) {
            throw new IllegalArgumentException("双重解密需要8位十六进制密钥（32位）");
        }

        // 拆分32位密钥为两个16位密钥
        String key1Hex = keyHex.substring(0, 4);
        String key2Hex = keyHex.substring(4, 8);

        int key1 = hexStringToInt(key1Hex);
        int key2 = hexStringToInt(key2Hex);

        // 双重解密：先用key2解密，再用key1解密
        int intermediate = decrypt(ciphertext, key2);
        return decrypt(intermediate, key1);
    }

    // 三重加密：使用48位密钥（K1+K2+K3）
    public static int tripleEncrypt(int plaintext, String keyHex) {
        if (keyHex.length() != 12) {
            throw new IllegalArgumentException("三重加密需要12位十六进制密钥（48位）");
        }

        // 拆分48位密钥为三个16位密钥
        String key1Hex = keyHex.substring(0, 4);
        String key2Hex = keyHex.substring(4, 8);
        String key3Hex = keyHex.substring(8, 12);

        int key1 = hexStringToInt(key1Hex);
        int key2 = hexStringToInt(key2Hex);
        int key3 = hexStringToInt(key3Hex);

        // 三重加密：先用key1加密，再用key2加密，最后用key3加密
        int intermediate1 = encrypt(plaintext, key1);
        int intermediate2 = encrypt(intermediate1, key2);
        return encrypt(intermediate2, key3);
    }

    // 三重解密：使用48位密钥（K1+K2+K3）
    public static int tripleDecrypt(int ciphertext, String keyHex) {
        if (keyHex.length() != 12) {
            throw new IllegalArgumentException("三重解密需要12位十六进制密钥（48位）");
        }

        // 拆分48位密钥为三个16位密钥
        String key1Hex = keyHex.substring(0, 4);
        String key2Hex = keyHex.substring(4, 8);
        String key3Hex = keyHex.substring(8, 12);

        int key1 = hexStringToInt(key1Hex);
        int key2 = hexStringToInt(key2Hex);
        int key3 = hexStringToInt(key3Hex);

        // 三重解密：先用key3解密，再用key2解密，最后用key1解密
        int intermediate1 = decrypt(ciphertext, key3);
        int intermediate2 = decrypt(intermediate1, key2);
        return decrypt(intermediate2, key1);
    }

    // ASCII文本双重加密
    public static String doubleEncryptAscii(String asciiText, String keyHex) {
        StringBuilder result = new StringBuilder();
        String textHex = asciiToHexString(asciiText);

        // 每4个十六进制字符（16位）进行一次双重加密
        for (int i = 0; i < textHex.length(); i += 4) {
            String blockHex = textHex.substring(i, Math.min(i + 4, textHex.length()));
            // 如果不足4位，补0
            while (blockHex.length() < 4) {
                blockHex += "0";
            }
            int plaintext = hexStringToInt(blockHex);
            int ciphertext = doubleEncrypt(plaintext, keyHex);
            result.append(intToHexString(ciphertext, 4));
        }
        return result.toString();
    }

    // ASCII文本双重解密
    public static String doubleDecryptAscii(String cipherHex, String keyHex) {
        StringBuilder result = new StringBuilder();

        // 每4个十六进制字符（16位）进行一次双重解密
        for (int i = 0; i < cipherHex.length(); i += 4) {
            String blockHex = cipherHex.substring(i, Math.min(i + 4, cipherHex.length()));
            int ciphertext = hexStringToInt(blockHex);
            int plaintext = doubleDecrypt(ciphertext, keyHex);
            String plainHex = intToHexString(plaintext, 4);
            result.append(plainHex);
        }

        // 转换为ASCII
        return hexStringToAscii(result.toString());
    }

    // ASCII文本三重加密
    public static String tripleEncryptAscii(String asciiText, String keyHex) {
        StringBuilder result = new StringBuilder();
        String textHex = asciiToHexString(asciiText);

        // 每4个十六进制字符（16位）进行一次三重加密
        for (int i = 0; i < textHex.length(); i += 4) {
            String blockHex = textHex.substring(i, Math.min(i + 4, textHex.length()));
            // 如果不足4位，补0
            while (blockHex.length() < 4) {
                blockHex += "0";
            }
            int plaintext = hexStringToInt(blockHex);
            int ciphertext = tripleEncrypt(plaintext, keyHex);
            result.append(intToHexString(ciphertext, 4));
        }
        return result.toString();
    }

    // ASCII文本三重解密
    public static String tripleDecryptAscii(String cipherHex, String keyHex) {
        StringBuilder result = new StringBuilder();

        // 每4个十六进制字符（16位）进行一次三重解密
        for (int i = 0; i < cipherHex.length(); i += 4) {
            String blockHex = cipherHex.substring(i, Math.min(i + 4, cipherHex.length()));
            int ciphertext = hexStringToInt(blockHex);
            int plaintext = tripleDecrypt(ciphertext, keyHex);
            String plainHex = intToHexString(plaintext, 4);
            result.append(plainHex);
        }

        // 转换为ASCII
        return hexStringToAscii(result.toString());
    }

    // 生成16位初始向量（IV）
    public static int generateIV() {
        return (int) (Math.random() * 0x10000) & 0xFFFF;
    }

    // CBC模式加密
    public static String cbcEncrypt(String plaintextHex, String keyHex, int iv) {
        if (plaintextHex.length() % 4 != 0) {
            throw new IllegalArgumentException("明文长度必须是4的倍数");
        }

        StringBuilder result = new StringBuilder();
        int previousBlock = iv; // 第一个块使用IV
        int key = hexStringToInt(keyHex);

        // 处理每个16位分组
        for (int i = 0; i < plaintextHex.length(); i += 4) {
            String blockHex = plaintextHex.substring(i, i + 4);
            int plaintextBlock = hexStringToInt(blockHex);

            // CBC模式：明文块与前一个密文块（或IV）异或
            int xorResult = plaintextBlock ^ previousBlock;

            // 加密异或结果
            int ciphertextBlock = encrypt(xorResult, key);

            // 添加到结果
            result.append(intToHexString(ciphertextBlock, 4));
            previousBlock = ciphertextBlock; // 更新前一个密文块
        }

        return result.toString();
    }

    // CBC模式解密
    public static String cbcDecrypt(String ciphertextHex, String keyHex, int iv) {
        if (ciphertextHex.length() % 4 != 0) {
            throw new IllegalArgumentException("密文长度必须是4的倍数");
        }

        StringBuilder result = new StringBuilder();
        int previousBlock = iv; // 第一个块使用IV
        int key = hexStringToInt(keyHex);

        // 处理每个16位分组
        for (int i = 0; i < ciphertextHex.length(); i += 4) {
            String blockHex = ciphertextHex.substring(i, i + 4);
            int ciphertextBlock = hexStringToInt(blockHex);

            // 解密当前密文块
            int decryptedBlock = decrypt(ciphertextBlock, key);

            // CBC模式：解密结果与前一个密文块（或IV）异或
            int plaintextBlock = decryptedBlock ^ previousBlock;

            // 添加到结果
            result.append(intToHexString(plaintextBlock, 4));
            previousBlock = ciphertextBlock; // 更新前一个密文块
        }

        return result.toString();
    }

    // ASCII文本CBC模式加密
    public static String cbcEncryptAscii(String asciiText, String keyHex, int iv) {
        String textHex = asciiToHexString(asciiText);
        // 确保长度是4的倍数
        while (textHex.length() % 4 != 0) {
            textHex += "0";
        }
        return cbcEncrypt(textHex, keyHex, iv);
    }

    // ASCII文本CBC模式解密
    public static String cbcDecryptAscii(String cipherHex, String keyHex, int iv) {
        String decryptedHex = cbcDecrypt(cipherHex, keyHex, iv);
        return hexStringToAscii(decryptedHex);
    }

    // 篡改密文分组（用于测试CBC模式的错误传播）
    public static String tamperCiphertext(String ciphertextHex, int blockIndex, String newBlockHex) {
        if (ciphertextHex.length() % 4 != 0) {
            throw new IllegalArgumentException("密文长度必须是4的倍数");
        }

        if (blockIndex < 0 || blockIndex * 4 >= ciphertextHex.length()) {
            throw new IllegalArgumentException("无效的分组索引");
        }

        if (newBlockHex.length() != 4) {
            throw new IllegalArgumentException("新分组必须是4位十六进制");
        }

        // 替换指定位置的密文分组
        int startIndex = blockIndex * 4;
        return ciphertextHex.substring(0, startIndex) + newBlockHex +
                ciphertextHex.substring(startIndex + 4);
    }

    // 测试CBC模式错误传播
    public static void testCBCErrorPropagation(String plaintextHex, String keyHex, int iv, int tamperBlockIndex) {
        System.out.println("=== CBC模式错误传播测试 ===");
        System.out.printf("明文: %s%n", plaintextHex);
        System.out.printf("密钥: %s%n", keyHex);
        System.out.printf("初始向量: 0x%04X%n", iv);

        // 正常加密
        String ciphertextHex = cbcEncrypt(plaintextHex, keyHex, iv);
        System.out.printf("正常加密结果: %s%n", ciphertextHex);

        // 正常解密
        String decryptedHex = cbcDecrypt(ciphertextHex, keyHex, iv);
        System.out.printf("正常解密结果: %s%n", decryptedHex);
        System.out.printf("解密是否正确: %s%n", decryptedHex.equals(plaintextHex) ? "是" : "否");

        // 篡改密文
        String tamperedCiphertext = tamperCiphertext(ciphertextHex, tamperBlockIndex, "FFFF");
        System.out.printf("篡改第%d个分组后的密文: %s%n", tamperBlockIndex, tamperedCiphertext);

        // 解密被篡改的密文
        String tamperedDecrypted = cbcDecrypt(tamperedCiphertext, keyHex, iv);
        System.out.printf("篡改后解密结果: %s%n", tamperedDecrypted);

        // 对比错误传播
        System.out.println("\n=== 错误传播分析 ===");
        for (int i = 0; i < plaintextHex.length(); i += 4) {
            String originalBlock = plaintextHex.substring(i, i + 4);
            String tamperedBlock = tamperedDecrypted.substring(i, Math.min(i + 4, tamperedDecrypted.length()));
            boolean isCorrect = originalBlock.equals(tamperedBlock);
            System.out.printf("分组%d: 原明文=%s, 解密结果=%s, 是否正确: %s%n",
                    i / 4, originalBlock, tamperedBlock, isCorrect ? "是" : "否");
        }
    }

    // 主函数：测试
    public static void main(String[] args) {
        int plaintext = 0x1234;
        int key = 0x2D55;

        System.out.println("--- S-AES 加密解密测试（修复后） ---");
        System.out.printf("明文（十六进制）: 0x%04X%n", plaintext);
        System.out.printf("密钥（十六进制）: 0x%04X%n", key);

        int[] roundKeys = keyExpansion(key);
        System.out.printf("扩展轮密钥 K0: 0x%04X（预期0x2D55）%n", roundKeys[0]);
        System.out.printf("扩展轮密钥 K1: 0x%04X（预期0xBCE9）%n", roundKeys[1]);
        System.out.printf("扩展轮密钥 K2: 0x%04X（预期0xA34A）%n", roundKeys[2]);

        // 加密
        int ciphertext = encrypt(plaintext, key);
        System.out.printf("加密后密文: 0x%04X（预期0x14EA）%n", ciphertext);

        // 解密
        int decrypted = decrypt(ciphertext, key);
        System.out.printf("解密后明文: 0x%04X（预期0x1234）%n", decrypted);

        // 结果验证
        if (decrypted == plaintext) {
            System.out.println("✅ 测试通过：解密结果与原明文一致！");
        } else {
            System.out.println("❌ 测试失败：解密结果与原明文不一致！");
        }

        System.out.println("\n--- 列混淆功能测试 ---");
        int testState = 0x6C40;
        int expectedMix = 0x3743;
        int actualMix = mixColumns(testState);
        System.out.printf("输入状态: 0x%04X%n", testState);
        System.out.printf("预期结果: 0x%04X%n", expectedMix);
        System.out.printf("实际结果: 0x%04X%n", actualMix);
        System.out.println(actualMix == expectedMix ? "✅ 列混淆测试通过！" : "❌ 列混淆测试失败！");

        System.out.println("=== S-AES CBC模式测试 ===");

        // 测试数据
        String plaintextHex = "123456789ABC"; // 3个16位分组
        String keyHex = "2D55";
        int iv = generateIV();

        System.out.println("1. 正常CBC加密解密测试:");
        testCBCErrorPropagation(plaintextHex, keyHex, iv, 1);

        System.out.println("\n2. 篡改第一个分组测试:");
        testCBCErrorPropagation(plaintextHex, keyHex, iv, 0);

        System.out.println("\n3. ASCII文本CBC模式测试:");
        String asciiText = "Hello";
        System.out.printf("ASCII明文: %s%n", asciiText);

        String asciiCipher = cbcEncryptAscii(asciiText, keyHex, iv);
        System.out.printf("CBC加密结果: %s%n", asciiCipher);

        String asciiDecrypted = cbcDecryptAscii(asciiCipher, keyHex, iv);
        System.out.printf("CBC解密结果: %s%n", asciiDecrypted);
        System.out.printf("解密是否正确: %s%n", asciiDecrypted.equals(asciiText) ? "是" : "否");

        System.out.println("\n请使用 toolUi.java 界面进行完整的CBC模式加密解密操作");
    }
}