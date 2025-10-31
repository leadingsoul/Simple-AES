package S_AES;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class toolUi {
    private JFrame frame;
    private JTextField inputField;
    private JTextField keyField;
    private JTextField resultField;
    private JTextField ivField; // 新增：初始向量输入框
    private JButton encryptButton;
    private JButton decryptButton;
    private JLabel inputLabel;
    private JLabel keyLabel;
    private JLabel ivLabel; // 新增：初始向量标签
    private JComboBox<String> modeComboBox;
    private JComboBox<String> encryptionModeComboBox; // 新增：加密模式选择

    public toolUi() {
        initialize();
    }

    private void initialize() {
        frame = new JFrame("S-AES 加密工具");
        frame.setBounds(100, 100, 600, 550); // 增加窗口高度以容纳新控件
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.getContentPane().setLayout(new GridLayout(8, 2, 10, 10)); // 增加行数

        // 模式选择
        JLabel modeLabel = new JLabel("输入模式:");
        frame.getContentPane().add(modeLabel);

        String[] modes = { "十六进制", "ASCII码" };
        modeComboBox = new JComboBox<>(modes);
        modeComboBox.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                updateLabels();
            }
        });
        frame.getContentPane().add(modeComboBox);

        // 加密模式选择
        JLabel encryptionModeLabel = new JLabel("加密模式:");
        frame.getContentPane().add(encryptionModeLabel);

        String[] encryptionModes = { "单重加密", "双重加密", "三重加密", "CBC模式" };
        encryptionModeComboBox = new JComboBox<>(encryptionModes);
        encryptionModeComboBox.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                updateKeyLabel();
                updateIVFieldVisibility();
            }
        });
        frame.getContentPane().add(encryptionModeComboBox);

        // 输入标签和文本框
        inputLabel = new JLabel("明文 (4位十六进制):");
        frame.getContentPane().add(inputLabel);

        inputField = new JTextField();
        inputField.setText("0000"); // 默认值
        frame.getContentPane().add(inputField);
        inputField.setColumns(20);

        // 密钥标签和文本框
        keyLabel = new JLabel("密钥 (4位十六进制):");
        frame.getContentPane().add(keyLabel);

        keyField = new JTextField();
        keyField.setText("2D55"); // 默认值
        frame.getContentPane().add(keyField);
        keyField.setColumns(20);

        // 初始向量标签和文本框
        ivLabel = new JLabel("初始向量 (4位十六进制):");
        frame.getContentPane().add(ivLabel);

        ivField = new JTextField();
        ivField.setText(SAES.intToHexString(SAES.generateIV(), 4)); // 默认生成随机IV
        frame.getContentPane().add(ivField);
        ivField.setColumns(20);

        // 结果标签和文本框
        JLabel resultLabel = new JLabel("结果:");
        frame.getContentPane().add(resultLabel);

        resultField = new JTextField();
        resultField.setEditable(false);
        frame.getContentPane().add(resultField);
        resultField.setColumns(20);

        // 加密按钮
        encryptButton = new JButton("加密");
        encryptButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                performEncryption();
            }
        });
        frame.getContentPane().add(encryptButton);

        // 解密按钮
        decryptButton = new JButton("解密");
        decryptButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                performDecryption();
            }
        });
        frame.getContentPane().add(decryptButton);

        // 清空按钮
        JButton clearButton = new JButton("清空");
        clearButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                inputField.setText("");
                keyField.setText("");
                resultField.setText("");
                ivField.setText(SAES.intToHexString(SAES.generateIV(), 4)); // 重置IV
            }
        });
        frame.getContentPane().add(clearButton);

        // 篡改测试按钮
        JButton tamperButton = new JButton("篡改测试");
        tamperButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                performTamperTest();
            }
        });
        frame.getContentPane().add(tamperButton);

        // 初始隐藏IV字段（非CBC模式时）
        updateIVFieldVisibility();

        // 设置窗口可见
        frame.setVisible(true);
    }

    private void updateLabels() {
        String mode = (String) modeComboBox.getSelectedItem();
        String encryptionMode = (String) encryptionModeComboBox.getSelectedItem();

        if ("ASCII码".equals(mode)) {
            if ("CBC模式".equals(encryptionMode)) {
                inputLabel.setText("明文 (ASCII文本):");
            } else {
                inputLabel.setText("明文 (ASCII文本):");
            }
            updateKeyLabel();
        } else {
            if ("CBC模式".equals(encryptionMode)) {
                inputLabel.setText("明文 (十六进制，长度需为4的倍数):");
            } else {
                inputLabel.setText("明文 (4位十六进制):");
            }
            updateKeyLabel();
        }
    }

    private void updateKeyLabel() {
        String encryptionMode = (String) encryptionModeComboBox.getSelectedItem();

        if ("双重加密".equals(encryptionMode)) {
            keyLabel.setText("密钥 (8位十六进制):");
        } else if ("三重加密".equals(encryptionMode)) {
            keyLabel.setText("密钥 (12位十六进制):");
        } else {
            keyLabel.setText("密钥 (4位十六进制):");
        }
    }

    private void updateIVFieldVisibility() {
        String encryptionMode = (String) encryptionModeComboBox.getSelectedItem();
        boolean isCBCMode = "CBC模式".equals(encryptionMode);

        ivLabel.setVisible(isCBCMode);
        ivField.setVisible(isCBCMode);

        // 调整布局
        frame.getContentPane().revalidate();
        frame.getContentPane().repaint();
    }

    private void performEncryption() {
        try {
            String mode = (String) modeComboBox.getSelectedItem();
            String encryptionMode = (String) encryptionModeComboBox.getSelectedItem();
            String inputText = inputField.getText().trim();
            String keyHex = keyField.getText().trim().toUpperCase();

            // 根据加密模式检查密钥格式
            String keyPattern;
            switch (encryptionMode) {
                case "双重加密":
                    keyPattern = "[0-9A-F]{8}";
                    break;
                case "三重加密":
                    keyPattern = "[0-9A-F]{12}";
                    break;
                case "CBC模式":
                    keyPattern = "[0-9A-F]{4}";
                    break;
                default:
                    keyPattern = "[0-9A-F]{4}";
                    break;
            }

            if (!keyHex.matches(keyPattern)) {
                JOptionPane.showMessageDialog(frame,
                        "请输入" + getKeyLengthDescription(encryptionMode) + "作为密钥",
                        "输入错误", JOptionPane.ERROR_MESSAGE);
                return;
            }

            if ("CBC模式".equals(encryptionMode)) {
                // CBC模式特殊处理
                String ivHex = ivField.getText().trim().toUpperCase();
                if (!ivHex.matches("[0-9A-F]{4}")) {
                    JOptionPane.showMessageDialog(frame, "请输入4位十六进制数作为初始向量", "输入错误", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                int iv = SAES.hexStringToInt(ivHex);

                if ("ASCII码".equals(mode)) {
                    // ASCII模式CBC加密
                    if (inputText.isEmpty()) {
                        JOptionPane.showMessageDialog(frame, "请输入ASCII文本", "输入错误", JOptionPane.ERROR_MESSAGE);
                        return;
                    }

                    String cipherHex = SAES.cbcEncryptAscii(inputText, keyHex, iv);
                    resultField.setText(SAES.hexStringToAscii(cipherHex));
                    inputLabel.setText("密文 (ASCII文本):");

                } else {
                    // 十六进制模式CBC加密
                    String plaintextHex = inputText.toUpperCase();
                    if (plaintextHex.length() % 4 != 0) {
                        JOptionPane.showMessageDialog(frame, "明文长度必须是4的倍数", "输入错误", JOptionPane.ERROR_MESSAGE);
                        return;
                    }

                    String ciphertextHex = SAES.cbcEncrypt(plaintextHex, keyHex, iv);
                    resultField.setText(ciphertextHex);
                    inputLabel.setText("密文 (十六进制):");
                }

            } else if ("ASCII码".equals(mode)) {
                // ASCII模式加密（非CBC）
                if (inputText.isEmpty()) {
                    JOptionPane.showMessageDialog(frame, "请输入ASCII文本", "输入错误", JOptionPane.ERROR_MESSAGE);
                    return;
                }

                String cipherHex;
                switch (encryptionMode) {
                    case "双重加密":
                        cipherHex = SAES.doubleEncryptAscii(inputText, keyHex);
                        break;
                    case "三重加密":
                        cipherHex = SAES.tripleEncryptAscii(inputText, keyHex);
                        break;
                    default:
                        cipherHex = SAES.encryptAscii(inputText, keyHex);
                        break;
                }

                resultField.setText(SAES.hexStringToAscii(cipherHex));
                inputLabel.setText("密文 (ASCII文本):");

            } else {
                // 十六进制模式加密（非CBC）
                String plaintextHex = inputText.toUpperCase();
                if (!plaintextHex.matches("[0-9A-F]{4}")) {
                    JOptionPane.showMessageDialog(frame, "请输入4位十六进制数作为明文", "输入错误", JOptionPane.ERROR_MESSAGE);
                    return;
                }

                int plaintext = SAES.hexStringToInt(plaintextHex);
                int ciphertext;

                switch (encryptionMode) {
                    case "双重加密":
                        ciphertext = SAES.doubleEncrypt(plaintext, keyHex);
                        break;
                    case "三重加密":
                        ciphertext = SAES.tripleEncrypt(plaintext, keyHex);
                        break;
                    default:
                        ciphertext = SAES.encrypt(plaintext, SAES.hexStringToInt(keyHex));
                        break;
                }

                resultField.setText(SAES.intToHexString(ciphertext, 4));
                inputLabel.setText("密文 (4位十六进制):");
            }

        } catch (NumberFormatException ex) {
            JOptionPane.showMessageDialog(frame, "无效的十六进制格式", "错误", JOptionPane.ERROR_MESSAGE);
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(frame, "加密过程中发生错误: " + ex.getMessage(),
                    "错误", JOptionPane.ERROR_MESSAGE);
            ex.printStackTrace();
        }
    }

    private void performDecryption() {
        try {
            String mode = (String) modeComboBox.getSelectedItem();
            String encryptionMode = (String) encryptionModeComboBox.getSelectedItem();
            String inputText = inputField.getText().trim();
            String keyHex = keyField.getText().trim().toUpperCase();

            // 根据加密模式检查密钥格式
            String keyPattern;
            switch (encryptionMode) {
                case "双重加密":
                    keyPattern = "[0-9A-F]{8}";
                    break;
                case "三重加密":
                    keyPattern = "[0-9A-F]{12}";
                    break;
                case "CBC模式":
                    keyPattern = "[0-9A-F]{4}";
                    break;
                default:
                    keyPattern = "[0-9A-F]{4}";
                    break;
            }

            if (!keyHex.matches(keyPattern)) {
                JOptionPane.showMessageDialog(frame,
                        "请输入" + getKeyLengthDescription(encryptionMode) + "作为密钥",
                        "输入错误", JOptionPane.ERROR_MESSAGE);
                return;
            }

            if ("CBC模式".equals(encryptionMode)) {
                // CBC模式特殊处理
                String ivHex = ivField.getText().trim().toUpperCase();
                if (!ivHex.matches("[0-9A-F]{4}")) {
                    JOptionPane.showMessageDialog(frame, "请输入4位十六进制数作为初始向量", "输入错误", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                int iv = SAES.hexStringToInt(ivHex);

                if ("ASCII码".equals(mode)) {
                    // ASCII模式CBC解密
                    if (inputText.isEmpty()) {
                        JOptionPane.showMessageDialog(frame, "请输入ASCII密文", "输入错误", JOptionPane.ERROR_MESSAGE);
                        return;
                    }

                    String cipherHex = SAES.asciiToHexString(inputText);
                    String plaintext = SAES.cbcDecryptAscii(cipherHex, keyHex, iv);
                    resultField.setText(plaintext);
                    inputLabel.setText("明文 (ASCII文本):");

                } else {
                    // 十六进制模式CBC解密
                    String ciphertextHex = inputText.toUpperCase();
                    if (ciphertextHex.length() % 4 != 0) {
                        JOptionPane.showMessageDialog(frame, "密文长度必须是4的倍数", "输入错误", JOptionPane.ERROR_MESSAGE);
                        return;
                    }

                    String plaintextHex = SAES.cbcDecrypt(ciphertextHex, keyHex, iv);
                    resultField.setText(plaintextHex);
                    inputLabel.setText("明文 (十六进制):");
                }

            } else if ("ASCII码".equals(mode)) {
                // ASCII模式解密（非CBC）
                if (inputText.isEmpty()) {
                    JOptionPane.showMessageDialog(frame, "请输入ASCII密文", "输入错误", JOptionPane.ERROR_MESSAGE);
                    return;
                }

                String cipherHex = SAES.asciiToHexString(inputText);
                String plaintext;

                switch (encryptionMode) {
                    case "双重加密":
                        plaintext = SAES.doubleDecryptAscii(cipherHex, keyHex);
                        break;
                    case "三重加密":
                        plaintext = SAES.tripleDecryptAscii(cipherHex, keyHex);
                        break;
                    default:
                        plaintext = SAES.decryptAscii(cipherHex, keyHex);
                        break;
                }

                resultField.setText(plaintext);
                inputLabel.setText("明文 (ASCII文本):");

            } else {
                // 十六进制模式解密（非CBC）
                String ciphertextHex = inputText.toUpperCase();
                if (!ciphertextHex.matches("[0-9A-F]{4}")) {
                    JOptionPane.showMessageDialog(frame, "请输入4位十六进制数作为密文", "输入错误", JOptionPane.ERROR_MESSAGE);
                    return;
                }

                int ciphertext = SAES.hexStringToInt(ciphertextHex);
                int plaintext;

                switch (encryptionMode) {
                    case "双重加密":
                        plaintext = SAES.doubleDecrypt(ciphertext, keyHex);
                        break;
                    case "三重加密":
                        plaintext = SAES.tripleDecrypt(ciphertext, keyHex);
                        break;
                    default:
                        plaintext = SAES.decrypt(ciphertext, SAES.hexStringToInt(keyHex));
                        break;
                }

                resultField.setText(SAES.intToHexString(plaintext, 4));
                inputLabel.setText("明文 (4位十六进制):");
            }

        } catch (NumberFormatException ex) {
            JOptionPane.showMessageDialog(frame, "无效的十六进制格式", "错误", JOptionPane.ERROR_MESSAGE);
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(frame, "解密过程中发生错误: " + ex.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void performTamperTest() {
        try {
            String mode = (String) modeComboBox.getSelectedItem();
            String encryptionMode = (String) encryptionModeComboBox.getSelectedItem();

            if (!"CBC模式".equals(encryptionMode)) {
                JOptionPane.showMessageDialog(frame, "篡改测试仅适用于CBC模式", "提示", JOptionPane.INFORMATION_MESSAGE);
                return;
            }

            String inputText = inputField.getText().trim();
            String keyHex = keyField.getText().trim().toUpperCase();
            String ivHex = ivField.getText().trim().toUpperCase();

            if (!ivHex.matches("[0-9A-F]{4}")) {
                JOptionPane.showMessageDialog(frame, "请输入4位十六进制数作为初始向量", "输入错误", JOptionPane.ERROR_MESSAGE);
                return;
            }
            int iv = SAES.hexStringToInt(ivHex);

            if ("ASCII码".equals(mode)) {
                if (inputText.isEmpty()) {
                    JOptionPane.showMessageDialog(frame, "请输入ASCII文本进行测试", "输入错误", JOptionPane.ERROR_MESSAGE);
                    return;
                }

                // 正常加密
                String cipherHex = SAES.cbcEncryptAscii(inputText, keyHex, iv);

                // 篡改第二个分组
                String tamperedCipher = SAES.tamperCiphertext(cipherHex, 1, "FFFF");

                // 正常解密
                String normalDecrypted = SAES.cbcDecryptAscii(cipherHex, keyHex, iv);

                // 篡改后解密
                String tamperedDecrypted = SAES.cbcDecryptAscii(tamperedCipher, keyHex, iv);

                // 显示结果对比
                String result = "=== CBC模式篡改测试结果 ===\n" +
                        "原始明文: " + inputText + "\n" +
                        "正常解密: " + normalDecrypted + "\n" +
                        "篡改后解密: " + tamperedDecrypted + "\n" +
                        "错误传播分析: 第二个分组及之后的分组会受到影响";

                resultField.setText(result);

            } else {
                String plaintextHex = inputText.toUpperCase();
                if (plaintextHex.length() % 4 != 0) {
                    JOptionPane.showMessageDialog(frame, "明文长度必须是4的倍数", "输入错误", JOptionPane.ERROR_MESSAGE);
                    return;
                }

                // 执行篡改测试
                SAES.testCBCErrorPropagation(plaintextHex, keyHex, iv, 1);
                resultField.setText("请查看控制台输出获取详细的篡改测试结果");
            }

        } catch (Exception ex) {
            JOptionPane.showMessageDialog(frame, "篡改测试过程中发生错误: " + ex.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
        }
    }

    private String getKeyLengthDescription(String encryptionMode) {
        switch (encryptionMode) {
            case "双重加密":
                return "8位十六进制数（32位）";
            case "三重加密":
                return "12位十六进制数（48位）";
            case "CBC模式":
                return "4位十六进制数（16位）";
            default:
                return "4位十六进制数（16位）";
        }
    }

    public static void main(String[] args) {
        // 在事件调度线程中创建和显示GUI
        EventQueue.invokeLater(new Runnable() {
            public void run() {
                try {
                    new toolUi();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
    }
}