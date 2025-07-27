package org.vimal.security.v2.utils;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.qrcode.QRCodeWriter;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class QRUtility {
    private static final int DEFAULT_SIZE = 300;
    private static final String DEFAULT_IMAGE_FORMAT = "PNG";

    public static byte[] generateQRCode(String content) throws IOException, WriterException {
        return generateQRCode(content, DEFAULT_SIZE, DEFAULT_IMAGE_FORMAT);
    }

    public static byte[] generateQRCode(String content,
                                        int size,
                                        String format) throws WriterException, IOException {
        var qrCodeWriter = new QRCodeWriter();
        var bitMatrix = qrCodeWriter.encode(content, BarcodeFormat.QR_CODE, size, size);
        var outputStream = new ByteArrayOutputStream();
        MatrixToImageWriter.writeToStream(bitMatrix, format, outputStream);
        return outputStream.toByteArray();
    }
}
