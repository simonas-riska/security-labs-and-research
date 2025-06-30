using QRCoder;
using System;
namespace TaskNr2_2FA.QrHelper
{
    public class QrGenerator
    {

        public static string GenerateQrCodePayload(string payload)
        {
            var qrGenerator = new QRCodeGenerator();
            var qrCodeData = qrGenerator.CreateQrCode(payload, QRCodeGenerator.ECCLevel.Q);
            using (PngByteQRCode qrCode = new PngByteQRCode(qrCodeData))
            {
                byte[] qrCodeImage = qrCode.GetGraphic(20);
                var base64Image = Convert.ToBase64String(qrCodeImage);
                return $"data:image/png;base64,{base64Image}";
            }
        }
    }
}
