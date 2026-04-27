using Microsoft.Win32;

using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

using System.Text;
using System.Text.RegularExpressions;

namespace ITLab3
{
    public partial class MainWindow : Window
    {
        private static readonly SolidColorBrush CORRECT_BLUE = new(Color.FromRgb(37, 99, 235));
        private static readonly SolidColorBrush ERROR_RED = new(Color.FromRgb(254, 226, 226));

        private static readonly Regex _numericRegex = NumericRegex();
        private byte[]? _cachedEncryptedBytes = null;
        private string _cachedFilePath = "";

        public MainWindow()
        {
            InitializeComponent();
        }

        private void FilterNonNumericInputs(object sender, TextCompositionEventArgs e)
        {
            e.Handled = _numericRegex.IsMatch(e.Text);
        }

        private void FilterNonNumericPasting(object sender, DataObjectPastingEventArgs e)
        {
            if (e.DataObject.GetDataPresent(typeof(string)))
            {
                string text = (string)e.DataObject.GetData(typeof(string));
                if (_numericRegex.IsMatch(text))
                    e.CancelCommand();
            }
            else e.CancelCommand();
        }

        private void EncryptInputs_TextChanged(object? sender, TextChangedEventArgs? e)
        {
            bool pValid = long.TryParse(TxtP.Text, out long p) && IsPrime(p);
            TxtP.Background = pValid || string.IsNullOrEmpty(TxtP.Text) ? Brushes.White : ERROR_RED;

            bool qValid = long.TryParse(TxtQ.Text, out long q) && IsPrime(q);
            TxtQ.Background = qValid || string.IsNullOrEmpty(TxtQ.Text) ? Brushes.White : ERROR_RED;

            long r = 0;
            TxtError.Text = "";

            bool rValid = false;
            if (pValid && qValid)
            {
                r = p * q;
                TxtCalcR.Text = r.ToString();
                rValid = 255 < r && r <= 65535;

                if (!rValid)
                {
                    TxtCalcR.Foreground = Brushes.Red;
                    TxtError.Text = "Requirement: 255 < r (p*q) <= 65535 to fit 8-bit into 16-bit blocks.";
                }
                else TxtCalcR.Foreground = CORRECT_BLUE;
            }
            else TxtCalcR.Text = "-";

            bool secretKeyValid = long.TryParse(TxtKsEncrypt.Text, out long secretKey);
            bool isCoprime = false;

            TxtCalcKo.Text = "-";
            TxtKsEncrypt.Background = ERROR_RED;
            if (pValid && qValid && secretKeyValid && rValid)
            {
                long phi = (p - 1) * (q - 1);

                if (1 < secretKey && secretKey < phi)
                {
                    isCoprime = EuclidEx(phi, secretKey, out _, out long openKey) == 1;

                    if (isCoprime)
                    {
                        TxtCalcKo.Text = (openKey < 0 ? openKey + phi : openKey).ToString();
                        TxtKsEncrypt.Background = Brushes.White;
                    }
                    else TxtError.Text = "Ks must be coprime to phi(r).";
                }
                else TxtError.Text = (1 < secretKey) ? "Ks must be below phi(r)." : "Ks must be above 1.";
            }

            bool fileValid = false;
            if (!string.IsNullOrWhiteSpace(TxtEncryptFilePath.Text) && File.Exists(TxtEncryptFilePath.Text))
            {
                long len = new FileInfo(TxtEncryptFilePath.Text).Length;
                
                if (len == 0)
                    TxtError.Text = "Selected file is empty.";
                else
                    fileValid = true;
            }

            BtnEncrypt.IsEnabled = pValid && qValid && secretKeyValid && rValid && isCoprime && fileValid;
        }

        private void DecryptInputs_TextChanged(object? sender, TextChangedEventArgs? e)
        {
            bool rValid = long.TryParse(TxtRDecrypt.Text, out long r);
            bool secretKeyValid = long.TryParse(TxtKsDecrypt.Text, out long secretKey);
            TxtErrorDecrypt.Text = "";

            TxtRDecrypt.Background = rValid || string.IsNullOrEmpty(TxtRDecrypt.Text) ? Brushes.White : ERROR_RED;

            if (secretKeyValid)
            {
                if (secretKey <= 1)
                {
                    secretKeyValid = false;
                    TxtErrorDecrypt.Text += "Ks must be above 1.";
                }
                else if (rValid && secretKey >= r)
                {
                    secretKeyValid = false;
                    TxtErrorDecrypt.Text += "Ks must be below r.";
                }
            }
            TxtKsDecrypt.Background = secretKeyValid || string.IsNullOrEmpty(TxtKsDecrypt.Text) ? Brushes.White : ERROR_RED;

            bool fileValid = false;
            if (!string.IsNullOrWhiteSpace(TxtDecryptFilePath.Text) && File.Exists(TxtDecryptFilePath.Text))
            {
                long len = new FileInfo(TxtDecryptFilePath.Text).Length;
                if (len == 0)
                    TxtErrorDecrypt.Text = "Selected file is empty.";
                else if (len % 2 != 0)
                    TxtErrorDecrypt.Text = "File must be even length (2n bytes).";
                else
                    fileValid = true;
            }

            BtnDecrypt.IsEnabled = rValid && secretKeyValid && fileValid;
        }

        private void BtnGenerate_Click(object sender, RoutedEventArgs e)
        {
            Random rnd = new();
            List<long> primes = GetPrimesUpTo(300);
            long p, q, r, phi, secretKey;

            do
            {
                p = primes[rnd.Next(primes.Count)];
                q = primes[rnd.Next(primes.Count)];
                r = p * q;
            } while (p == q || r <= 255 || r > 65535);

            phi = (p - 1) * (q - 1);
            do
            {
                secretKey = rnd.Next(3, (int)phi);
            } while (EuclidEx(phi, secretKey, out _, out _) != 1);

            TxtP.Text = p.ToString();
            TxtQ.Text = q.ToString();
            TxtKsEncrypt.Text = secretKey.ToString();
        }

        private static List<long> GetPrimesUpTo(long max)
        {
            var primes = new List<long>();

            for (long i = 2; i <= max; i++)
                if (IsPrime(i))
                    primes.Add(i);

            return primes;
        }

        private void BtnBrowseEncrypt_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog dlg = new();
            if (dlg.ShowDialog() == true)
            {
                TxtEncryptFilePath.Text = dlg.FileName;
                EncryptInputs_TextChanged(null, null);
            }
        }

        private void BtnBrowseDecrypt_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog dlg = new();
            if (dlg.ShowDialog() == true)
            {
                TxtDecryptFilePath.Text = dlg.FileName;
                DecryptInputs_TextChanged(null, null);
            }
        }

        private async void BtnEncrypt_Click(object sender, RoutedEventArgs e)
        {
            string filePath = TxtEncryptFilePath.Text;

            if (filePath == _cachedFilePath && _cachedEncryptedBytes != null)
            {
                SaveEncryptedFile(_cachedEncryptedBytes, filePath);
                return;
            }

            long p = long.Parse(TxtP.Text);
            long q = long.Parse(TxtQ.Text);
            long secretKey = long.Parse(TxtKsEncrypt.Text);

            long r = p * q;
            long phi = (p - 1) * (q - 1);

            EuclidEx(phi, secretKey, out _, out long openKey);
            if (openKey < 0) openKey += phi;

            PrgStatus.Value = 0;
            BtnEncrypt.IsEnabled = false;
            PrgStatus.Visibility = Visibility.Visible;
            TxtBase10Output.Text = "Encrypting file, please wait...";

            var progress = new Progress<int>(percent => PrgStatus.Value = percent);

            try
            {
                var (encryptedData, base10String) = await Task.Run(() => PerformEncryption(filePath, openKey, r, progress));

                _cachedEncryptedBytes = encryptedData;
                _cachedFilePath = filePath;

                TxtBase10Output.Text = base10String;

                SaveEncryptedFile(_cachedEncryptedBytes, filePath);
            }
            catch (Exception ex)
            {
                TxtError.Text = "Encryption failed.";
                MessageBox.Show(ex.Message, "Encryption Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                BtnEncrypt.IsEnabled = true;
                PrgStatus.Visibility = Visibility.Collapsed;
            }
        }

        private static (byte[] data, string display) PerformEncryption(string filePath, long openKey, long r, IProgress<int> progress)
        {
            using MemoryStream ms = new();
            using BinaryWriter bw = new(ms);
            StringBuilder base10Display = new();
            byte[] inputBytes = File.ReadAllBytes(filePath);

            for (int i = 0; i < inputBytes.Length; i++)
            {
                long c = FastExponent(inputBytes[i], openKey, r);

                if (i < 100)
                    base10Display.Append(c).Append(' ');
                else if (i == 100)
                    base10Display.Append($"... (showing first 100 of {inputBytes.Length} words)");

                bw.Write((ushort)c);

                if (i % Math.Max(1, inputBytes.Length / 20) == 0)
                    progress.Report((int)((double)i / inputBytes.Length * 100));
            }

            progress.Report(100);

            return (ms.ToArray(), base10Display.ToString());
        }

        private static void SaveEncryptedFile(byte[] data, string originalFilePath)
        {
            string defaultName = Path.GetFileName(originalFilePath) + ".crypt";

            SaveFileDialog dlg = new()
            {
                Title = "Save Encrypted File",
                FileName = defaultName,
                Filter = "Encrypted Files (*.crypt)|*.crypt|All Files (*.*)|*.*"
            };

            if (dlg.ShowDialog() == true)
                File.WriteAllBytes(dlg.FileName, data);
        }

        private async void BtnDecrypt_Click(object sender, RoutedEventArgs e)
        {
            long r = long.Parse(TxtRDecrypt.Text);
            string filePath = TxtDecryptFilePath.Text;
            long secretKey = long.Parse(TxtKsDecrypt.Text);

            PrgStatus.Value = 0;
            BtnDecrypt.IsEnabled = false;
            PrgStatus.Visibility = Visibility.Visible;
            TxtBase10OutputDecrypt.Text = "Decrypting file, please wait...";

            var progress = new Progress<int>(percent => PrgStatus.Value = percent);

            try
            {
                var (decryptedData, base10String) = await Task.Run(() => PerformDecryption(filePath, secretKey, r, progress));

                TxtBase10OutputDecrypt.Text = base10String;

                string defaultFileName = Path.GetFileName(filePath);
                if (defaultFileName.EndsWith(".crypt", StringComparison.OrdinalIgnoreCase))
                    defaultFileName = defaultFileName[..^6]; // removes the last 6 characters

                SaveFileDialog dlg = new()
                {
                    Title = "Save Decrypted File",
                    FileName = defaultFileName
                };

                if (dlg.ShowDialog() == true)
                    File.WriteAllBytes(dlg.FileName, decryptedData);
            }
            catch (Exception ex)
            {
                TxtErrorDecrypt.Text = "Decryption failed.";
                MessageBox.Show(ex.Message, "Decryption Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                BtnDecrypt.IsEnabled = true;
                PrgStatus.Visibility = Visibility.Collapsed;
            }
        }

        private static (byte[] data, string display) PerformDecryption(string filePath, long secretKey, long r, IProgress<int> progress)
        {
            byte[] encryptedBytes = File.ReadAllBytes(filePath);
            
            if (encryptedBytes.Length % 2 != 0)
                throw new Exception("File length is not a multiple of 16-bit blocks.");

            using MemoryStream ms = new();
            StringBuilder base10Display = new();

            int totalBlocks = encryptedBytes.Length / 2;

            for (int i = 0; i < encryptedBytes.Length; i += 2)
            {
                ushort c = BitConverter.ToUInt16(encryptedBytes, i);
                long m = FastExponent(c, secretKey, r);
                ms.WriteByte((byte)m);

                int currentBlock = i / 2;

                if (currentBlock < 100)
                    base10Display.Append(m).Append(' ');
                else if (currentBlock == 100)
                    base10Display.Append($"... (showing 100 of {totalBlocks} words)");

                if (currentBlock % Math.Max(1, totalBlocks / 20) == 0)
                    progress.Report((int)((double)currentBlock / totalBlocks * 100));
            }

            progress.Report(100);
            return (ms.ToArray(), base10Display.ToString());
        }

        private static long FastExponent(long a, long z, long n)
        {
            long a1 = a;
            long z1 = z;
            long x = 1;

            while (z1 != 0)
            {
                while (z1 % 2 == 0)
                {
                    z1 /= 2;
                    a1 = (a1 * a1) % n;
                }
                z1--;
                x = (x * a1) % n;
            }
            return x;
        }

        private static long EuclidEx(long a, long b, out long x1Result, out long y1Result)
        {
            long d0 = a, d1 = b;
            long x0 = 1, x1 = 0;
            long y0 = 0, y1 = 1;

            while (d1 > 1)
            {
                long q = d0 / d1;
                long d2 = d0 % d1;
                long x2 = x0 - q * x1;
                long y2 = y0 - q * y1;

                d0 = d1; d1 = d2;
                x0 = x1; x1 = x2;
                y0 = y1; y1 = y2;
            }

            x1Result = x1;
            y1Result = y1;
            return d1;
        }

        private static bool IsPrime(long number)
        {
            if (number <= 1) return false;
            if (number <= 3) return true;

            if (number % 2 == 0 || number % 3 == 0) return false;

            for (long i = 5; i * i <= number; i += 6)
                if (number % i == 0 || number % (i + 2) == 0)
                    return false;

            return true;
        }

        [GeneratedRegex("[^0-9]+")]
        private static partial Regex NumericRegex();
    }
}