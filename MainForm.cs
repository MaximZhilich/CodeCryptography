/*
 * Для изменения этого шаблона используйте Сервис | Настройка | Кодирование | Правка стандартных заголовков.
 */
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Windows.Forms;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using System.Xml.Linq;

namespace EDS_File
{
    /// <summary>
    /// Description of MainForm.
    /// </summary>
    public partial class MainForm : Form
    {
        OpenFileDialog openfile = new OpenFileDialog();
        SaveFileDialog save_encrypt = new SaveFileDialog();
        string ext1,ext2;
        string fName_enc, fName_dec;

        public MainForm ( ) {
            //
            // The InitializeComponent() call is required for Windows Forms designer support.
            //
            InitializeComponent();

           
            Console.ReadLine();
        }

        void Button1Click ( object sender, EventArgs e ) {
            string dest = Path.Combine(
                Application.StartupPath,
                "keys"
                );

            Directory.CreateDirectory( dest );
            dest = Path.Combine(
                dest,
                Path.GetFileName( textBox1.Text ) +
                ".key"
                );

            using ( var fs = File.Open( dest, FileMode.Create, FileAccess.Write ) )
            using (var aes = new AesCryptoServiceProvider())


            {
                // Создаем генератор случайных чисел
                
                var rnd = RNGCryptoServiceProvider.Create();
                // Создаем буфер, равный длине ключа, и длине вектора (16 байт)
                byte[] buff0 = new byte[aes.KeySize / 8],
                       buff1 = new byte[16];
               // Console.Write(buff0);
                //// Заполняем ключ случайными числами
                rnd.GetNonZeroBytes(buff0);
                // Заполняем вектор случайными числами
                rnd.GetNonZeroBytes(buff1);

                fs.Write(buff0, 0, buff0.Length);// Пишем ключ в файл
                fs.Write(buff1, 0, buff1.Length);// Пишем вектор в файл
                //Криптуем!
                CryptFile(
                    textBox1.Text,
                    textBox1.Text,
                    aes, buff0, buff1
                    );
            }
        }

        void Button3Click ( object sender, EventArgs e ) {
            if ( openfile.ShowDialog() == DialogResult.OK ) {
                textBox1.Text = openfile.FileName;
                ext1 = Path.GetExtension( textBox1.Text );
                fName_enc = Path.GetFileNameWithoutExtension( openfile.FileName );
            }
        }

        void Button4Click ( object sender, EventArgs e ) {
            if ( openfile.ShowDialog() == DialogResult.OK ) {
                textBox2.Text = openfile.FileName;
                ext2 = Path.GetExtension( textBox2.Text );
                fName_dec = Path.GetFileNameWithoutExtension( openfile.FileName );
            }
        }

        void Button2Click ( object sender, EventArgs e ) {
            string dest = Path.Combine(
                Application.StartupPath,
                "keys",
                Path.GetFileNameWithoutExtension( textBox2.Text ) +
                ".key"
                );

            using ( var fs = File.Open( dest, FileMode.Open, FileAccess.Read ) )
            using ( var aes = new AesCryptoServiceProvider() ) {
                byte[] buff0 = new byte[aes.KeySize / 8],
                       buff1 = new byte[16];

                fs.Read( buff0, 0, buff0.Length );
                fs.Read( buff1, 0, buff1.Length );
                //Декрипт
                DecryptFile(
                    textBox2.Text,
                    Path.Combine(
                        Path.GetDirectoryName( textBox2.Text ),
                        Path.GetFileNameWithoutExtension( textBox2.Text )
                        ),
                    aes, buff0, buff1
                    );
            }
        }

        private void MainForm_Load(object sender, EventArgs e)
        {

        }

        static void CryptFile ( string fileIn, string fileOut, SymmetricAlgorithm algo, byte[] rgbKey, byte[] rgbIV ) {
            if ( string.IsNullOrEmpty( fileIn ) )
                throw new FileNotFoundException( string.Format( "Неверный путь к файлу: {0}.", fileIn ) );

            if ( !File.Exists( fileIn ) )
                throw new FileNotFoundException( string.Format( "Файл '{0}' не найден.", fileIn ) );


            byte[] buff = null;
            const string CRYPT_EXT = ".crypt";

            var sa = algo;// using
            // Создаем поток для записи зашифрованных данных
            using ( var fsw = File.Open( fileOut + CRYPT_EXT, FileMode.Create, FileAccess.Write ) )
            // Создаем крипто-поток для записи
            using ( var cs = new CryptoStream( fsw,
                sa.CreateEncryptor( rgbKey, rgbIV ), CryptoStreamMode.Write )
                ) {
                // Читаем исходный файл
                using (var fs = File.Open(fileIn, FileMode.Open, FileAccess.Read))
                // Создаем буфер длинной в файл + 8 байт, для хранения изначальной
                // длины файла, т.к. при шифровании используется выравнивание по
                // определенной длине блока (например 512 байт, или 1024)
                // тем самым файл может немного "раздуть" и оригинал при дешифровке
                // мы уже не получим

                {
                    buff = new byte[fs.Length + sizeof(long)];
                    // Читаем данные в буфер не с самого начала, а со смещением 8 байт
                    fs.Read(buff, sizeof(long), buff.Length - sizeof(long));
                    /* Записываем в первые 8 байт длину исходного файла
                     * нужно это для того чтобы, после дешифровки не было
                     * лишних данных
                     */
                    int i = 0;
                    //перевод значения из лонг в байт
                    foreach (byte @byte in BitConverter.GetBytes(fs.Length))
                        buff[i++] = @byte;
                }

                cs.Write( buff, 0, buff.Length );
                cs.Flush();
            }

            Array.Clear( rgbKey, 0, rgbKey.Length );
            Array.Clear( rgbIV, 0, rgbIV.Length );
        }

        static void DecryptFile ( string fileIn, string fileOut, SymmetricAlgorithm algo, byte[] rgbKey, byte[] rgbIV ) {
            if ( string.IsNullOrEmpty( fileIn ) )
                throw new FileNotFoundException( string.Format( "Неверный путь к файлу: {0}.", fileIn ) );

            if ( !File.Exists( fileIn ) )
                throw new FileNotFoundException( string.Format( "Файл '{0}' не найден.", fileIn ) );

            byte[] buff = null;
            const string DECRYPT_EXT = ".decrypt";

            using ( var sa = algo )
            // Создаем поток для чтения шифрованных данных
            using ( var fsr = File.Open( fileIn, FileMode.Open, FileAccess.Read ) )
            // Создаем крипто-поток для чтения
            using ( var cs = new CryptoStream( fsr,
                sa.CreateDecryptor( rgbKey, rgbIV ), CryptoStreamMode.Read )
                ) {
                // Дешифровываем исходный поток данных
                buff = new byte[fsr.Length];
                cs.Read( buff, 0, buff.Length );
                // Пишем дешифрованные данные
                using (var fsw = File.Open(fileOut + DECRYPT_EXT, FileMode.Create, FileAccess.Write))
                {
                    // Читаем записанную длину исходного файла
                    int len = (int)BitConverter.ToInt64(buff, 0);
                    // Пишем только ту часть дешифрованных данных,
                    // которая представляет исходный файл
                    fsw.Write(buff, sizeof(long), len);
                    fsw.Flush();
                }
            }

            Array.Clear( rgbKey, 0, rgbKey.Length );
            Array.Clear( rgbIV, 0, rgbIV.Length );
        }
    }
}