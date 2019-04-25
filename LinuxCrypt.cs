using System;
using System.Text;
using System.Security.Cryptography;
using System.IO;

namespace GLibcCrypt
{
    class LinuxCrypt
    {
        /// <summary>
        ///     <para><c>Crypt</c></para>
        ///     <para>C# implementation of glibc crypt() function.</para>
        /// </summary>
        /// <param name="key">
        ///     <para>The clear-text string.</para>
        /// </param>
        /// <param name="salt">
        ///     <para>The GLIBC-formatted salt string.</para>
        ///     <example>
        ///         <para>MD5: $1$ABC123abc</para>
        ///         <para>SHA256: $5$ABC123abc</para>
        ///         <para>SHA256 with rounds: $5$rounds=10000$ABC123abc</para>
        ///         <para>SHA512: $6$ABC123abc</para>
        ///         <para>SHA512 with rounds: $6$rounds=10000$ABC123abc</para>
        ///     </example>
        /// </param>
        /// <returns>
        ///     <para>The hash string without any header which is 
        ///     different with the Glibc implementation.</para>
        /// </returns>
        public static string Crypt(string key, string salt)
        {
            return Crypt(Encoding.ASCII.GetBytes(key), Encoding.ASCII.GetBytes(salt));
        }

        /// <summary>
        ///     <para><c>Crypt</c></para>
        ///     <para>C# implementation of glibc crypt() function.</para>
        /// </summary>
        /// <param name="key">
        ///     <para>The clear-text buffer.</para>
        /// </param>
        /// <param name="salt">
        ///     <para>The GLIBC-formatted salt buffer.</para>
        ///     <example>
        ///         <para>MD5: $1$ABC123abc</para>
        ///         <para>SHA256: $5$ABC123abc</para>
        ///         <para>SHA256 with rounds: $5$rounds=10000$ABC123abc</para>
        ///         <para>SHA512: $6$ABC123abc</para>
        ///         <para>SHA512 with rounds: $6$rounds=10000$ABC123abc</para>
        ///     </example>
        /// </param>
        /// <returns>
        ///     <para>The hash string without any header which is 
        ///     different with the Glibc implementation.</para>
        /// </returns>
        public static string Crypt(Byte[] key, Byte[] salt)
        {
            Byte[] md5_header = { (byte)'$', (byte)'1', (byte)'$' };
            Byte[] sha256_header = { (byte)'$', (byte)'5', (byte)'$' };
            Byte[] sha512_header = { (byte)'$', (byte)'6', (byte)'$' };
            Byte[] rounds_header = Encoding.ASCII.GetBytes("rounds=");
            int rounds = 5000;
            int clean_salt_index;
            byte[] clean_salt;

            if (__ncmp(salt, md5_header, md5_header.Length))
            {
                clean_salt = new byte[salt.Length - md5_header.Length];
                clean_salt_index = md5_header.Length;
                Array.Copy(salt, md5_header.Length, clean_salt, 0, salt.Length - clean_salt_index);
                return MD5Crypt(key, clean_salt);
            }

            if (__ncmp(salt, sha256_header, sha256_header.Length))
            {
                clean_salt_index = sha256_header.Length;
                if (__ncmp(salt, sha256_header.Length, rounds_header, 0, rounds_header.Length))
                {
                    rounds = __atoi(salt, sha256_header.Length + rounds_header.Length, ref clean_salt_index);
                    if (salt[clean_salt_index++] != (byte)'$')
                    {
                        return null;
                    }
                }
                clean_salt = new byte[salt.Length - clean_salt_index];
                Array.Copy(salt, clean_salt_index, clean_salt, 0, salt.Length - clean_salt_index);
                return SHA256Crypt(key, clean_salt, rounds);
            }

            if (__ncmp(salt, sha512_header, sha512_header.Length))
            {
                clean_salt_index = sha512_header.Length;
                if (__ncmp(salt, sha512_header.Length, rounds_header, 0, rounds_header.Length))
                {
                    rounds = __atoi(salt, sha512_header.Length + rounds_header.Length, ref clean_salt_index);
                    if (salt[clean_salt_index++] != (byte)'$')
                    {
                        return null;
                    }
                }
                clean_salt = new byte[salt.Length - clean_salt_index];
                Array.Copy(salt, clean_salt_index, clean_salt, 0, salt.Length - clean_salt_index);
                return SHA512Crypt(key, clean_salt, rounds);
            }

            // Infact Glibc implementation use DES as default crypt function.
            return MD5Crypt(key, salt);
        }

        /// <summary>
        ///     <c>MD5Crypt</c>
        /// </summary>
        /// <param name="key">
        ///     The clear-text buffer.
        /// </param>
        /// <param name="salt">
        ///     The salt buffer without header.
        /// </param>
        /// <returns>
        ///     The hash string.
        /// </returns>
        public static string MD5Crypt(Byte[] key, Byte[] salt)
        {
            int key_len = key.Length;
            int salt_len = salt.Length;
            int rounds = 1000;
            MD5 ctx = new MD5Cng();

            MemoryStream ctx_stream = new MemoryStream();
            MemoryStream alt_stream = new MemoryStream();

            Byte[] alt_result;

            int cnt;

            ctx.Initialize();

            ctx_stream.Write(key, 0, key_len);
            ctx_stream.Write(Encoding.ASCII.GetBytes("$1$"), 0, 3);
            ctx_stream.Write(salt, 0, salt_len);

            alt_stream.Write(key, 0, key_len);
            alt_stream.Write(salt, 0, salt_len);
            alt_stream.Write(key, 0, key_len);

            alt_stream.Position = 0;
            alt_result = ctx.ComputeHash(alt_stream);
            alt_stream.SetLength(0);

            for (cnt = key_len; cnt > 16; cnt -= 16)
            {
                ctx_stream.Write(alt_result, 0, 16);
            }
            ctx_stream.Write(alt_result, 0, cnt);

            /* For the following code we need a NUL byte.  */
            alt_result[0] = (byte)'\0';

            /*
             *  This seems to be wrong but we have to stay compatible.
             */
            for (cnt = key_len; cnt > 0; cnt >>= 1)
            {
                if ((cnt & 0x01) != 0)
                {
                    ctx_stream.Write(alt_result, 0, 1);
                }
                else
                {
                    ctx_stream.Write(key, 0, 1);
                }
            }

            ctx_stream.Position = 0;
            alt_result = ctx.ComputeHash(ctx_stream);
            ctx_stream.SetLength(0);

            for (cnt = 0; cnt < rounds; cnt++)
            {
                ctx_stream.SetLength(0);

                if ((cnt & 0x1) != 0)
                {
                    ctx_stream.Write(key, 0, key_len);
                }
                else
                {
                    ctx_stream.Write(alt_result, 0, 16);
                }

                if ((cnt % 3) != 0)
                {
                    ctx_stream.Write(salt, 0, salt_len);
                }

                if ((cnt % 7) != 0)
                {
                    ctx_stream.Write(key, 0, key_len);
                }

                if ((cnt & 1) != 0)
                {
                    ctx_stream.Write(alt_result, 0, 16);
                }
                else
                {
                    ctx_stream.Write(key, 0, key_len);
                }

                ctx_stream.Position = 0;
                alt_result = ctx.ComputeHash(ctx_stream);
            }

            StringBuilder result_sb = new StringBuilder(24);
            result_sb.Append(__b64_from_24bit(
                alt_result[0], alt_result[6], alt_result[12], 4));
            result_sb.Append(__b64_from_24bit(
                alt_result[1], alt_result[7], alt_result[13], 4));
            result_sb.Append(__b64_from_24bit(
                alt_result[2], alt_result[8], alt_result[14], 4));
            result_sb.Append(__b64_from_24bit(
                alt_result[3], alt_result[9], alt_result[15], 4));
            result_sb.Append(__b64_from_24bit(
                alt_result[4], alt_result[10], alt_result[5], 4));
            result_sb.Append(__b64_from_24bit(
                0, 0, alt_result[11], 2));
            return result_sb.ToString();
        }

        /// <summary>
        ///     <c>SHA256Crypt</c>
        /// </summary>
        /// <param name="key">
        ///     The clear-text buffer.
        /// </param>
        /// <param name="salt">
        ///     The salt buffer without header.
        /// </param>
        /// <param name="rounds">
        ///     Specify hash rounds.
        /// </param>
        /// <returns></returns>
        public static string SHA256Crypt(Byte[] key, Byte[] salt, int rounds)
        {
            int key_len = key.Length;
            int salt_len = salt.Length;
            SHA256 ctx = new SHA256Cng();

            MemoryStream ctx_stream = new MemoryStream();
            MemoryStream alt_stream = new MemoryStream();

            Byte[] alt_result;
            Byte[] temp_result;

            int cnt;

            ctx.Initialize();

            ctx_stream.Write(key, 0, key_len);
            ctx_stream.Write(salt, 0, salt_len);

            alt_stream.Write(key, 0, key_len);
            alt_stream.Write(salt, 0, salt_len);
            alt_stream.Write(key, 0, key_len);

            alt_stream.Position = 0;
            alt_result = ctx.ComputeHash(alt_stream);
            alt_stream.SetLength(0);

            for (cnt = key_len; cnt > 32; cnt -= 32)
            {
                ctx_stream.Write(alt_result, 0, 32);
            }
            ctx_stream.Write(alt_result, 0, cnt);

            for (cnt = key_len; cnt > 0; cnt >>= 1)
            {
                if ((cnt & 1) != 0)
                {
                    ctx_stream.Write(alt_result, 0, 32);
                }
                else
                {
                    ctx_stream.Write(key, 0, key_len);
                }
            }

            ctx_stream.Position = 0;
            alt_result = ctx.ComputeHash(ctx_stream);
            ctx_stream.SetLength(0);

            for (cnt = 0; cnt < key_len; cnt++)
            {
                alt_stream.Write(key, 0, key_len);
            }
            alt_stream.Position = 0;
            temp_result = ctx.ComputeHash(alt_stream);
            alt_stream.SetLength(0);

            Byte[] p_bytes = new Byte[key_len];
            {
                int i = 0;
                for (cnt = key_len; cnt >= 32; cnt -= 32)
                {
                    Array.Copy(temp_result, 0, p_bytes, i, 32);
                    i += 32;
                }
                Array.Copy(temp_result, 0, p_bytes, i, cnt);
            }

            for (cnt = 0; cnt < 16 + alt_result[0]; cnt++)
            {
                alt_stream.Write(salt, 0, salt_len);
            }
            alt_stream.Position = 0;
            temp_result = ctx.ComputeHash(alt_stream);
            alt_stream.SetLength(0);

            Byte[] s_bytes = new byte[salt_len];
            {
                int i = 0;
                for (cnt = salt_len; cnt >= 32; cnt -= 32)
                {
                    Array.Copy(temp_result, 0, s_bytes, i, 32);
                    i += 32;
                }
                Array.Copy(temp_result, 0, s_bytes, i, cnt);
            }

            for (cnt = 0; cnt < rounds; cnt++)
            {
                ctx_stream.SetLength(0);

                if ((cnt & 1) != 0)
                {
                    ctx_stream.Write(p_bytes, 0, key_len);
                }
                else
                {
                    ctx_stream.Write(alt_result, 0, 32);
                }

                if ((cnt % 3) != 0)
                {
                    ctx_stream.Write(s_bytes, 0, salt_len);
                }

                if ((cnt % 7) != 0)
                {
                    ctx_stream.Write(p_bytes, 0, key_len);
                }

                if ((cnt & 1) != 0)
                {
                    ctx_stream.Write(alt_result, 0, 32);
                }
                else
                {
                    ctx_stream.Write(p_bytes, 0, key_len);
                }

                ctx_stream.Position = 0;
                alt_result = ctx.ComputeHash(ctx_stream);
            }

            StringBuilder result_sb = new StringBuilder(44);
            result_sb.Append(__b64_from_24bit(
                alt_result[0], alt_result[10], alt_result[20], 4));
            result_sb.Append(__b64_from_24bit(
                alt_result[21], alt_result[1], alt_result[11], 4));
            result_sb.Append(__b64_from_24bit(
                alt_result[12], alt_result[22], alt_result[2], 4));
            result_sb.Append(__b64_from_24bit(
                alt_result[3], alt_result[13], alt_result[23], 4));
            result_sb.Append(__b64_from_24bit(
                alt_result[24], alt_result[4], alt_result[14], 4));
            result_sb.Append(__b64_from_24bit(
                alt_result[15], alt_result[25], alt_result[5], 4));
            result_sb.Append(__b64_from_24bit(
                alt_result[6], alt_result[16], alt_result[26], 4));
            result_sb.Append(__b64_from_24bit(
                alt_result[27], alt_result[7], alt_result[17], 4));
            result_sb.Append(__b64_from_24bit(
                alt_result[18], alt_result[28], alt_result[8], 4));
            result_sb.Append(__b64_from_24bit(
                alt_result[9], alt_result[19], alt_result[29], 4));
            result_sb.Append(__b64_from_24bit(
                0, alt_result[31], alt_result[30], 3));

            return result_sb.ToString();
        }

        /// <summary>
        ///     <c>SHA512Crypt</c>
        /// </summary>
        /// <param name="key">
        ///     The clear-text buffer.
        /// </param>
        /// <param name="salt">
        ///     The salt buffer without header.
        /// </param>
        /// <param name="rounds">
        ///     Specify hash rounds.
        /// </param>
        /// <returns></returns>
        public static string SHA512Crypt(Byte[] key, Byte[] salt, int rounds)
        {
            int key_len = key.Length;
            int salt_len = salt.Length;
            SHA512 ctx = new SHA512Cng();

            MemoryStream ctx_stream = new MemoryStream();
            MemoryStream alt_stream = new MemoryStream();

            Byte[] alt_result;
            Byte[] temp_result;

            int cnt;

            ctx_stream.Write(key, 0, key_len);
            ctx_stream.Write(salt, 0, salt_len);

            alt_stream.Write(key, 0, key_len);
            alt_stream.Write(salt, 0, salt_len);
            alt_stream.Write(key, 0, key_len);

            alt_stream.Position = 0;
            alt_result = ctx.ComputeHash(alt_stream);
            alt_stream.SetLength(0);

            for (cnt = key_len; cnt > 64; cnt -= 64)
            {
                ctx_stream.Write(alt_result, 0, 64);
            }
            ctx_stream.Write(alt_result, 0, cnt);

            for (cnt = key_len; cnt > 0; cnt >>= 1)
            {
                if ((cnt & 0x01) != 0)
                {
                    ctx_stream.Write(alt_result, 0, 64);
                }
                else
                {
                    ctx_stream.Write(key, 0, key_len);
                }
            }

            ctx_stream.Position = 0;
            alt_result = ctx.ComputeHash(ctx_stream);
            ctx_stream.SetLength(0);
            ctx.Initialize();

            for (cnt = 0; cnt < key_len; cnt++)
            {
                alt_stream.Write(key, 0, key_len);
            }
            alt_stream.Position = 0;
            temp_result = ctx.ComputeHash(alt_stream);
            alt_stream.SetLength(0);
            ctx.Initialize();

            Byte[] p_bytes = new Byte[key_len];
            {
                int i = 0;
                for (cnt = key_len; cnt >= 64; cnt -= 64)
                {
                    Array.Copy(temp_result, 0, p_bytes, i, 64);
                    i += 64;
                }
                Array.Copy(temp_result, 0, p_bytes, i, cnt);
            }


            for (cnt = 0; cnt < 16 + alt_result[0]; cnt++)
            {
                alt_stream.Write(salt, 0, salt_len);
            }
            alt_stream.Position = 0;
            temp_result = ctx.ComputeHash(alt_stream);
            ctx_stream.SetLength(0);
            ctx.Initialize();

            Byte[] s_bytes = new byte[salt_len];
            {
                int i = 0;
                for (cnt = salt_len; cnt >= 64; cnt -= 64)
                {
                    Array.Copy(temp_result, 0, s_bytes, i, 64);
                    i += 64;
                }
                Array.Copy(temp_result, 0, s_bytes, i, cnt++);
            }

            for (cnt = 0; cnt < rounds; cnt++)
            {
                ctx_stream.SetLength(0);
                ctx.Initialize();
                if ((cnt & 1) != 0)
                {
                    ctx_stream.Write(p_bytes, 0, key_len);
                }
                else
                {
                    ctx_stream.Write(alt_result, 0, 64);
                }

                if ((cnt % 3) != 0)
                {
                    ctx_stream.Write(s_bytes, 0, salt_len);
                }

                if ((cnt % 7) != 0)
                {
                    ctx_stream.Write(p_bytes, 0, key_len);
                }

                if ((cnt & 1) != 0)
                {
                    ctx_stream.Write(alt_result, 0, 64);
                }
                else
                {
                    ctx_stream.Write(p_bytes, 0, key_len);
                }
                ctx_stream.Position = 0;
                alt_result = ctx.ComputeHash(ctx_stream);
            }

            StringBuilder result_sb = new StringBuilder(88);
            result_sb.Append(__b64_from_24bit(
                alt_result[0], alt_result[21], alt_result[42], 4));
            result_sb.Append(__b64_from_24bit(
                alt_result[22], alt_result[43], alt_result[1], 4));
            result_sb.Append(__b64_from_24bit(
                alt_result[44], alt_result[2], alt_result[23], 4));
            result_sb.Append(__b64_from_24bit(
                alt_result[3], alt_result[24], alt_result[45], 4));
            result_sb.Append(__b64_from_24bit(
                alt_result[25], alt_result[46], alt_result[4], 4));
            result_sb.Append(__b64_from_24bit(
                alt_result[47], alt_result[5], alt_result[26], 4));
            result_sb.Append(__b64_from_24bit(
                alt_result[6], alt_result[27], alt_result[48], 4));
            result_sb.Append(__b64_from_24bit(
                alt_result[28], alt_result[49], alt_result[7], 4));
            result_sb.Append(__b64_from_24bit(
                alt_result[50], alt_result[8], alt_result[29], 4));
            result_sb.Append(__b64_from_24bit(
                alt_result[9], alt_result[30], alt_result[51], 4));
            result_sb.Append(__b64_from_24bit(
                alt_result[31], alt_result[52], alt_result[10], 4));
            result_sb.Append(__b64_from_24bit(
                alt_result[53], alt_result[11], alt_result[32], 4));
            result_sb.Append(__b64_from_24bit(
                alt_result[12], alt_result[33], alt_result[54], 4));
            result_sb.Append(__b64_from_24bit(
                alt_result[34], alt_result[55], alt_result[13], 4));
            result_sb.Append(__b64_from_24bit(
                alt_result[56], alt_result[14], alt_result[35], 4));
            result_sb.Append(__b64_from_24bit(
                alt_result[15], alt_result[36], alt_result[57], 4));
            result_sb.Append(__b64_from_24bit(
                alt_result[37], alt_result[58], alt_result[16], 4));
            result_sb.Append(__b64_from_24bit(
                alt_result[59], alt_result[17], alt_result[38], 4));
            result_sb.Append(__b64_from_24bit(
                alt_result[18], alt_result[39], alt_result[60], 4));
            result_sb.Append(__b64_from_24bit(
                alt_result[40], alt_result[61], alt_result[19], 4));
            result_sb.Append(__b64_from_24bit(
                alt_result[62], alt_result[20], alt_result[41], 4));
            result_sb.Append(__b64_from_24bit(
                0, 0, alt_result[63], 2));

            return result_sb.ToString();
        }

        private static readonly byte[] b64t = Encoding.ASCII.GetBytes("./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");
        /// <summary>
        ///     <c>__b64_from_24bit</c>
        ///     Glibc specified Base64 encode method.
        /// </summary>
        /// <param name="b2"></param>
        /// <param name="b1"></param>
        /// <param name="b0"></param>
        /// <param name="n"></param>
        /// <returns></returns>
        private static string __b64_from_24bit(byte b2, byte b1, byte b0, int n)
        {
            byte[] buffer = new byte[n];
            uint w = ((uint)b2 << 16) | ((uint)b1 << 8) | b0;
            for (int i = 0; i < n; i++)
            {
                buffer[i] = b64t[w & 0x3f];
                w >>= 6;
            }
            return Encoding.ASCII.GetString(buffer);
        }

        private static bool __ncmp<T>(T[] a, T[] b, int n)
        {
            for (int i = 0; i < n; i++)
            {
                if ((a[i] as IComparable).CompareTo(b[i]) != 0)
                {
                    return false;
                }
            }
            return true;
        }

        private static bool __ncmp<T>(T[] a, int indexa, T[] b, int indexb, int n)
        {
            for (int i = 0; i < n; i++)
            {
                if ((a[i + indexa] as IComparable).CompareTo(b[i + indexb]) != 0)
                {
                    return false;
                }
            }
            return true;
        }

        private static int __atoi(byte[] ch, int startIndex, ref int endIndex)
        {
            int length = ch.Length;
            int lastNumber = 0;
            int returnNumber = 0;
            bool numberNegative = false;
            int startPoint = startIndex;
            int i;

            if (ch[startIndex] == '-')
            {
                numberNegative = true;
                startPoint += 1;
            }
            else if (ch[startIndex] == '+')
            {
                numberNegative = false;
                startPoint += 1;
            }

            for (i = startPoint; i < length; i++)
            {
                if (ch[i] == ' ')
                {
                    continue;
                }
                else
                {
                    if ((ch[i] >= '0') && ch[i] <= '9')
                    {
                        returnNumber = ch[i] - '0';
                        if (i > 0)
                            lastNumber *= 10;
                        lastNumber += returnNumber;
                    }
                    else
                    {
                        break;
                    }
                }
            }
            if (numberNegative)
            {
                lastNumber *= -1;
            }
            endIndex = i;
            return lastNumber;
        }
    }
}
