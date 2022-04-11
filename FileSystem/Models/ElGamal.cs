using System;
using System.Collections.Generic;

namespace FileSystem.models
{
    public class ElGamal
    {
        public int Gcd(int a, int b)
        {
            while (a != 0 && b != 0)
            {
                if (a > b)
                    a %= b;
                else
                    b %= a;
            }

            return a | b;
        }

        public int GenKey(int q)
        {
            var rand = new Random();
            var key = rand.Next((int) Math.Pow(10, 2), q);
            while (Gcd(q, key) != 1)
            {
                key = rand.Next((int)Math.Pow(10, 2), q);
            }

            return key;

        }

        public int Power(int a, int b, int c)
        {
            var x = 1;
            var y = a;
            while (b > 0)
            {
                if (b % 2 != 0)
                {
                    x = x * y % c;
                }
                y = y * y % c;
                b /= 2;
            }
            return x % c;
        }

        public (List<char>, int) Encrypt(string msg, int q, int h, int g)
        {
            var en_msg = new List<char>();
            var k = GenKey(q); // Private key for sender
            var s = Power(h, k, q);
            var p = Power(g, k, q);
            for (var i = 0; i < msg.Length; i++)
            {
                en_msg.Add ((char) (s * msg[i]));
            }

            return (en_msg, p);
        }

        public string Decrypt(List<char> en_msg, int p, int key, int q)
        {
            var dr_msg = new List<char>();
            var h = Power(p, key, q);
            for(int i = 0; i < en_msg.Count; i++)
            {
                dr_msg.Add((char) (en_msg[i]/h));
            }

            return new string(dr_msg.ToArray());
        }
    }
}