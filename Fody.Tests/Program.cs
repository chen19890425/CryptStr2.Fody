using System;
using System.IO;
using CryptStr2;

namespace Fody.Tests
{
    class Program
    {
        static void Main(string[] args)
        {
            var result = WeaverTestHelper.ExecuteTestRun(
                new ModuleWeaver(),
                Path.Combine(AppContext.BaseDirectory, "dlls", "Sys.Utility.dll"),
                false);

            Console.ReadKey();
        }
    }
}
