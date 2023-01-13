using System;
using System.IO;

namespace Fody.Tests
{
    class Program
    {
        static void Main(string[] args)
        {
            var result = WeaverTestHelper.ExecuteTestRun(
                new ModuleWeaver(),
                Path.Combine(AppContext.BaseDirectory, "../../../../TestDll/bin", "TestDll.exe"),
                runPeVerify: false,
                writeSymbols: false);

            Console.WriteLine("Press any key to exit .");
            Console.ReadKey();
        }
    }
}
