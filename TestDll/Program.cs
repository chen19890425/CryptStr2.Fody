using System;
using System.Reflection;

namespace TestDll
{
    class Emit_Test
    {
        public static int AA = 10000;
    }

    public class Program
    {
        public static void Main()
        {
            Info.OfConstructor<object>();

            var m = Info.OfMethod<Action<string>>(nameof(Action<string>.Invoke));

            var m2 = Info.OfMethod<string>(nameof(string.Clone));

            Info.OfMethod<Type>(nameof(Type.GetTypeFromHandle));

            var c = Info.OfConstructor<Action<string>>();

            var mt = Info.OfMethod<int>("TryParse", $"{nameof(String)}, {nameof(Int32)}&");

            var mmm = Info.OfMethod<Program>("Main");

            var m_GetTypeFromHandle = Info.OfMethod<Type>(nameof(Type.GetTypeFromHandle));

            var m_GetMethodFromHandle = Info.OfMethod<MethodBase>(
                nameof(MethodBase.GetMethodFromHandle),
                $"{nameof(RuntimeMethodHandle)}, {nameof(RuntimeTypeHandle)}");

            var fi__ = Info.OfField<string>(nameof(string.Empty));

            var fi__1 = Info.OfField<Emit_Test>(nameof(Emit_Test.AA));

            var writeline = Info.OfMethod("mscorlib", "System.Console", "WriteLine", "String");

            Console.ReadKey();
        }
    }
}
