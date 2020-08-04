using System;
using System.CodeDom.Compiler;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Fody;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Mono.Cecil.Rocks;
using Mono.Collections.Generic;

namespace CryptStr2
{
    public class ModuleWeaver : BaseModuleWeaver
    {
        public ModuleWeaver()
        {

        }

        private int _minLen = 1;
        private int _maxLen = 1000000;

        private string _Id = Math.Abs(Guid.NewGuid().GetHashCode()).ToString();

        private List<byte> _stringBytes = new List<byte>(10000);
        private int _strIndex = 0;

        private static byte[] _key;

        private FieldDefinition _decryptedField;
        private FieldDefinition _stringsArrayField;

        private MethodDefinition _decryptMethod;
        private MethodDefinition _lookupMethod;

        public override bool ShouldCleanReference => true;

        public override void Execute()
        {
            if (Config.HasAttributes)
            {
                var minattr = Config.Attribute("MinLen");
                var maxattr = Config.Attribute("MaxLen");

                if (minattr != null) int.TryParse(minattr.Value, out _minLen);
                if (maxattr != null) int.TryParse(maxattr.Value, out _maxLen);
            }

            var moduleType = ModuleDefinition.GetAllTypes().First(td => td.Name == "<Module>");

            var bodys = FindAllStrings();

            var ldstrLength = bodys.Sum(tp => tp.Ldstrs.Count);

            Define_Fields(moduleType);

            Create_CryptInit(moduleType);

            Create_CryptGet(moduleType);

            Create_Cctor(moduleType, ldstrLength);

            foreach (var body in bodys)
            {
                ProcessMethod(body);
            }

            Finish_CryptInit(moduleType, EncryptBytes(_stringBytes.ToArray()), _stringBytes.Count);
        }

        public override IEnumerable<string> GetAssembliesForScanning()
        {
            return Enumerable.Empty<string>();
        }

        private byte[] EncryptBytes(byte[] plainText)
        {
            string pw = Guid.NewGuid().ToString();
            byte[] salt = Guid.NewGuid().ToByteArray();
            var keyGenerator = new Rfc2898DeriveBytes(pw, salt);
            _key = keyGenerator.GetBytes(16);

            using (AesCryptoServiceProvider aesProvider = new AesCryptoServiceProvider() { Padding = PaddingMode.None })
            using (ICryptoTransform cryptoTransform = aesProvider.CreateEncryptor(_key, _key))
            using (MemoryStream memStream = new MemoryStream())
            using (CryptoStream cryptoStream = new CryptoStream(memStream, cryptoTransform, CryptoStreamMode.Write))
            {
                cryptoStream.Write(plainText.ToArray(), 0, plainText.Length);

                if (plainText.Length % 16 != 0)
                {
                    byte[] pad = new byte[16 - plainText.Length % 16];
                    cryptoStream.Write(pad, 0, pad.Length);
                }

                cryptoStream.FlushFinalBlock();

                byte[] bytes = memStream.GetBuffer();
                int len = (int)memStream.Length;
                int pos = (int)memStream.Position;

                return bytes;
            }
        }

        private void AddAttrs(Collection<CustomAttribute> attrs)
        {
            var value = typeof(ModuleWeaver).Assembly.GetName().Version.ToString();
            var attr = new CustomAttribute(ModuleDefinition.ImportReference(typeof(GeneratedCodeAttribute).GetConstructors()[0]));
            attr.ConstructorArguments.Add(new CustomAttributeArgument(ModuleDefinition.ImportReference(typeof(string)), $"{typeof(ModuleWeaver).Namespace}.Fody"));
            attr.ConstructorArguments.Add(new CustomAttributeArgument(ModuleDefinition.ImportReference(typeof(string)), value));
            attrs.Add(attr);

            attrs.Add(new CustomAttribute(ModuleDefinition.ImportReference(typeof(DebuggerNonUserCodeAttribute).GetConstructors()[0])));
        }

        private void Define_Fields(TypeDefinition moduleType)
        {
            _decryptedField = new FieldDefinition($"CryptBytes_{_Id}"
                , FieldAttributes.Private | FieldAttributes.Static
                , ModuleDefinition.ImportReference(typeof(Lazy<byte[]>)));

            AddAttrs(_decryptedField.CustomAttributes);

            moduleType.Fields.Add(_decryptedField);

            _stringsArrayField = new FieldDefinition($"Strings_{_Id}"
                , FieldAttributes.Private | FieldAttributes.Static
                , ModuleDefinition.ImportReference(typeof(string[])));

            AddAttrs(_stringsArrayField.CustomAttributes);

            moduleType.Fields.Add(_stringsArrayField);
        }

        private void Create_CryptInit(TypeDefinition moduleType)
        {
            _decryptMethod = new MethodDefinition($"CryptInit_{_Id}", MethodAttributes.HideBySig | MethodAttributes.Static | MethodAttributes.CompilerControlled, ModuleDefinition.ImportReference(typeof(byte[])));
            AddAttrs(_decryptMethod.CustomAttributes);
            _decryptMethod.Body = new MethodBody(_decryptMethod);
            moduleType.Methods.Add(_decryptMethod);
        }

        private void Create_Cctor(TypeDefinition moduleType, int ldstrLength)
        {
            MethodDefinition cctor = FindOrCreateCctor(moduleType);
            MethodBody body = cctor.Body;

            body.SimplifyMacros();
            List<Instruction> returnPoints = body.Instructions.Where((Instruction x) => x.OpCode == OpCodes.Ret).ToList();

            foreach (Instruction instruction in returnPoints)
            {
                List<Instruction> instructions = new List<Instruction>();
                instructions.Add(Instruction.Create(OpCodes.Ldc_I4, ldstrLength));
                instructions.Add(Instruction.Create(OpCodes.Newarr, ModuleDefinition.ImportReference(typeof(string))));
                instructions.Add(Instruction.Create(OpCodes.Stsfld, _stringsArrayField));
                instructions.Add(Instruction.Create(OpCodes.Ldnull));
                instructions.Add(Instruction.Create(OpCodes.Ldftn, _decryptMethod));
                instructions.Add(Instruction.Create(OpCodes.Newobj, ModuleDefinition.ImportReference(typeof(Func<byte[]>).GetConstructors()[0])));
                instructions.Add(Instruction.Create(OpCodes.Newobj, ModuleDefinition.ImportReference(typeof(Lazy<byte[]>).GetConstructor(new[] { typeof(Func<byte[]>) }))));
                instructions.Add(Instruction.Create(OpCodes.Stsfld, _decryptedField));
                instructions.Add(Instruction.Create(OpCodes.Ret));
                body.Instructions.Replace(instruction, instructions);
            }

            body.OptimizeMacros();

            MethodDefinition FindOrCreateCctor(TypeDefinition moduleClass)
            {
                MethodDefinition _cctor = moduleClass.Methods.FirstOrDefault((MethodDefinition x) => x.Name == ".cctor");
                if (_cctor == null)
                {
                    MethodAttributes attributes = MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.HideBySig | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName;
                    _cctor = new MethodDefinition(".cctor", attributes, TypeSystem.VoidReference);
                    moduleClass.Methods.Add(_cctor);
                    _cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
                }
                return _cctor;
            }
        }

        private void Create_CryptGet(TypeDefinition moduleType)
        {
            var getUtf8 = ModuleDefinition.ImportReference(typeof(Encoding).GetMethod("get_UTF8", Type.EmptyTypes));
            var getString = ModuleDefinition.ImportReference(typeof(Encoding).GetMethod("GetString", new Type[] { typeof(byte[]), typeof(Int32), typeof(Int32) }));
            var lazyValue = ModuleDefinition.ImportReference(typeof(Lazy<byte[]>).GetMethod("get_Value"));
            var intern = ModuleDefinition.ImportReference(typeof(string).GetMethod("Intern", System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static));

            _lookupMethod = new MethodDefinition($"CryptGet_{_Id}", MethodAttributes.HideBySig | MethodAttributes.Static, ModuleDefinition.ImportReference(typeof(string)));
            _lookupMethod.Parameters.Add(new ParameterDefinition("ndx", ParameterAttributes.None, ModuleDefinition.ImportReference(typeof(int))));
            _lookupMethod.Parameters.Add(new ParameterDefinition("len", ParameterAttributes.None, ModuleDefinition.ImportReference(typeof(int))));
            _lookupMethod.Parameters.Add(new ParameterDefinition("i", ParameterAttributes.None, ModuleDefinition.ImportReference(typeof(int))));
            AddAttrs(_lookupMethod.CustomAttributes);
            _lookupMethod.DeclaringType = moduleType;
            _lookupMethod.Body = new MethodBody(_lookupMethod);
            var il = _lookupMethod.Body.GetILProcessor();

            VariableDefinition outVar = _lookupMethod.AddLocal(typeof(string));

            var loadReturnVal = il.Create(OpCodes.Ldloc_0);

            il.Append(il.Create(OpCodes.Ldsfld, _stringsArrayField));
            il.Append(il.Create(OpCodes.Ldarg, 2));
            il.Append(il.Create(OpCodes.Ldelem_Ref));
            il.Append(il.Create(OpCodes.Stloc_0));

            il.Append(il.Create(OpCodes.Ldloc_0));
            il.Append(il.Create(OpCodes.Brtrue_S, loadReturnVal));

            il.Append(il.Create(OpCodes.Call, getUtf8));
            il.Append(il.Create(OpCodes.Ldsfld, _decryptedField));
            il.Append(il.Create(OpCodes.Callvirt, lazyValue));
            il.Append(il.Create(OpCodes.Ldarg_0));
            il.Append(il.Create(OpCodes.Ldarg_1));
            il.Append(il.Create(OpCodes.Callvirt, getString));
            il.Append(il.Create(OpCodes.Call, intern));
            il.Append(il.Create(OpCodes.Stloc_0));

            il.Append(il.Create(OpCodes.Ldsfld, _stringsArrayField));
            il.Append(il.Create(OpCodes.Ldarg, 2));
            il.Append(il.Create(OpCodes.Ldloc_0));
            il.Append(il.Create(OpCodes.Stelem_Ref));

            il.Append(loadReturnVal);
            il.Append(il.Create(OpCodes.Ret));

            moduleType.Methods.Add(_lookupMethod);
        }

        private void Finish_CryptInit(TypeDefinition moduleType, byte[] cipherBytes, int byteCount)
        {
            var il = _decryptMethod.Body.GetILProcessor();

            _decryptMethod.Body.InitLocals = true;

            VariableDefinition memStream = _decryptMethod.AddLocal(typeof(Stream));
            VariableDefinition keyBytes = _decryptMethod.AddLocal(typeof(byte[]));
            VariableDefinition aesProvider = _decryptMethod.AddLocal(typeof(AesCryptoServiceProvider));
            VariableDefinition cryptoTransform = _decryptMethod.AddLocal(typeof(ICryptoTransform));
            VariableDefinition cryptoStream = _decryptMethod.AddLocal(typeof(CryptoStream));
            VariableDefinition retBytes = _decryptMethod.AddLocal(typeof(byte[]));

            var resourceName = $"data-{this._Id}";
            var new_bytes = new byte[_key.Length + cipherBytes.Length];

            Array.Copy(_key, new_bytes, _key.Length);
            Array.Copy(cipherBytes, 0, new_bytes, _key.Length, cipherBytes.Length);

            EmbeddedResource resource = new EmbeddedResource(resourceName, ManifestResourceAttributes.Private, new_bytes);

            this.ModuleDefinition.Resources.Add(resource);

            var aesCtor = ModuleDefinition.ImportReference(typeof(AesCryptoServiceProvider).GetConstructor(Type.EmptyTypes));
            var setPadding = ModuleDefinition.ImportReference(typeof(SymmetricAlgorithm).GetMethod("set_Padding", new Type[] { typeof(PaddingMode) }));
            var createDecryptor = ModuleDefinition.ImportReference(typeof(SymmetricAlgorithm).GetMethod("CreateDecryptor", new Type[] { typeof(byte[]), typeof(byte[]) }));
            var cryptoStreamCtor = ModuleDefinition.ImportReference(typeof(CryptoStream).GetConstructor(new Type[] { typeof(Stream), typeof(ICryptoTransform), typeof(CryptoStreamMode) }));
            var readStream = ModuleDefinition.ImportReference(typeof(Stream).GetMethod("Read", new Type[] { typeof(byte[]), typeof(int), typeof(int) }));
            var disposeStream = ModuleDefinition.ImportReference(typeof(Stream).GetMethod("Dispose", Type.EmptyTypes));
            var dispose = ModuleDefinition.ImportReference(typeof(IDisposable).GetMethod("Dispose", Type.EmptyTypes));
            var disposeSymmetric = ModuleDefinition.ImportReference(typeof(SymmetricAlgorithm).GetMethod("Dispose", Type.EmptyTypes));
            var getTypeFromHandle = ModuleDefinition.ImportReference(typeof(Type).GetMethod("GetTypeFromHandle", new Type[] { typeof(RuntimeTypeHandle) }));
            var get_Assembly = ModuleDefinition.ImportReference(typeof(Type).GetProperty("Assembly").GetGetMethod());
            var getManifestResourceStream = ModuleDefinition.ImportReference(typeof(System.Reflection.Assembly).GetMethod("GetManifestResourceStream", new[] { typeof(string) }));

            il.Append(il.Create(OpCodes.Ldtoken, moduleType));
            il.Append(il.Create(OpCodes.Call, getTypeFromHandle));
            il.Append(il.Create(OpCodes.Callvirt, get_Assembly));
            il.Append(il.Create(OpCodes.Ldstr, resourceName));
            il.Append(il.Create(OpCodes.Callvirt, getManifestResourceStream));
            il.Append(il.Create(OpCodes.Stloc_0));
            il.Append(il.Create(OpCodes.Ldc_I4, _key.Length));
            il.Append(il.Create(OpCodes.Newarr, ModuleDefinition.ImportReference(typeof(byte))));
            il.Append(il.Create(OpCodes.Stloc_1));
            il.Append(il.Create(OpCodes.Ldloc_0));
            il.Append(il.Create(OpCodes.Ldloc_1));
            il.Append(il.Create(OpCodes.Ldc_I4_0));
            il.Append(il.Create(OpCodes.Ldc_I4, _key.Length));
            il.Append(il.Create(OpCodes.Callvirt, readStream));
            il.Append(il.Create(OpCodes.Pop));
            il.Append(il.Create(OpCodes.Newobj, aesCtor));
            il.Append(il.Create(OpCodes.Stloc_2));
            il.Append(il.Create(OpCodes.Ldloc_2));
            il.Append(il.Create(OpCodes.Ldc_I4_1));
            il.Append(il.Create(OpCodes.Callvirt, setPadding));
            il.Append(il.Create(OpCodes.Ldloc_2));
            il.Append(il.Create(OpCodes.Ldloc_1));
            il.Append(il.Create(OpCodes.Ldloc_1));
            il.Append(il.Create(OpCodes.Callvirt, createDecryptor));
            il.Append(il.Create(OpCodes.Stloc_3));
            il.Append(il.Create(OpCodes.Ldloc_0));
            il.Append(il.Create(OpCodes.Ldloc_3));
            il.Append(il.Create(OpCodes.Ldc_I4_0));
            il.Append(il.Create(OpCodes.Newobj, cryptoStreamCtor));
            il.Append(il.Create(OpCodes.Stloc_S, cryptoStream));
            il.Append(il.Create(OpCodes.Ldc_I4, byteCount));
            il.Append(il.Create(OpCodes.Newarr, ModuleDefinition.ImportReference(typeof(byte))));
            il.Append(il.Create(OpCodes.Stloc_S, retBytes));
            il.Append(il.Create(OpCodes.Ldloc_S, cryptoStream));
            il.Append(il.Create(OpCodes.Ldloc_S, retBytes));
            il.Append(il.Create(OpCodes.Ldc_I4_0));
            il.Append(il.Create(OpCodes.Ldc_I4, byteCount));
            il.Append(il.Create(OpCodes.Callvirt, readStream));
            il.Append(il.Create(OpCodes.Pop));
            il.Append(il.Create(OpCodes.Ldloc_S, cryptoStream));
            il.Append(il.Create(OpCodes.Callvirt, disposeStream));
            il.Append(il.Create(OpCodes.Ldloc_3));
            il.Append(il.Create(OpCodes.Callvirt, dispose));
            il.Append(il.Create(OpCodes.Ldloc_2));
            il.Append(il.Create(OpCodes.Callvirt, disposeSymmetric));
            il.Append(il.Create(OpCodes.Ldloc_0));
            il.Append(il.Create(OpCodes.Callvirt, disposeStream));
            il.Append(il.Create(OpCodes.Ldloc_S, retBytes));
            il.Append(il.Create(OpCodes.Ret));
        }

        private void ProcessMethod((MethodBody Body, List<Instruction> Ldstrs) tuple)
        {
            tuple.Body.SimplifyMacros();

            var il = tuple.Body.GetILProcessor();

            foreach (Instruction instruction in tuple.Ldstrs)
            {
                string originalValue = instruction.Operand.ToString();
                byte[] bytes = Encoding.UTF8.GetBytes(originalValue);

                instruction.OpCode = OpCodes.Ldc_I4;
                instruction.Operand = _stringBytes.Count;

                _stringBytes.AddRange(bytes);

                Instruction loadByteLen = il.Create(OpCodes.Ldc_I4, bytes.Length);
                il.InsertAfter(instruction, loadByteLen);

                Instruction loadIndex = il.Create(OpCodes.Ldc_I4, _strIndex);
                il.InsertAfter(loadByteLen, loadIndex);

                Instruction call = il.Create(OpCodes.Call, _lookupMethod);
                il.InsertAfter(loadIndex, call);

                _strIndex++;
            }

            tuple.Body.OptimizeMacros();
        }

        private List<(MethodBody Body, List<Instruction> Ldstrs)> FindAllStrings()
        {
            var list = new List<(MethodBody Body, List<Instruction> Ldstrs)>();

            foreach (ModuleDefinition moduleDefinition in ModuleDefinition.Assembly.Modules)
            {
                foreach (TypeDefinition typeDefinition in moduleDefinition.GetAllTypes())
                {
                    foreach (MethodDefinition methodDefinition in typeDefinition.Methods)
                    {
                        if (methodDefinition.HasBody)
                        {
                            var ldstrs = FindStrings(methodDefinition.Body).ToList();

                            if (ldstrs.Count > 0)
                            {
                                list.Add((methodDefinition.Body, ldstrs));
                            }
                        }
                    }
                }
            }

            return list;

            IEnumerable<Instruction> FindStrings(MethodBody body)
            {
                foreach (Instruction instruction in body.Instructions)
                {
                    switch (instruction.OpCode.Name)
                    {
                        case "ldstr":
                            if (instruction.Operand is string str)
                            {
                                if (str.Length >= _minLen && str.Length <= _maxLen)
                                {
                                    yield return instruction;
                                }
                            }
                            break;
                    }
                }
            }
        }
    }
}