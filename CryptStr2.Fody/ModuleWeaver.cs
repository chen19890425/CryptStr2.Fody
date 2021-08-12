using System;
using System.CodeDom.Compiler;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using CryptStr2.Utils;
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
        private bool _isRemoveDuplicate = true;

        private string _id = Math.Abs(Guid.NewGuid().GetHashCode()).ToString();

        private FieldDefinition _decryptedField;
        private FieldDefinition _stringsArrayField;

        private MethodDefinition _cryptInitMethod;
        private MethodDefinition _cryptGetMethod;

        public override bool ShouldCleanReference => true;

        public override void Execute()
        {
            if (Config.HasAttributes)
            {
                var minattr = Config.Attribute("MinLen");
                var maxattr = Config.Attribute("MaxLen");
                var isRemoveDuplicate = Config.Attribute("IsRemoveDuplicate");

                if (minattr != null) int.TryParse(minattr.Value, out _minLen);
                if (maxattr != null) int.TryParse(maxattr.Value, out _maxLen);
                if (isRemoveDuplicate != null) bool.TryParse(isRemoveDuplicate.Value, out _isRemoveDuplicate);
            }

            Model model;

            if (_isRemoveDuplicate)
            {
                model = Get_ModelNotRepeat();
            }
            else
            {
                model = Get_ModelAll();
            }

            var moduleType = ModuleDefinition.GetAllTypes().First(td => td.Name == "<Module>");

            Define_Fields(moduleType);

            Create_CryptInit(moduleType);

            Create_CryptGet(moduleType);

            Create_Cctor(moduleType, model.Infos.Count);

            if (_isRemoveDuplicate)
            {
                foreach (var body in model.Bodys)
                {
                    ProcessMethod(body, str => model.Infos.Find(info => info.Str == str));
                }
            }
            else
            {
                foreach (var body in model.Bodys)
                {
                    ProcessMethod(body);
                }
            }

            var cipherBytes = EncryptBytes(model.AllBytes.ToArray(), out var key);

            Finish_CryptInit(moduleType, key, cipherBytes, model.AllBytes.Count);
        }

        public override IEnumerable<string> GetAssembliesForScanning()
        {
            return Enumerable.Empty<string>();
        }

        private Model Get_ModelAll()
        {
            var index = 0;
            var bodys = FindAllStrings();
            var all_bytes = new List<byte>(10000);
            var list_Infos = new List<Info>();

            for (var i = 0; i < bodys.Count; i++)
            {
                var body = bodys[i];

                for (var j = 0; j < body.Ldstrs.Count; j++)
                {
                    var ldstr = body.Ldstrs[j];
                    var str = ldstr.Instruction.Operand.ToString();
                    var bytes = Encoding.UTF8.GetBytes(str);

                    ldstr.Info = new Info()
                    {
                        Str = str,
                        StartIndex = all_bytes.Count,
                        Length = bytes.Length,
                        Index = index
                    };

                    list_Infos.Add(ldstr.Info);

                    all_bytes.AddRange(bytes);

                    index++;
                }
            }

            return new Model(bodys, all_bytes, list_Infos);
        }

        private Model Get_ModelNotRepeat()
        {
            var bodys = FindAllStrings();
            var all_bytes = new List<byte>(10000);
            var list_Infos = new List<Info>();

            var strs = bodys
                .SelectMany(m => m.Ldstrs.Select(ins => ins.Instruction.Operand.ToString()))
                .Distinct()
                .ToArray();

            for (var i = 0; i < strs.Length; i++)
            {
                var str = strs[i];
                var bytes = Encoding.UTF8.GetBytes(str);

                list_Infos.Add(new Info()
                {
                    Str = str,
                    StartIndex = all_bytes.Count,
                    Length = bytes.Length,
                    Index = i
                });

                all_bytes.AddRange(bytes);
            }

            return new Model(bodys, all_bytes, list_Infos);
        }

        private void ProcessMethod(BodyInfo model, Func<string, Info> getInfo = null)
        {
            model.Body.SimplifyMacros();

            var il = model.Body.GetILProcessor();

            foreach (var instInfo in model.Ldstrs)
            {
                var instruction = instInfo.Instruction;
                var originalValue = instruction.Operand.ToString();
                var info = getInfo == null ? instInfo.Info : getInfo.Invoke(originalValue);

                instruction.OpCode = OpCodes.Ldc_I4;
                instruction.Operand = info.StartIndex;

                var loadByteLen = il.Create(OpCodes.Ldc_I4, info.Length);
                il.InsertAfter(instruction, loadByteLen);

                var loadIndex = il.Create(OpCodes.Ldc_I4, info.Index);
                il.InsertAfter(loadByteLen, loadIndex);

                var call = il.Create(OpCodes.Call, _cryptGetMethod);
                il.InsertAfter(loadIndex, call);
            }

            model.Body.OptimizeMacros();
        }

        private byte[] EncryptBytes(byte[] plainText, out byte[] key)
        {
            string pw = Guid.NewGuid().ToString();
            byte[] salt = Guid.NewGuid().ToByteArray();
            var keyGenerator = new Rfc2898DeriveBytes(pw, salt);

            key = keyGenerator.GetBytes(16);

            using (var aesProvider = new AesCryptoServiceProvider() { Padding = PaddingMode.None })
            using (var cryptoTransform = aesProvider.CreateEncryptor(key, key))
            using (var memStream = new MemoryStream())
            using (var cryptoStream = new CryptoStream(memStream, cryptoTransform, CryptoStreamMode.Write))
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
            _decryptedField = new FieldDefinition(
                $"CryptBytes_{_id}",
                FieldAttributes.Private | FieldAttributes.Static,
                ModuleDefinition.ImportReference(typeof(Lazy<byte[]>)));

            AddAttrs(_decryptedField.CustomAttributes);

            moduleType.Fields.Add(_decryptedField);

            _stringsArrayField = new FieldDefinition(
                $"Strings_{_id}",
                FieldAttributes.Private | FieldAttributes.Static,
                ModuleDefinition.ImportReference(typeof(string[])));

            AddAttrs(_stringsArrayField.CustomAttributes);

            moduleType.Fields.Add(_stringsArrayField);
        }

        private void Create_CryptInit(TypeDefinition moduleType)
        {
            _cryptInitMethod = new MethodDefinition($"CryptInit_{_id}", MethodAttributes.HideBySig | MethodAttributes.Static | MethodAttributes.CompilerControlled, ModuleDefinition.ImportReference(typeof(byte[])));

            AddAttrs(_cryptInitMethod.CustomAttributes);

            _cryptInitMethod.Body = new MethodBody(_cryptInitMethod);

            moduleType.Methods.Add(_cryptInitMethod);
        }

        private void Create_Cctor(TypeDefinition moduleType, int ldstrLength)
        {
            var cctor = FindOrCreateCctor(moduleType);
            var body = cctor.Body;

            body.SimplifyMacros();
            List<Instruction> returnPoints = body.Instructions.Where((Instruction x) => x.OpCode == OpCodes.Ret).ToList();

            foreach (Instruction instruction in returnPoints)
            {
                List<Instruction> instructions = new List<Instruction>();
                instructions.Add(Instruction.Create(OpCodes.Ldc_I4, ldstrLength));
                instructions.Add(Instruction.Create(OpCodes.Newarr, ModuleDefinition.ImportReference(typeof(string))));
                instructions.Add(Instruction.Create(OpCodes.Stsfld, _stringsArrayField));
                instructions.Add(Instruction.Create(OpCodes.Ldnull));
                instructions.Add(Instruction.Create(OpCodes.Ldftn, _cryptInitMethod));
                instructions.Add(Instruction.Create(OpCodes.Newobj, ModuleDefinition.ImportReference(typeof(Func<byte[]>).GetConstructors()[0])));
                instructions.Add(Instruction.Create(OpCodes.Newobj, ModuleDefinition.ImportReference(typeof(Lazy<byte[]>).GetConstructor(new[] { typeof(Func<byte[]>) }))));
                instructions.Add(Instruction.Create(OpCodes.Stsfld, _decryptedField));
                instructions.Add(Instruction.Create(OpCodes.Ret));
                body.Instructions.Replace(instruction, instructions);
            }

            body.OptimizeMacros();

            MethodDefinition FindOrCreateCctor(TypeDefinition moduleClass)
            {
                var _cctor = moduleClass.Methods.FirstOrDefault((MethodDefinition x) => x.Name == ".cctor");

                if (_cctor == null)
                {
                    var attributes = MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.HideBySig | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName;
                    
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

            _cryptGetMethod = new MethodDefinition($"CryptGet_{_id}", MethodAttributes.HideBySig | MethodAttributes.Static, ModuleDefinition.ImportReference(typeof(string)));
            _cryptGetMethod.Parameters.Add(new ParameterDefinition("ndx", ParameterAttributes.None, ModuleDefinition.ImportReference(typeof(int))));
            _cryptGetMethod.Parameters.Add(new ParameterDefinition("len", ParameterAttributes.None, ModuleDefinition.ImportReference(typeof(int))));
            _cryptGetMethod.Parameters.Add(new ParameterDefinition("i", ParameterAttributes.None, ModuleDefinition.ImportReference(typeof(int))));

            AddAttrs(_cryptGetMethod.CustomAttributes);

            _cryptGetMethod.DeclaringType = moduleType;

            _cryptGetMethod.Body = new MethodBody(_cryptGetMethod);

            var il = _cryptGetMethod.Body.GetILProcessor();

            _cryptGetMethod.Body.SimplifyMacros();

            _cryptGetMethod.Body.InitLocals = true;

            _cryptGetMethod.AddLocal(typeof(string));

            var loadReturnVal = il.Create(OpCodes.Ldloc_0);

            il.Append(il.Create(OpCodes.Ldsfld, _stringsArrayField));
            il.Append(il.Create(OpCodes.Ldarg_2));
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
            il.Append(il.Create(OpCodes.Ldarg_2));
            il.Append(il.Create(OpCodes.Ldloc_0));
            il.Append(il.Create(OpCodes.Stelem_Ref));

            il.Append(loadReturnVal);
            il.Append(il.Create(OpCodes.Ret));

            moduleType.Methods.Add(_cryptGetMethod);

            _cryptGetMethod.Body.OptimizeMacros();
        }

        private void Finish_CryptInit(TypeDefinition moduleType, byte[] key, byte[] cipherBytes, int byteCount)
        {
            var il = _cryptInitMethod.Body.GetILProcessor();

            _cryptInitMethod.Body.SimplifyMacros();

            _cryptInitMethod.Body.InitLocals = true;

            var memStream = _cryptInitMethod.AddLocal(typeof(Stream));
            var keyBytes = _cryptInitMethod.AddLocal(typeof(byte[]));
            var aesProvider = _cryptInitMethod.AddLocal(typeof(AesCryptoServiceProvider));
            var cryptoTransform = _cryptInitMethod.AddLocal(typeof(ICryptoTransform));
            var cryptoStream = _cryptInitMethod.AddLocal(typeof(CryptoStream));
            var retBytes = _cryptInitMethod.AddLocal(typeof(byte[]));

            var resourceName = $"data-{this._id}";
            var new_bytes = new byte[key.Length + cipherBytes.Length];

            Array.Copy(key, new_bytes, key.Length);
            Array.Copy(cipherBytes, 0, new_bytes, key.Length, cipherBytes.Length);

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
            il.Append(il.Create(OpCodes.Ldc_I4, key.Length));
            il.Append(il.Create(OpCodes.Newarr, ModuleDefinition.ImportReference(typeof(byte))));
            il.Append(il.Create(OpCodes.Stloc_1));
            il.Append(il.Create(OpCodes.Ldloc_0));
            il.Append(il.Create(OpCodes.Ldloc_1));
            il.Append(il.Create(OpCodes.Ldc_I4_0));
            il.Append(il.Create(OpCodes.Ldc_I4, key.Length));
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

            _cryptInitMethod.Body.OptimizeMacros();
        }

        private List<BodyInfo> FindAllStrings()
        {
            var list = new List<BodyInfo>();

            foreach (var moduleDefinition in ModuleDefinition.Assembly.Modules)
            {
                foreach (var typeDefinition in moduleDefinition.GetAllTypes())
                {
                    foreach (var methodDefinition in typeDefinition.Methods)
                    {
                        if (methodDefinition.HasBody)
                        {
                            var ldstrs = FindStrings(methodDefinition.Body).ToList();

                            if (ldstrs.Count > 0)
                            {
                                list.Add(new BodyInfo(methodDefinition.Body, ldstrs));
                            }
                        }
                    }
                }
            }

            return list;

            IEnumerable<InstInfo> FindStrings(MethodBody body)
            {
                foreach (var instruction in body.Instructions)
                {
                    switch (instruction.OpCode.Name)
                    {
                        case "ldstr":
                            if (instruction.Operand is string str)
                            {
                                if (str.Length >= _minLen && str.Length <= _maxLen)
                                {
                                    yield return new InstInfo(instruction);
                                }
                            }
                            break;
                    }
                }
            }
        }

        private class Model
        {
            public Model(List<BodyInfo> bodys, List<byte> allBytes, List<Info> infos)
            {
                this.Bodys = bodys;
                this.AllBytes = allBytes;
                this.Infos = infos;
            }

            public List<BodyInfo> Bodys { get; }

            public List<byte> AllBytes { get; }

            public List<Info> Infos { get; }
        }

        private class BodyInfo
        {
            public BodyInfo(MethodBody body, List<InstInfo> ldstrs)
            {
                this.Body = body;
                this.Ldstrs = ldstrs;
            }

            public MethodBody Body { get; }

            public List<InstInfo> Ldstrs { get; }
        }

        private sealed class InstInfo
        {
            public InstInfo(Instruction instruction)
            {
                this.Instruction = instruction;
                this.Info = default;
            }

            public Instruction Instruction { get; }

            public Info Info { get; set; }
        }

        private struct Info
        {
            public string Str { get; set; }

            public int StartIndex { get; set; }

            public int Length { get; set; }

            public int Index { get; set; }
        }
    }
}