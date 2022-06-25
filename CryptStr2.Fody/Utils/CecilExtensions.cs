using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Mono.Cecil.Rocks;
using Mono.Collections.Generic;
using MethodAttributes = Mono.Cecil.MethodAttributes;
using MethodBody = Mono.Cecil.Cil.MethodBody;

namespace CryptStr2.Fody
{
    public static class CecilExtensions
    {
        public static void Replace(this Collection<Instruction> collection, Instruction instruction, IEnumerable<Instruction> instructions)
        {
            int indexOf = collection.IndexOf(instruction);
            collection.RemoveAt(indexOf);
            foreach (Instruction instruction2 in instructions)
            {
                collection.Insert(indexOf, instruction2);
                indexOf++;
            }
        }

        public static TypeDefinition GetTypeDefinition(this TypeReference typeReference)
        {
            if (typeReference == null)
                return null;
            foreach (TypeDefinition td in typeReference.Module.GetAllTypes())
                if (td.FullName == typeReference.FullName)
                    return td;
            return null;
        }

        public static VariableDefinition AddLocal(this MethodDefinition methodDef, Type localType)
        {
            TypeReference declaringType = methodDef.DeclaringType;
            ModuleDefinition module = declaringType.Module;
            TypeReference variableType = module.ImportReference(localType);
            VariableDefinition result = new VariableDefinition(variableType);

            methodDef.Body.Variables.Add(result);

            return result;
        }

        public static VariableDefinition AddLocal(this MethodDefinition methodDef, AssemblyDefinition assembly, Type localType)
        {
            TypeReference variableType = assembly.MainModule.ImportReference(localType);
            VariableDefinition result = new VariableDefinition(variableType);

            methodDef.Body.Variables.Add(result);

            return result;
        }

        public static TypeReference GetTypeReference(this MethodDefinition methodDef, Type localType)
        {
            TypeReference declaringType = methodDef.DeclaringType;
            ModuleDefinition module = declaringType.Module;
            return module.ImportReference(localType);
        }

        public static MethodReference ImportMethod(this MethodBody body, MethodReference reference)
        {
            return body.Method.DeclaringType.Module.ImportReference(reference);
        }

        public static int GetAddressSize(this AssemblyDefinition assemblyDefinition)
        {
            if (assemblyDefinition.Is64BitAssembly())
                return 8;
            return 4;
        }

        public static bool Is64BitAssembly(this AssemblyDefinition assemblyDefinition)
        {
            if (assemblyDefinition == null) throw new ArgumentNullException("assemblyDefinition");
            switch (assemblyDefinition.MainModule.Architecture)
            {
                case TargetArchitecture.AMD64:
                case TargetArchitecture.IA64:
                    return true;
                default:
                    return false;
            }
        }

        public static MethodDefinition FindMethod(this Collection<MethodDefinition> methods, string methodName, Collection<ParameterDefinition> parameters)
        {
            var defs = from m in methods where m.Name == methodName select m;
            foreach (MethodDefinition def in defs)
            {
                if (def.Parameters.Count == parameters.Count)
                {
                    bool isMatch = true;
                    for (int i = 0; i < def.Parameters.Count && isMatch; i++)
                    {
                        if (def.Parameters[i].ParameterType.Name != parameters[i].ParameterType.Name)
                            isMatch = false;
                    }

                    if (isMatch)
                        return def;
                }
            }
            return null;
        }

        public static PropertyDefinition[] FindProperty(this Collection<PropertyDefinition> properties, string name)
        {
            var pd = from p in properties where p.Name == name select p;
            if (pd.Any())
                return pd.ToArray();
            return new PropertyDefinition[0];
        }

        public static bool HasProperty(this Collection<PropertyDefinition> properties, string name)
        {
            var pd = from p in properties where p.Name == name select p;
            return pd.Any();
        }

        public static TypeReference Import(this AssemblyDefinition assemblyDefinition, Type type)
        {
            if (assemblyDefinition == null) throw new ArgumentNullException("assemblyDefinition");
            return assemblyDefinition.MainModule.ImportReference(type);
        }

        public static MethodReference Import(this AssemblyDefinition assemblyDefinition, MethodBase methodBase)
        {
            if (assemblyDefinition == null) throw new ArgumentNullException("assemblyDefinition");
            return assemblyDefinition.MainModule.ImportReference(methodBase);
        }

        public static MethodBody CreateDefaultConstructor(this AssemblyDefinition assembly, TypeDefinition typeDefinition)
        {
            MethodDefinition ctor = new MethodDefinition(".ctor",
                MethodAttributes.Public | MethodAttributes.HideBySig |
                MethodAttributes.SpecialName | MethodAttributes.RTSpecialName,
                assembly.Import(typeof(void)));

            typeDefinition.Methods.Add(ctor);
            ctor.Body = new MethodBody(ctor);
            return ctor.Body;
        }

        public static void Append(this ILProcessor il, OpCode opCode)
        {
            il.Append(il.Create(opCode));
        }

        public static void AdjustOffsets(this ILProcessor il, MethodBody body, int adjustBy)
        {
            il.AdjustOffsets(body, new List<int> { 0 }, adjustBy);
        }

        public static void AdjustOffsets(this ILProcessor il, MethodBody body, IList<int> offsets, int adjustBy)
        {
            if (offsets.Count == 0)
                return;

            List<int> seenHashCodes = new List<int>();

            for (int i = 0; i < body.Instructions.Count; i++)
            {
                Instruction instruction = body.Instructions[i];

                if (instruction.Operand is Instruction)
                {
                    Instruction target = (Instruction)instruction.Operand;
                    int hashCode = target.GetHashCode();
                    if (seenHashCodes.Contains(hashCode))
                        continue;
                    seenHashCodes.Add(hashCode);

                    OpCode opCode = instruction.OpCode;

                    int originalOffset = target.Offset;
                    int offset = target.Offset;
                    foreach (int movedOffsets in offsets)
                    {
                        if (originalOffset > movedOffsets)
                            offset += adjustBy;
                    }
                    target.Offset = offset;

                    Instruction newInstr = il.Create(opCode, target);
                    il.Replace(instruction, newInstr);
                }
                else if (instruction.Operand is Instruction[])
                {
                    Instruction[] targets = (Instruction[])instruction.Operand;

                    foreach (Instruction target in targets)
                    {
                        int hashCode = target.GetHashCode();
                        if (seenHashCodes.Contains(hashCode))
                            continue;
                        seenHashCodes.Add(hashCode);

                        int originalOffset = target.Offset;
                        int offset = target.Offset;
                        foreach (int movedOffsets in offsets)
                        {
                            if (originalOffset > movedOffsets)
                                offset += adjustBy;
                        }
                        target.Offset = offset;
                    }
                    Instruction newInstr = il.Create(instruction.OpCode, targets);
                    il.Replace(instruction, newInstr);
                }
            }

            foreach (ExceptionHandler handler in body.ExceptionHandlers)
            {
                Instruction target = handler.TryStart;
                int hashCode = target.GetHashCode();
                if (seenHashCodes.Contains(hashCode))
                    continue;
                seenHashCodes.Add(hashCode);

                int originalOffset = target.Offset;
                int offset = target.Offset;
                foreach (int movedOffsets in offsets)
                {
                    if (originalOffset > movedOffsets)
                        offset += adjustBy;
                }

                target.Offset = offset;
            }
        }
    }
}