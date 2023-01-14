using System;
using Mono.Cecil;

public static class ModuleDefinitionExtensions
{
    /// <summary>
    /// Create a GenericInstanceType for the given generic type instantiated with the given generic arguments.
    /// </summary>
    /// <param name="genericType">The generic type to instantiate.</param>
    /// <param name="genericArgs">The generic arguments needed to instantiate the generic type.</param>
    /// <returns></returns>
    public static GenericInstanceType ImportGenericTypeInstance(this ModuleDefinition module, TypeReference genericType, params TypeReference[] genericArgs)
    {
        TypeReference typeDef = genericType.Resolve();

        if (!typeDef.HasGenericParameters)
        {
            throw new InvalidOperationException(string.Format("Type {0} is not generic", genericType));
        }

        typeDef = module.ImportReference(typeDef);

        var instance = new GenericInstanceType(typeDef);

        for (int i = 0; i < typeDef.GenericParameters.Count; i++)
        {
            var p = typeDef.GenericParameters[i];

            if (p.Position < genericArgs.Length)
            {
                GenericParameter parameter = new GenericParameter(p.Name, typeDef);

                instance.GenericParameters.Add(parameter);
                instance.GenericArguments.Add(genericArgs[p.Position]);
            }
            else
            {
                throw new InvalidOperationException(string.Format("Not enough generic arguments to instantiate type {0}", genericType));
            }
        }

        return instance;
    }

    /// <summary>
    /// Create a GenericInstanceMethod from the given generic method and the given generic arguments.
    /// Note: this can also handle the case where the DeclaringType is also generic.  Simply pass the combined
    /// generic args for the declaring type and the method.
    /// </summary>
    /// <param name="genericMethod">A generic method to instantiate.</param>
    /// <param name="genericArgs">The combined generic arguments for the declaring type (if it is generic) and for the method.</param>
    /// <returns></returns>
    public static MethodReference ImportGenericMethodInstance(this ModuleDefinition module, MethodReference genericMethod, params TypeReference[] genericArgs)
    {
        var methodDef = genericMethod.Resolve();
        TypeReference typeDef = methodDef.DeclaringType;
        var genericArgOffset = 0;

        GenericInstanceType typeInstance = null;

        if (typeDef.HasGenericParameters)
        {
            typeInstance = module.ImportGenericTypeInstance(typeDef, genericArgs);
            typeDef = typeInstance;
            genericArgOffset = typeInstance.GenericArguments.Count;
        }

        TypeReference returnType = methodDef.ReturnType;

        // create a new MethodReference with the instantiated generic type as the DeclaringType.
        MethodReference result = new MethodReference(genericMethod.Name, returnType, typeDef)
        {
            HasThis = genericMethod.HasThis,
            ExplicitThis = genericMethod.ExplicitThis,
            CallingConvention = genericMethod.CallingConvention
        };

        GenericInstanceMethod genericMethodInstance = null;

        if (methodDef.HasGenericParameters)
        {
            // Then we also need to instantiate the generic method!
            genericMethodInstance = new GenericInstanceMethod(result);

            for (int i = 0; i < methodDef.GenericParameters.Count; i++)
            {
                var p = methodDef.GenericParameters[i];
                var j = p.Position + genericArgOffset;

                if (j > genericArgs.Length)
                {
                    throw new InvalidOperationException(string.Format("Not enough generic arguments to instantiate method {0}", genericMethod));
                }

                GenericParameter parameter = new GenericParameter(p.Name, genericMethodInstance);

                result.GenericParameters.Add(parameter);
                genericMethodInstance.GenericParameters.Add(parameter);
                genericMethodInstance.GenericArguments.Add(genericArgs[j]);
            }

            result = genericMethodInstance;
        }

        foreach (var arg in genericMethod.Parameters)
        {
            ParameterDefinition p = new ParameterDefinition(arg.Name, arg.Attributes, module.ImportReference(arg.ParameterType, typeDef));

            if (arg.ParameterType is GenericParameter gp)
            {
                if (gp.DeclaringType != null)
                {
                    p.ParameterType = typeInstance.GenericParameters[gp.Position];
                }
                else if (gp.DeclaringMethod != null)
                {
                    p.ParameterType = genericMethodInstance.GenericParameters[gp.Position];
                }
            }

            result.Parameters.Add(p);
        }

        return result;
    }
}