
Imports System.Reflection
Imports System.Reflection.Emit
Imports System.Runtime.InteropServices

Namespace Core

    Public Class DynamicInvoke

        Public AssemblyName As String = "DynamicInvoke"
        Public TypeName As String = "DynamicType"
        Public Convention As CallingConvention = CallingConvention.Winapi
        Public CharacterSet As CharSet = CharSet.Ansi

        Function Invoke(ByVal MethodName As String, ByVal LibraryName As String, ByVal ReturnType As Type, ByVal ParamArray Parameters() As Object)

            Dim ParameterTypesArray As Array

            If Parameters IsNot Nothing Then
                ParameterTypesArray = Array.CreateInstance(GetType(Type), Parameters.Length)
                Dim PTIndex As Integer = 0

                For Each Item In Parameters
                    If Item IsNot Nothing Then
                        ParameterTypesArray(PTIndex) = Item.GetType
                    End If
                    PTIndex += 1
                Next
            Else
                ParameterTypesArray = Nothing
            End If

            Dim ParameterTypes() As Type = ParameterTypesArray

            Dim asmName As New AssemblyName(AssemblyName)
            Dim dynamicAsm As AssemblyBuilder = AppDomain.CurrentDomain.DefineDynamicAssembly(asmName, AssemblyBuilderAccess.RunAndSave)

            ' Create the module.
            Dim dynamicMod As ModuleBuilder = dynamicAsm.DefineDynamicModule(asmName.Name, asmName.Name & ".dll")

            ' Create the TypeBuilder for the class that will contain the 
            ' signature for the PInvoke call.
            Dim tb As TypeBuilder = dynamicMod.DefineType(TypeName, TypeAttributes.Public Or TypeAttributes.UnicodeClass)

            Dim mb As MethodBuilder = tb.DefinePInvokeMethod(
                MethodName,
                LibraryName,
                MethodAttributes.Public Or MethodAttributes.Static Or MethodAttributes.PinvokeImpl,
                CallingConventions.Standard,
                ReturnType,
                ParameterTypes,
                Convention,
                CharacterSet)

            ' Add PreserveSig to the method implementation flags. NOTE: If this line
            ' is commented out, the return value will be zero when the method is
            ' invoked.
            mb.SetImplementationFlags(mb.GetMethodImplementationFlags() Or MethodImplAttributes.PreserveSig)

            ' The PInvoke method does not have a method body.

            ' Create the class and test the method.
            Dim t As Type = tb.CreateType()

            Dim mi As MethodInfo = t.GetMethod(MethodName)
            Return mi.Invoke(Me, Parameters)

            '' Produce the .dll file.
            'Console.WriteLine("Saving: " & asmName.Name & ".dll")
            'dynamicAsm.Save(asmName.Name & ".dll")
        End Function

    End Class

End Namespace
