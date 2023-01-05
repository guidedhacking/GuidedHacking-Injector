Namespace Core

    Public Class HelperExtractor

        Public Enum Arq
            x86
            x64
        End Enum

        Public Shared Sub Extract(ByVal Type As Arq)
            Try
                If IO.File.Exists(GHWrapper.API) Then IO.File.Delete(GHWrapper.API)

                Select Case Type
                    Case Arq.x86
                        IO.File.WriteAllBytes(GHWrapper.API, My.Resources.InjectionHelper)
                    Case Arq.x64
                        IO.File.WriteAllBytes(GHWrapper.API, My.Resources.InjectionHelper64)
                End Select
            Catch ex As Exception
                Throw New Exception(ex.Message)
            End Try
        End Sub

    End Class

End Namespace

