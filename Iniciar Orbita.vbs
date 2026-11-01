Option Explicit

Dim shell, fileSystem, scriptPath
Set shell = CreateObject("WScript.Shell")
Set fileSystem = CreateObject("Scripting.FileSystemObject")
scriptPath = fileSystem.BuildPath(fileSystem.GetParentFolderName(WScript.ScriptFullName), "iniciar_juego.py")
shell.CurrentDirectory = fileSystem.GetParentFolderName(scriptPath)
shell.Run "pyw -3 """ & scriptPath & """", 0, True
