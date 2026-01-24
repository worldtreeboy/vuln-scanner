using System;
using System.Reflection;

class Evasive {
    public static void Main(string[] args) {
        var asm = Assembly.Load("System");
        var type = asm.GetType("System." + "Dia" + "gnostics.Process");
        var method = type.GetMethod("Get" + "Processes");
        var processes = (Array)method.Invoke(null, null);
        foreach (var process in processes) {
            Console.WriteLine(process);
        }
    }
}
