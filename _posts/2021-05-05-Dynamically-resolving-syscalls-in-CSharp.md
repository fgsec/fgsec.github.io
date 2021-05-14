---
title: "Dynamically resolving syscalls in C#"
author: Felipe Gaspar
date: 2021-05-05 00:00:00 +0800
---
This post aims to describe and provide example code on how you can dynamically resolve syscalls using only C#.

## What are System calls?

**TL;DR**: System calls or just *syscalls* are used by applications to perform tasks that are executed by the kernel, such as opening files, allocating memory, and so on. In the offensive context, you can use them to evade API hooks used by security products to intercept and record calls from software.

If you are new to this subject, I would recommend reading [this post by Jack Halon](https://jhalon.github.io/utilizing-syscalls-in-csharp-1/), which explains very well how syscalls work and even how to use them in csharp.

## Hard coding vs Dynamically resolving

Why would you want to dynamically resolve syscalls if you can encode those magic numbers directly in your code?

The simple answer: syscall numbers are different between OS and build versions, and yes, you could bring all those diferent numbers inside your code and choose the one for that system, but why should you? 

We have different approaches that can be used to solve these numbers, without worrying about the OS version of our target. 

It is important to understand that, although we have different approaches, our blue team friends and their tools can also detect us in different ways. A great example of this is the [Cyberbit article](https://www.cyberbit.com/blog/endpoint-security/malware-mitigation-when-direct-system-calls-are-used/), which documents different malware and brings together the pros and cons of techniques used in direct and dynamic resolution of syscalls.

## Introduction

Okay, before we start, remember that the technique presented here is just an example among several forms that exists and not applied to WOW64 binaries (x86 binaries running on x64 system), you should apply the best within your context.

As a reminder, it's possible to confirm a hook by inspecting the first bytes of a function memory region, where we would find something like this:

```nasm
JMP 00000000132CF08
NOP
NOP
NOP
TEST BYTE PTR [000000007FFE0308],01
JNE 0000000000000015
SYSCALL
RET
```

Note the ```JMP``` instruction, this is a common way to divert execution to a different memory region, usually with code that will analyze whether the execution is malicious or not.

In constrast, the following instructions are a common syscall execution, we can also confirm that the syscall number for "NtAllocateVirtualMemory" is ```00000018```.

```nasm
MOV R10,RCX
MOV EAX,00000018
TEST BYTE PTR [000000007FFE0308],01
JNE 0000000000000015
SYSCALL
RET
```

As you can see, a hooked function prevents obtaining the syscall number. This is one of the problems that techniques like the one that will be presented try to solve.

## Hello Neighbor

This technique queries the syscall number of neighboring functions to find out the value of the hooked function.

Let's look at why and how this is possible.

If we were to inspect the [export directory table](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#export-directory-table) from ```ntdll.dll``` in search of the "NtAllocateVirtualMemory" entry, we would obtain a list of exported functions like this:

![List](/images/post4-01.png)


*(I'm using IDA to inspect the file, but you can use tools such as [CFF Explorer](https://ntcore.com/?page_id=388))*

This view is useful, but it is not exactly what we need. The vast majority of tools that let us inspect the export table, will sort using the name or the ordinal column, our interest is the address, more specifically the relative virtual address (RVA) of the function, you can read more about it [here](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#general-concepts). 

Now, if we sort the table by the address, we will have the following result:

![](/images/post4-02.png)

What this means? This means that by sorting by address, we are able to view the neighboring functions. In this case, we now know that ```NtQueryValueKey``` and  ```NtQueryInformationProcess``` are neighbors to function ```NtAllocateVirtualMemory```. Since we don't know the syscall number of our hooked function, we can discover it from these neighbors.

Ok, so let's inspect those instructions to confirm this theory *(I'm inspecting the ntdll on disk, so we will not see any hooks here)*:

![](/images/post4-03.png)

As we can see, the numbers are sequential, so even if the function ```NtAllocateVirtualMemory``` is hooked, we can determine that its value is "0x0018" by subtracting the number from the function ```NtQueryInformationProcess``` or by adding to the function ```NtQueryValueKey```.

Also, it is possible to visualize that there is a difference of 20 bytes between each function, this will be especially useful in the next section.

## Let's Code

Now that we've seen how the technique works, let's implement it using C#.

Before we start, let's organize what we need to make this work:

1. Base address of ntdll inside our process
2. The address of exported functions ([GetProcAddress](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress)), this will let us obtain the address for any function inside ntdll.
3. Check if function is hooked
4. Read and copy memory from inside the process

We can obtain the base address of ntdll by looping through our process loaded modules with the help of the ```System.Diagnostics.Process``` class:

```csharp
public static IntPtr GetNTDLLBase() {
    Process hProc = Process.GetCurrentProcess();
    foreach(ProcessModule module in hProc.Modules) {
      if (module.ModuleName.Equals("ntdll.dll"))
        return module.BaseAddress;
    }
    return IntPtr.Zero;
  }
  ```
Now, moving to the address of exported functions inside ntdll, we can use P/Invoke to call Win32's API function ```GetProcAddress```. It's really simple to use it, we just need to pass two arguments, the NTDLL base address and the name of the desired function as string:

```csharp
[DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

IntPtr ntdllBase = GetNTDLLBase();
IntPtr funcAddress = GetProcAddress(ntdllBase, "NtAllocateVirtualMemory");     
```

With the function address, we can copy the memory region and inspect the first bytes for a possible hook. We can do this using the ```Marshal.Copy()``` function, resulting in the code below:

```csharp
public static bool isHooked(byte value) {
    byte mov = 0x4C;
    if (value != mov)
        return true;
    return false;
}

byte[] instructions = new byte[4];
Marshal.Copy(funcAddress, instructions, 0, 4);
if (isHooked(instructions[0])) {
   Console.WriteLine("Function is hooked!");
} else {
   Console.WriteLine("Function is NOT hooked!");
}
```

The function ```isHooked()``` is just checking if the first byte is diferent from what a normal execution would be (4C8BD1B8). You can do something more reliable by checking all 4 bytes, but for this demonstration this is sufficient.

Ok, now we know how to tell if our function is hooked, all that remains is to look for the neighbor's number and deduct the correct value.

```csharp
static byte[] syscallStruct = {
  0x4C, 0x8B, 0xD1,               // mov r10, rcx
  0xB8, 0xFF, 0x00, 0x00, 0x00,   // mov eax, FUNC
  0x0F, 0x05,                     // syscall
  0xC3                            // ret
};
public static bool returnBasedOnNeighbor(IntPtr funcAddress) {
    byte counter = 1;
    while(true) {
        IntPtr nextFuncAddress = (IntPtr)((UInt64)funcAddress + (UInt64)32);
        Console.WriteLine(String.Format("Next Neighbor: {0} ", (nextFuncAddress).ToString("X")));
        byte[] instructions = new byte[21];
        Marshal.Copy(nextFuncAddress, instructions, 0, 21);
        Console.WriteLine(String.Format("Neighbor instructions: {0}", BitConverter.ToString(instructions).Replace("-", " ")));
        if (!isHooked(instructions[0])) {
            syscallStruct[4] = (byte)(instructions[4]-counter);
            return true;
        } else {
            funcAddress = nextFuncAddress;
            Console.WriteLine("Neighbor is also hooked ;(");
        }
        counter++;
    }
    Console.ReadKey();
    return false;
}
```
The ```returnBasedOnNeighbor()``` function does just that, with the difference that if our neighbor is also hooked, it continues until it finds one that is not.

Compiling these functions in a single code, we have a functional example of this technique:

![](/images/post4-04.png)

That's it!

The complete code will be available on my [github](https://github.com/fgsec).

