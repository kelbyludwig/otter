## otter

Otter is a Burp Suite plugin that automates authorization testing. Its premise
is simple: as a user walks an application with the browser, a value identifying
one user is replaced with a value identifying another. In many cases, this will
make testing application access controls as simple as browsing the application.

## otter's design goals

* Be easy to use: Requiring several configuration options is a hassle. Setup
  and usage should be trivial.

* Be unbiased: Otter will not attempt to identify authorization flaws. It
  presents information as-is, and lets the user decide.

* Be generally useful: Otter should be useful in most cases. It will not make
  assumptions about how APIs typically work.

## setup 

* Download [Jython](http://www.jython.org/downloads.html) (Otter was tested
  with Jython 2.7.0) and point Burp towards this JAR: "Extender" -> "Options"
  -> "Python Environment".

* Install the Burp extension: "Extender" -> "Extensions" -> "Add" -> "Extension
  Type: Python" -> Browse to otter.py.

* Otter will ignore requests based on your scope configuration: "Target" ->
  "Scope".

* Configure your session match-and-replace in otter's "Settings" tab. Only
  requests that include the "String to Match" somewhere in the request will be
  modified and re-sent. Unmodified requests are noted in the UI with the
  "Request Modified?" column.

* Otter also supports multiple match-and-replace values. These values are
  provided via a comma-separated list. For example, the match string "abc,def"
  and the replace string "123,456" will replace "abc" with "123" for all
  in-scope requests.

## why "otter"?

It sounds similar to "Author".
