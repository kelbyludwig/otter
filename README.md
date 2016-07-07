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

## why "otter"?

It sounds similar to "Author".
