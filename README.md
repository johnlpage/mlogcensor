# mlogcensor
Tool to remove any identifiable information from MongoDB Logfiles

This is intended to take a prescriptive approach to censoring mongodb logfiles.

Rather than take an approach of removing potentially sensitive data as [https://github.com/rueckstiess/fruitsalad] does. mlogcensor only includes line in the output it can positively identify and can remove known data from.

Features
---------

In version 1.0 it explicitly

* Replaces all namespaces with the string "database.collection"
* Replaces all commands,queries etc with { field : value }
* Removes any non cluster IP adresses
* Removes any usernames


Philosophy
----------
* It is designed to require no additional python modules ot be installed.
* Is is intended to be easy to inspect and reason about what it is doing.
* It does not currently replace literals with a hash or derived value as that allows guessing of original values

These rules *may* change - for example we may take an approach to consistently renaming namespaces and fields

