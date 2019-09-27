# mlogcensor
Tool to remove any identifiable information from MongoDB Logfiles

This is intended to take a prescriptive approach to censoring mongodb logfiles.

Rather than take an approach of removing potentially sensitive data as [https://github.com/rueckstiess/fruitsalad] does. mlogcensor only includes line in the output it can positively identify and can remove known data from.

Philosophy
----------
* It is designed to require no additional python modules t0 be installed.
* Is is intended to be easy to inspect and reason about what it is doing.
* It replaces literals including field names and database/collection names with one of a small number of strings
* It replaces numbers with one of a small number of numbers (1 and 0 are left alone)
* The same literal value will always substitute the same way.


