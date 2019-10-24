# mlogcensor
mlogcensor is a to remove any identifiable information from MongoDB Logfiles, redacting log files in this way means they can be shared with MongoDB support with no risk of leaking any confidentia information.

This is intended to take a prescriptive approach to censoring mongodb logfiles.

Rather than take an approach of removing potentially sensitive data as [https://github.com/rueckstiess/fruitsalad] does. mlogcensor only includes line in the output it can positively identify and can remove known data from.

It requires python 3

usage:

`python3 mlogcensor.py mongod.log` 
 
 mlogcensor outputs to stdout so you may want to redirect to an output file using
 
`python3 mlogcensor.py mongod.log > redacted_mongod.log`

It also writes to a file in the same directory any lines it is unable to redact and a reason for that. You should check this file *unredacted_lines.log* as it should not normally contain much information given a standard mongodb logfile.

Philosophy
----------
* It is designed to require no additional python modules to be installed.
* Is is intended to be easy to inspect and reason about what it is doing.
* It replaces literals including field names and database/collection names with one of a very small number of strings
* It replaces numbers with one of a small number of numbers (1 and 0 are left as they were)
* The same literal value will always substitute the same way but mutiple litteras map to the same output.

We have done it this way to avoid reverse attacks where values are hashed to see if they match - it also confounds statistical attacks as only 26 possible string values and 100 numeric vaues are suppied.

